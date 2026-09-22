/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IRequestInfo;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/**
 * HTTP client for communicating with the Python FastAPI worker.
 * <p>
 * Handles serialization of raw Burp HTTP requests to JSON, forwarding to the
 * Python worker, and reconstruction of the worker's JSON reply into raw HTTP
 * response bytes suitable for handing back to Burp's legacy API.
 * </p>
 * <p>
 * Uses OkHttp with connection pooling for efficient communication.
 * </p>
 */
public class PythonWorkerClient {

    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");
    private static final int DEFAULT_TIMEOUT_SECONDS = 30;
    private static final int CONNECTION_POOL_SIZE = 10;
    private static final int KEEP_ALIVE_MINUTES = 5;

    private final Logging logging;
    private final IExtensionHelpers helpers;
    private final OkHttpClient httpClient;
    private final ExecutorService executor;

    // Configuration
    private String serverUrl = "http://127.0.0.1:8787";
    private String impersonateTarget = "chrome";
    private int timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
    private boolean verifySsl = true;
    private boolean followRedirects = true;
    private boolean autoUserAgent = true;
    private volatile boolean connected = false;

    /**
     * Creates a new PythonWorkerClient instance.
     *
     * @param logging the logging adapter
     * @param helpers the Burp extension helpers used to parse raw requests
     */
    public PythonWorkerClient(Logging logging, IExtensionHelpers helpers) {
        this.logging = logging;
        this.helpers = helpers;
        this.executor = Executors.newFixedThreadPool(10, r -> {
            Thread t = new Thread(r, "WorkerClient");
            t.setDaemon(true);
            return t;
        });

        // Configure OkHttp client with connection pooling
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .connectionPool(new ConnectionPool(CONNECTION_POOL_SIZE, KEEP_ALIVE_MINUTES, TimeUnit.MINUTES))
            .build();
    }

    /**
     * Configures the client with server and impersonation settings.
     *
     * @param serverUrl the Python worker server URL
     * @param impersonateTarget the browser to impersonate
     */
    public void configure(String serverUrl, String impersonateTarget) {
        this.serverUrl = serverUrl;
        this.impersonateTarget = impersonateTarget;
    }

    /**
     * Sets the request timeout.
     *
     * @param seconds timeout in seconds
     */
    public void setTimeout(int seconds) {
        this.timeoutSeconds = seconds;
    }

    /**
     * Sets whether to verify SSL certificates.
     *
     * @param verify true to verify, false to skip
     */
    public void setVerifySsl(boolean verify) {
        this.verifySsl = verify;
    }

    /**
     * Sets whether to follow redirects.
     *
     * @param follow true to follow, false to not follow
     */
    public void setFollowRedirects(boolean follow) {
        this.followRedirects = follow;
    }

    /**
     * Sets whether to automatically set User-Agent based on impersonated browser.
     *
     * @param auto true to auto-set User-Agent, false to use original
     */
    public void setAutoUserAgent(boolean auto) {
        this.autoUserAgent = auto;
    }

    /**
     * Gets whether auto User-Agent is enabled.
     *
     * @return true if auto User-Agent is enabled
     */
    public boolean isAutoUserAgent() {
        return autoUserAgent;
    }

    /**
     * Gets the current impersonation target.
     *
     * @return the impersonation target
     */
    public String getImpersonateTarget() {
        return impersonateTarget;
    }

    /**
     * Checks connection to the Python worker server.
     *
     * @return true if connected, false otherwise
     */
    public boolean checkConnection() {
        try {
            Request request = new Request.Builder()
                .url(serverUrl + "/health")
                .get()
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                connected = response.isSuccessful();
                if (connected && response.body() != null) {
                    String body = response.body().string();
                    logging.logToOutput("[WorkerClient] Health check: " + body);
                }
                return connected;
            }
        } catch (IOException e) {
            logging.logToError("[WorkerClient] Health check failed: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    /**
     * Checks if the client is connected to the worker.
     *
     * @return true if connected
     */
    public boolean isConnected() {
        return connected;
    }

    /**
     * Fetches available impersonation targets from the worker.
     *
     * @return list of available targets, or empty list on error
     */
    public List<String> fetchAvailableTargets() {
        try {
            Request request = new Request.Builder()
                .url(serverUrl + "/targets")
                .get()
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    String body = response.body().string();
                    JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                    List<String> targets = new ArrayList<>();
                    json.getAsJsonArray("targets").forEach(e -> targets.add(e.getAsString()));
                    return targets;
                }
            }
        } catch (Exception e) {
            logging.logToError("[WorkerClient] Failed to fetch targets: " + e.getMessage());
        }
        return Collections.emptyList();
    }

    /**
     * Forwards a raw Burp HTTP request to the Python worker synchronously.
     *
     * @param request the raw request bytes
     * @param httpService the service the request targets
     * @return the raw HTTP response bytes from the target server (via Python worker)
     * @throws IOException if the request fails
     */
    public byte[] forwardRequest(byte[] request, IHttpService httpService) throws IOException {
        JsonObject payload = buildRequestPayload(request, httpService);

        RequestBody body = RequestBody.create(payload.toString(), JSON_MEDIA_TYPE);
        Request httpRequest = new Request.Builder()
            .url(serverUrl + "/proxy")
            .post(body)
            .build();

        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "No error details";
                throw new IOException("Worker returned error " + response.code() + ": " + errorBody);
            }
            return parseWorkerResponse(response.body().string());
        }
    }

    /**
     * Forwards a raw Burp HTTP request to the Python worker asynchronously.
     *
     * @param request the raw request bytes
     * @param httpService the service the request targets
     * @return a CompletableFuture that will contain the response bytes
     */
    public CompletableFuture<byte[]> forwardRequestAsync(byte[] request, IHttpService httpService) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return forwardRequest(request, httpService);
            } catch (IOException e) {
                logging.logToError("[WorkerClient] Async forward failed: " + e.getMessage());
                return null;
            }
        }, executor);
    }

    /**
     * Builds the JSON payload for the Python worker from a raw Burp request.
     * <p>
     * The JSON shape is unchanged from the Montoya implementation - the Python
     * worker's Pydantic models are the other half of this contract.
     * </p>
     */
    private JsonObject buildRequestPayload(byte[] request, IHttpService httpService) {
        JsonObject payload = new JsonObject();

        IRequestInfo info = helpers.analyzeRequest(httpService, request);

        payload.addProperty("method", info.getMethod());
        payload.addProperty("url", info.getUrl().toString());

        // Headers: element 0 is the request line (e.g. "GET / HTTP/1.1"), skip it
        JsonObject headers = new JsonObject();
        List<String> headerLines = info.getHeaders();
        for (int i = 1; i < headerLines.size(); i++) {
            String header = headerLines.get(i);
            int colon = header.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = header.substring(0, colon).trim();
            String value = header.substring(colon + 1).trim();

            // Skip headers curl_cffi sets itself
            if (name.startsWith(":") || name.equalsIgnoreCase("content-length")) {
                continue;
            }
            headers.addProperty(name, value);
        }
        payload.add("headers", headers);

        // Body: getBodyOffset() gives the exact start of the message body
        int bodyOffset = info.getBodyOffset();
        if (bodyOffset > 0 && bodyOffset < request.length) {
            byte[] bodyBytes = Arrays.copyOfRange(request, bodyOffset, request.length);
            if (bodyBytes.length > 0) {
                payload.addProperty("body", Base64.getEncoder().encodeToString(bodyBytes));
                payload.addProperty("body_encoding", "base64");
            }
        }

        // Impersonation and options
        payload.addProperty("impersonate", impersonateTarget);
        payload.addProperty("timeout", timeoutSeconds);
        payload.addProperty("verify_ssl", verifySsl);
        payload.addProperty("follow_redirects", followRedirects);
        payload.addProperty("auto_user_agent", autoUserAgent);

        return payload;
    }

    /**
     * Parses the JSON response from the Python worker into raw HTTP response bytes.
     * <p>
     * Content-Length is recomputed from the decoded body and transfer-encoding /
     * content-encoding / connection are dropped, because curl_cffi already
     * decompressed the body.
     * </p>
     */
    private byte[] parseWorkerResponse(String jsonResponse) throws IOException {
        try {
            JsonObject json = JsonParser.parseString(jsonResponse).getAsJsonObject();

            int statusCode = json.get("status_code").getAsInt();
            String reason = json.has("reason") ? json.get("reason").getAsString() : "OK";

            JsonObject headers = json.has("headers") ? json.getAsJsonObject("headers") : new JsonObject();
            String charset = extractCharsetFromHeaders(headers);

            byte[] bodyBytes = null;
            if (json.has("body") && !json.get("body").isJsonNull()) {
                String bodyData = json.get("body").getAsString();
                String bodyEncoding = json.has("body_encoding")
                    ? json.get("body_encoding").getAsString() : "text";

                if ("base64".equals(bodyEncoding)) {
                    bodyBytes = Base64.getDecoder().decode(bodyData);
                } else {
                    Charset textCharset;
                    try {
                        textCharset = charset != null
                            ? Charset.forName(charset) : StandardCharsets.UTF_8;
                    } catch (Exception e) {
                        textCharset = StandardCharsets.UTF_8;
                    }
                    bodyBytes = bodyData.getBytes(textCharset);
                }
            }

            StringBuilder head = new StringBuilder();
            head.append("HTTP/1.1 ").append(statusCode).append(" ").append(reason).append("\r\n");

            Set<String> skipHeaders = new HashSet<>(Arrays.asList(
                "transfer-encoding",
                "content-encoding",
                "content-length",
                "connection"
            ));

            for (String key : headers.keySet()) {
                if (!skipHeaders.contains(key.toLowerCase())) {
                    head.append(key).append(": ").append(headers.get(key).getAsString()).append("\r\n");
                }
            }

            head.append("Connection: close\r\n");
            head.append("Content-Length: ")
                .append(bodyBytes != null ? bodyBytes.length : 0).append("\r\n");
            head.append("\r\n");

            byte[] headBytes = head.toString().getBytes(StandardCharsets.ISO_8859_1);
            if (bodyBytes == null || bodyBytes.length == 0) {
                return headBytes;
            }

            byte[] full = new byte[headBytes.length + bodyBytes.length];
            System.arraycopy(headBytes, 0, full, 0, headBytes.length);
            System.arraycopy(bodyBytes, 0, full, headBytes.length, bodyBytes.length);
            return full;

        } catch (Exception e) {
            throw new IOException("Failed to parse worker response: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the status code from raw response bytes.
     *
     * @param response the raw HTTP response
     * @return the status code, or 0 if it cannot be parsed
     */
    public int parseStatusCode(byte[] response) {
        try {
            return helpers.analyzeResponse(response).getStatusCode();
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Extracts charset from Content-Type header.
     */
    private String extractCharsetFromHeaders(JsonObject headers) {
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase("content-type")) {
                String contentType = headers.get(key).getAsString().toLowerCase();
                int charsetIdx = contentType.indexOf("charset=");
                if (charsetIdx != -1) {
                    String charset = contentType.substring(charsetIdx + 8);
                    // Remove any trailing parameters or quotes
                    int endIdx = charset.indexOf(';');
                    if (endIdx != -1) {
                        charset = charset.substring(0, endIdx);
                    }
                    charset = charset.trim().replace("\"", "").replace("'", "");
                    return charset;
                }
            }
        }
        return null;
    }

    /**
     * Shuts down the client, releasing all resources.
     */
    public void shutdown() {
        connected = false;
        executor.shutdownNow();
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
    }

    /**
     * Gets the server URL.
     *
     * @return the server URL
     */
    public String getServerUrl() {
        return serverUrl;
    }
}
