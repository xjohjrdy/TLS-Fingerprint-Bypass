/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.*;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

/**
 * HTTP client for communicating with the Python FastAPI worker.
 * <p>
 * Handles serialization of Burp HTTP requests to JSON, forwarding to the Python
 * worker, and deserialization of responses back to Burp HttpResponse objects.
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
    private final OkHttpClient httpClient;
    private final ExecutorService executor;

    // Response cache for async operations
    private final Map<String, HttpResponse> responseCache;

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
     * @param logging the Burp logging interface
     */
    public PythonWorkerClient(Logging logging) {
        this.logging = logging;
        this.responseCache = new ConcurrentHashMap<>();
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
     * Forwards a Burp HTTP request to the Python worker synchronously.
     *
     * @param burpRequest the Burp HTTP request to forward
     * @return the HTTP response from the target server (via Python worker)
     * @throws IOException if the request fails
     */
    public HttpResponse forwardRequest(HttpRequest burpRequest) throws IOException {
        // Build request payload
        JsonObject payload = buildRequestPayload(burpRequest);

        // Send to Python worker
        RequestBody body = RequestBody.create(payload.toString(), JSON_MEDIA_TYPE);
        Request request = new Request.Builder()
            .url(serverUrl + "/proxy")
            .post(body)
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "No error details";
                throw new IOException("Worker returned error " + response.code() + ": " + errorBody);
            }

            String responseBody = response.body().string();
            return parseWorkerResponse(responseBody);
        }
    }

    /**
     * Forwards a Burp HTTP request to the Python worker asynchronously.
     *
     * @param burpRequest the Burp HTTP request to forward
     * @return a CompletableFuture that will contain the response
     */
    public CompletableFuture<HttpResponse> forwardRequestAsync(HttpRequest burpRequest) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return forwardRequest(burpRequest);
            } catch (IOException e) {
                logging.logToError("[WorkerClient] Async forward failed: " + e.getMessage());
                return null;
            }
        }, executor);
    }

    /**
     * Builds the JSON payload for the Python worker from a Burp request.
     */
    private JsonObject buildRequestPayload(HttpRequest burpRequest) {
        JsonObject payload = new JsonObject();

        // Method and URL
        payload.addProperty("method", burpRequest.method());
        payload.addProperty("url", burpRequest.url());

        // Headers
        JsonObject headers = new JsonObject();
        for (HttpHeader header : burpRequest.headers()) {
            String name = header.name();
            String value = header.value();

            // Skip pseudo-headers and headers that will be set by curl_cffi
            if (name.startsWith(":") || name.equalsIgnoreCase("content-length")) {
                continue;
            }

            headers.addProperty(name, value);
        }
        payload.add("headers", headers);

        // Body
        if (burpRequest.body() != null && burpRequest.body().length() > 0) {
            byte[] bodyBytes = burpRequest.body().getBytes();
            String base64Body = Base64.getEncoder().encodeToString(bodyBytes);
            payload.addProperty("body", base64Body);
            payload.addProperty("body_encoding", "base64");
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
     * Parses the JSON response from the Python worker into a Burp HttpResponse.
     */
    private HttpResponse parseWorkerResponse(String jsonResponse) throws IOException {
        try {
            JsonObject json = JsonParser.parseString(jsonResponse).getAsJsonObject();

            int statusCode = json.get("status_code").getAsInt();
            String reason = json.has("reason") ? json.get("reason").getAsString() : "OK";

            // Parse headers first to get Content-Type charset
            JsonObject headers = json.has("headers") ? json.getAsJsonObject("headers") : new JsonObject();
            String charset = extractCharsetFromHeaders(headers);

            // Get body data first to calculate correct Content-Length
            byte[] bodyBytes = null;
            if (json.has("body") && !json.get("body").isJsonNull()) {
                String bodyData = json.get("body").getAsString();
                String bodyEncoding = json.has("body_encoding") ?
                    json.get("body_encoding").getAsString() : "text";

                if ("base64".equals(bodyEncoding)) {
                    bodyBytes = Base64.getDecoder().decode(bodyData);
                } else {
                    // For text content, use the charset from Content-Type or default to UTF-8
                    java.nio.charset.Charset textCharset;
                    try {
                        textCharset = charset != null ?
                            java.nio.charset.Charset.forName(charset) :
                            java.nio.charset.StandardCharsets.UTF_8;
                    } catch (Exception e) {
                        textCharset = java.nio.charset.StandardCharsets.UTF_8;
                    }
                    bodyBytes = bodyData.getBytes(textCharset);
                }
            }

            // Build HTTP response headers
            StringBuilder httpResponseStr = new StringBuilder();
            httpResponseStr.append("HTTP/1.1 ").append(statusCode).append(" ").append(reason).append("\r\n");

            // Headers to skip - these will be recalculated or are not applicable
            Set<String> skipHeaders = new HashSet<>(Arrays.asList(
                "transfer-encoding",    // We provide full body, not chunked
                "content-encoding",     // curl_cffi auto-decompresses, so this is no longer valid
                "content-length",       // Will be recalculated based on actual body size
                "connection"            // Will be set explicitly
            ));

            // Add headers from response
            for (String key : headers.keySet()) {
                String lowerKey = key.toLowerCase();
                if (!skipHeaders.contains(lowerKey)) {
                    String value = headers.get(key).getAsString();
                    httpResponseStr.append(key).append(": ").append(value).append("\r\n");
                }
            }

            // Add Connection header for HTTP/1.1 compatibility
            httpResponseStr.append("Connection: close\r\n");

            // Add correct Content-Length header
            if (bodyBytes != null && bodyBytes.length > 0) {
                httpResponseStr.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
            } else {
                httpResponseStr.append("Content-Length: 0\r\n");
            }

            httpResponseStr.append("\r\n");

            // Build final response with body
            if (bodyBytes != null && bodyBytes.length > 0) {
                String headersPart = httpResponseStr.toString();
                byte[] headersBytes = headersPart.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                byte[] fullResponse = new byte[headersBytes.length + bodyBytes.length];
                System.arraycopy(headersBytes, 0, fullResponse, 0, headersBytes.length);
                System.arraycopy(bodyBytes, 0, fullResponse, headersBytes.length, bodyBytes.length);
                return HttpResponse.httpResponse(ByteArray.byteArray(fullResponse));
            }

            return HttpResponse.httpResponse(httpResponseStr.toString());

        } catch (Exception e) {
            throw new IOException("Failed to parse worker response: " + e.getMessage(), e);
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
     * Caches a response for later retrieval.
     *
     * @param key the cache key
     * @param response the response to cache
     */
    public void cacheResponse(String key, HttpResponse response) {
        responseCache.put(key, response);
    }

    /**
     * Retrieves and removes a cached response.
     *
     * @param key the cache key
     * @return the cached response, or null if not found
     */
    public HttpResponse getCachedResponse(String key) {
        return responseCache.remove(key);
    }

    /**
     * Generates a unique cache key for a request.
     *
     * @return a unique cache key
     */
    public String generateCacheKey() {
        return UUID.randomUUID().toString();
    }

    /**
     * Shuts down the client, releasing all resources.
     */
    public void shutdown() {
        connected = false;
        executor.shutdownNow();
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
        responseCache.clear();
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
