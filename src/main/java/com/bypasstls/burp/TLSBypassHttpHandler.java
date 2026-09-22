/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HTTP listener that routes matching requests through the Python worker for TLS
 * fingerprint bypass.
 * <p>
 * The legacy API delivers requests and responses through a single callback,
 * {@code processHttpMessage}, distinguished by {@code messageIsRequest}.
 * </p>
 * <p>
 * <b>Response swapping:</b> when a request is bypassed, the worker's response is
 * parked in a queue keyed by the SHA-256 of the request bytes. The request bytes
 * are never modified, so the response phase recomputes the same key and installs
 * the parked response via {@code setResponse}. Using a FIFO queue (rather than a
 * single value) keeps concurrent identical requests - for example Intruder
 * replaying the same payload - from stealing each other's responses. Pairing is
 * best-effort: it is exact only when identical requests complete their response
 * phases in the order their request phases parked.
 * </p>
 */
public class TLSBypassHttpHandler implements burp.IHttpListener {

    private static final String BYPASS_COMMENT_PREFIX = "[TLS Bypassed] via ";
    private static final int MAX_CACHED_PER_KEY = 8;

    private final PythonWorkerClient workerClient;
    private final FilterConfig filterConfig;
    private final Logging logging;
    private final IExtensionHelpers helpers;

    // State
    private volatile boolean enabled = false;
    private volatile boolean logRequests = true;
    private volatile String highlightColor = "green";
    private volatile boolean highlightEnabled = true;

    // Statistics
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong bypassedRequests = new AtomicLong(0);
    private final AtomicLong failedRequests = new AtomicLong(0);

    // Parked worker responses, keyed by request-bytes hash
    private final ConcurrentHashMap<String, Deque<byte[]>> pendingResponses = new ConcurrentHashMap<>();

    // Bypass failure reasons, keyed by request-bytes hash, applied in the response phase.
    // Bounded so a request that never completes cannot leak entries indefinitely.
    private static final int MAX_FAILED_KEYS = 256;
    private final ConcurrentHashMap<String, String> failedKeys = new ConcurrentHashMap<>();

    // Listener for UI updates
    private RequestLogListener logListener;

    /**
     * Interface for request logging callbacks to the UI.
     */
    public interface RequestLogListener {
        void onRequestProcessed(String method, String url, int statusCode, long elapsedMs, boolean success);
    }

    /**
     * Creates a new TLSBypassHttpHandler.
     *
     * @param workerClient the Python worker client
     * @param filterConfig the filter configuration
     * @param logging the logging adapter
     * @param helpers the Burp extension helpers
     */
    public TLSBypassHttpHandler(PythonWorkerClient workerClient,
                                FilterConfig filterConfig,
                                Logging logging,
                                IExtensionHelpers helpers) {
        this.workerClient = workerClient;
        this.filterConfig = filterConfig;
        this.logging = logging;
        this.helpers = helpers;
    }

    /**
     * Enables or disables the TLS bypass.
     *
     * @param enabled true to enable, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logging.logToOutput("[HttpHandler] TLS Bypass " + (enabled ? "ENABLED" : "DISABLED"));
    }

    /**
     * Checks if the bypass is enabled.
     *
     * @return true if enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether to log requests.
     *
     * @param log true to log requests
     */
    public void setLogRequests(boolean log) {
        this.logRequests = log;
    }

    /**
     * Sets the highlight color for bypassed requests.
     * <p>
     * The legacy API accepts color names as lowercase strings: red, orange,
     * yellow, green, cyan, blue, pink, magenta, gray.
     * </p>
     *
     * @param color the lowercase color name, or null to disable highlighting
     */
    public void setHighlightColor(String color) {
        this.highlightColor = color;
        this.highlightEnabled = (color != null);
    }

    /**
     * Gets the current highlight color.
     *
     * @return the lowercase color name, or null if disabled
     */
    public String getHighlightColor() {
        return highlightEnabled ? highlightColor : null;
    }

    /**
     * Checks if highlighting is enabled.
     *
     * @return true if highlighting is enabled
     */
    public boolean isHighlightEnabled() {
        return highlightEnabled;
    }

    /**
     * Sets the log listener for UI updates.
     *
     * @param listener the listener
     */
    public void setLogListener(RequestLogListener listener) {
        this.logListener = listener;
    }

    /**
     * Gets statistics about processed requests.
     *
     * @return array of [total, bypassed, failed]
     */
    public long[] getStatistics() {
        return new long[]{
            totalRequests.get(),
            bypassedRequests.get(),
            failedRequests.get()
        };
    }

    /**
     * Resets statistics counters.
     */
    public void resetStatistics() {
        totalRequests.set(0);
        bypassedRequests.set(0);
        failedRequests.set(0);
    }

    /**
     * Clears all parked responses.
     */
    public void clearCache() {
        pendingResponses.clear();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            handleRequest(messageInfo);
        } else {
            handleResponse(messageInfo);
        }
    }

    /**
     * Handles an outgoing request: forwards it through the worker when it matches
     * the filter, parking the impersonated response for the response phase.
     */
    private void handleRequest(IHttpRequestResponse messageInfo) {
        totalRequests.incrementAndGet();

        if (!enabled || !workerClient.isConnected()) {
            return;
        }

        byte[] request = messageInfo.getRequest();
        if (request == null || request.length == 0) {
            return;
        }

        IHttpService service = messageInfo.getHttpService();
        if (service == null) {
            return;
        }

        IRequestInfo info = helpers.analyzeRequest(service, request);
        String host = service.getHost();
        String method = info.getMethod();
        String url = info.getUrl().toString();

        // Match the Montoya handler's semantics: path plus query string
        String path = info.getUrl().getPath();
        if (info.getUrl().getQuery() != null) {
            path = path + "?" + info.getUrl().getQuery();
        }

        if (!filterConfig.shouldBypass(host, path)) {
            return;
        }

        long startTime = System.currentTimeMillis();

        try {
            if (logRequests) {
                logging.logToOutput("[HttpHandler] Bypassing: " + method + " " + url);
            }

            byte[] workerResponse = workerClient.forwardRequest(request, service);
            if (workerResponse == null) {
                return;
            }

            long elapsedMs = System.currentTimeMillis() - startTime;
            bypassedRequests.incrementAndGet();

            cacheResponse(keyOf(request), workerResponse);

            if (logRequests) {
                logging.logToOutput(String.format(
                    "[HttpHandler] Bypassed: %s %s (%dms)", method, url, elapsedMs));
            }

            if (logListener != null) {
                logListener.onRequestProcessed(
                    method, url, workerClient.parseStatusCode(workerResponse), elapsedMs, true);
            }

        } catch (IOException e) {
            failedRequests.incrementAndGet();
            if (failedKeys.size() >= MAX_FAILED_KEYS) {
                failedKeys.clear();
            }
            failedKeys.put(keyOf(request), String.valueOf(e.getMessage()));
            long elapsedMs = System.currentTimeMillis() - startTime;

            logging.logToError("[HttpHandler] Bypass failed for " + url + ": " + e.getMessage());

            if (logListener != null) {
                logListener.onRequestProcessed(method, url, 0, elapsedMs, false);
            }
        }
    }

    /**
     * Handles a received response: installs the parked worker response when one
     * exists for this request.
     * <p>
     * Annotations are applied here rather than in the request phase, because the
     * response phase is when the history entry reaches its final state. Finding a
     * parked response is proof the request was bypassed.
     * </p>
     */
    private void handleResponse(IHttpRequestResponse messageInfo) {
        byte[] request = messageInfo.getRequest();
        if (request == null) {
            return;
        }

        // Drain any parked response first, even when the response is null: the
        // request may never have completed, and leaving it parked would leak it.
        String key = keyOf(request);
        byte[] parked = pollResponse(key);

        byte[] response = messageInfo.getResponse();
        if (response == null) {
            return;
        }
        if (parked == null) {
            // No parked response: either this request was never bypassed, or the
            // bypass attempt failed. Mark failures so they are visible in Burp.
            String failure = failedKeys.remove(key);
            if (failure != null) {
                messageInfo.setHighlight("red");
                messageInfo.setComment("[TLS Bypass Failed] " + failure);
            }
            return;
        }

        messageInfo.setResponse(parked);

        if (highlightEnabled && highlightColor != null) {
            messageInfo.setHighlight(highlightColor);
        }
        messageInfo.setComment(BYPASS_COMMENT_PREFIX + workerClient.getImpersonateTarget());
    }

    /**
     * Parks a worker response for later retrieval by the response phase.
     * <p>
     * The map-entry lifetime and the deque mutation are performed inside a single
     * {@code compute} call so they are atomic with respect to {@link #pollResponse}.
     * Doing them under separate locks allows a poll to remove the mapping between a
     * cache's insert and its append, which would orphan the response.
     * </p>
     */
    private void cacheResponse(String key, byte[] response) {
        pendingResponses.compute(key, (k, queue) -> {
            Deque<byte[]> q = (queue != null) ? queue : new ArrayDeque<>();
            while (q.size() >= MAX_CACHED_PER_KEY) {
                q.pollFirst();
            }
            q.addLast(response);
            return q;
        });
    }

    /**
     * Retrieves and removes a parked response.
     *
     * @return the parked response, or null if none exists
     */
    private byte[] pollResponse(String key) {
        final byte[][] holder = new byte[1][];
        pendingResponses.compute(key, (k, queue) -> {
            if (queue == null) {
                return null;
            }
            holder[0] = queue.pollFirst();
            // Returning null removes the mapping, so an emptied key does not linger
            return queue.isEmpty() ? null : queue;
        });
        return holder[0];
    }

    /**
     * Derives a stable cache key from raw request bytes.
     * <p>
     * The request bytes are not modified between the request and response phases,
     * so this yields the same key in both.
     * </p>
     */
    private static String keyOf(byte[] request) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(request));
        } catch (NoSuchAlgorithmException e) {
            // NoSuchAlgorithmException is not reachable on a compliant JRE, but the
            // fallback avoids a hard failure if a provider omits SHA-256
            return "fallback-" + Integer.toHexString(java.util.Arrays.hashCode(request));
        }
    }
}
