/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HTTP Handler that intercepts requests and routes them through the Python worker
 * for TLS fingerprint bypass.
 * <p>
 * This handler intercepts outgoing HTTP/HTTPS requests, forwards them to the Python
 * FastAPI worker which uses curl_cffi to impersonate browser TLS fingerprints,
 * and then injects the response back into Burp's workflow.
 * </p>
 */
public class TLSBypassHttpHandler implements HttpHandler {

    private static final String BYPASS_ANNOTATION_PREFIX = "TLS_BYPASS:";
    private static final String BYPASSED_MARKER = "[TLS Bypassed]";

    private final PythonWorkerClient workerClient;
    private final FilterConfig filterConfig;
    private final Logging logging;

    // State
    private volatile boolean enabled = false;
    private volatile boolean logRequests = true;
    private volatile HighlightColor highlightColor = HighlightColor.GREEN;
    private volatile boolean highlightEnabled = true;

    // Statistics
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong bypassedRequests = new AtomicLong(0);
    private final AtomicLong failedRequests = new AtomicLong(0);

    // Response cache for intercepted requests
    private final ConcurrentHashMap<String, HttpResponse> pendingResponses = new ConcurrentHashMap<>();

    // Listeners for UI updates
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
     * @param logging the logging interface
     */
    public TLSBypassHttpHandler(PythonWorkerClient workerClient,
                                 FilterConfig filterConfig, Logging logging) {
        this.workerClient = workerClient;
        this.filterConfig = filterConfig;
        this.logging = logging;
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
     *
     * @param color the highlight color, or null to disable highlighting
     */
    public void setHighlightColor(HighlightColor color) {
        this.highlightColor = color;
        this.highlightEnabled = (color != null);
    }

    /**
     * Gets the current highlight color.
     *
     * @return the highlight color, or null if disabled
     */
    public HighlightColor getHighlightColor() {
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

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        totalRequests.incrementAndGet();

        // Check if bypass is enabled and worker is connected
        if (!enabled || !workerClient.isConnected()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Get request details
        String host = requestToBeSent.httpService().host();
        String path = requestToBeSent.path();
        String method = requestToBeSent.method();
        String url = requestToBeSent.url();

        // Check if request matches filter criteria
        if (!filterConfig.shouldBypass(host, path)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Forward request to Python worker
        long startTime = System.currentTimeMillis();

        try {
            if (logRequests) {
                logging.logToOutput("[HttpHandler] Bypassing: " + method + " " + url);
            }

            // Make the request through Python worker
            HttpResponse workerResponse = workerClient.forwardRequest(requestToBeSent);

            if (workerResponse != null) {
                long elapsedMs = System.currentTimeMillis() - startTime;
                bypassedRequests.incrementAndGet();

                // Generate cache key and store response
                String cacheKey = workerClient.generateCacheKey();
                pendingResponses.put(cacheKey, workerResponse);

                // Log success
                if (logRequests) {
                    logging.logToOutput(String.format(
                        "[HttpHandler] Bypassed: %s %s -> %d (%dms)",
                        method, url, workerResponse.statusCode(), elapsedMs
                    ));
                }

                // Notify listener
                if (logListener != null) {
                    logListener.onRequestProcessed(method, url, workerResponse.statusCode(), elapsedMs, true);
                }

                // Add annotation to mark this request for response replacement
                Annotations annotations = requestToBeSent.annotations()
                    .withNotes(BYPASS_ANNOTATION_PREFIX + cacheKey);

                // Apply highlight color if enabled
                if (highlightEnabled && highlightColor != null) {
                    annotations = annotations.withHighlightColor(highlightColor);
                }

                return RequestToBeSentAction.continueWith(requestToBeSent, annotations);
            }

        } catch (IOException e) {
            failedRequests.incrementAndGet();
            long elapsedMs = System.currentTimeMillis() - startTime;

            logging.logToError("[HttpHandler] Bypass failed for " + url + ": " + e.getMessage());

            if (logListener != null) {
                logListener.onRequestProcessed(method, url, 0, elapsedMs, false);
            }

            // Add error annotation
            Annotations annotations = requestToBeSent.annotations()
                .withNotes("TLS Bypass Failed: " + e.getMessage())
                .withHighlightColor(HighlightColor.RED);

            return RequestToBeSentAction.continueWith(requestToBeSent, annotations);
        }

        // Continue with original request if bypass failed
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Check if this response should be replaced with Python worker response
        String notes = responseReceived.annotations().notes();

        if (notes != null && notes.startsWith(BYPASS_ANNOTATION_PREFIX)) {
            String cacheKey = notes.substring(BYPASS_ANNOTATION_PREFIX.length());
            HttpResponse cachedResponse = pendingResponses.remove(cacheKey);

            if (cachedResponse != null) {
                // Update annotations to show bypass was successful
                Annotations annotations = responseReceived.annotations()
                    .withNotes(BYPASSED_MARKER + " via " + workerClient.getImpersonateTarget());

                // Apply highlight color if enabled
                if (highlightEnabled && highlightColor != null) {
                    annotations = annotations.withHighlightColor(highlightColor);
                }

                return ResponseReceivedAction.continueWith(cachedResponse, annotations);
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Clears the pending response cache.
     */
    public void clearCache() {
        pendingResponses.clear();
    }
}
