/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.IBurpExtenderCallbacks;

/**
 * Thin adapter over the legacy API's output streams.
 * <p>
 * Deliberately mirrors the method names of the Montoya {@code Logging} interface
 * so that every existing call site ({@code logToOutput} / {@code logToError})
 * compiles unchanged. This keeps the migration diff small: components only need
 * their {@code import} line updated.
 * </p>
 */
public class Logging {

    private final IBurpExtenderCallbacks callbacks;

    /**
     * Creates a new Logging adapter.
     *
     * @param callbacks the Burp callbacks used for output
     */
    public Logging(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * Writes a message to Burp's extension output.
     *
     * @param message the message to write
     */
    public void logToOutput(String message) {
        callbacks.printOutput(message);
    }

    /**
     * Writes a message to Burp's extension error output.
     *
     * @param message the message to write
     */
    public void logToError(String message) {
        callbacks.printError(message);
    }
}
