/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.bypasstls.burp.ui.ConfigTab;

/**
 * Main entry point for the TLS Fingerprint Bypass Burp Suite extension.
 * <p>
 * This extension intercepts HTTP/HTTPS requests and forwards them through a local
 * Python worker that uses curl_cffi to impersonate browser TLS fingerprints,
 * effectively bypassing TLS fingerprinting detection mechanisms.
 * </p>
 */
public class BurpExtension {

    public static final String EXTENSION_NAME = "TLS Fingerprint Bypass";
    public static final String EXTENSION_VERSION = "1.0.0";
    private static final String SEPARATOR =
        "==================================================";

    private IBurpExtenderCallbacks callbacks;
    private Logging logging;
    private ResourceExtractor resourceExtractor;
    private ProcessManager processManager;
    private PythonWorkerClient workerClient;
    private TLSBypassHttpHandler httpHandler;
    private FilterConfig filterConfig;
    private ConfigTab configTab;
    private String extractedScriptPath;

    /**
     * Initializes the extension with the legacy Burp callbacks.
     * <p>
     * Invoked by {@link burp.BurpExtender#registerExtenderCallbacks}.
     * </p>
     *
     * @param callbacks the Burp callbacks
     */
    public void initialize(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.logging = new Logging(callbacks);

        callbacks.setExtensionName(EXTENSION_NAME);

        logging.logToOutput(SEPARATOR);
        logging.logToOutput(EXTENSION_NAME + " v" + EXTENSION_VERSION);
        logging.logToOutput("Initializing extension...");
        logging.logToOutput(SEPARATOR);

        try {
            // Initialize components
            initializeComponents();

            // Register HTTP listener for request interception
            callbacks.registerHttpListener(httpHandler);
            logging.logToOutput("[+] HTTP listener registered");

            // Register configuration tab in Burp UI
            callbacks.addSuiteTab(configTab);
            logging.logToOutput("[+] Configuration tab registered");

            // Register unload handler for cleanup
            callbacks.registerExtensionStateListener(this::onUnload);
            logging.logToOutput("[+] Unload handler registered");

            logging.logToOutput(SEPARATOR);
            logging.logToOutput("Extension loaded successfully!");
            logging.logToOutput("Go to '" + EXTENSION_NAME + "' tab to configure.");
            logging.logToOutput(SEPARATOR);

        } catch (Exception e) {
            logging.logToError("Failed to initialize extension: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Initializes all extension components in the correct order.
     */
    private void initializeComponents() {
        IExtensionHelpers helpers = callbacks.getHelpers();

        // Extract embedded Python resources from JAR
        this.resourceExtractor = new ResourceExtractor(logging);
        this.extractedScriptPath = resourceExtractor.extractResources();
        if (extractedScriptPath != null) {
            logging.logToOutput("[+] Python resources extracted to: " + extractedScriptPath);
        } else {
            logging.logToOutput("[!] Failed to extract Python resources, manual configuration required");
        }

        // Create filter configuration with persistence
        this.filterConfig = new FilterConfig();
        filterConfig.loadFromPersistence(callbacks);
        logging.logToOutput("[+] Filter configuration initialized");

        // Create process manager for Python worker lifecycle
        this.processManager = new ProcessManager(logging);
        logging.logToOutput("[+] Process manager initialized");

        // Create worker client for communication with Python sidecar
        this.workerClient = new PythonWorkerClient(logging, helpers);
        logging.logToOutput("[+] Worker client initialized");

        // Create HTTP listener for request interception
        this.httpHandler = new TLSBypassHttpHandler(workerClient, filterConfig, logging, helpers);
        logging.logToOutput("[+] HTTP listener initialized");

        // Create configuration tab with extracted script path
        this.configTab = new ConfigTab(callbacks, processManager, workerClient, httpHandler,
                                       filterConfig, logging, extractedScriptPath);
        logging.logToOutput("[+] Configuration tab initialized");
    }

    /**
     * Cleanup handler called when the extension is unloaded.
     */
    private void onUnload() {
        logging.logToOutput("Unloading " + EXTENSION_NAME + "...");

        try {
            // Stop Python server and release its output-reader threads
            if (processManager != null) {
                processManager.shutdown();
            }

            // Shutdown worker client
            if (workerClient != null) {
                workerClient.shutdown();
            }

            logging.logToOutput(EXTENSION_NAME + " unloaded successfully");
        } catch (Exception e) {
            logging.logToError("Error during unload: " + e.getMessage());
        }
    }

    /**
     * Gets the logging instance.
     */
    public Logging getLogging() {
        return logging;
    }
}
