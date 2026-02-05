/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.bypasstls.burp.ui.ConfigTab;

/**
 * Main entry point for the TLS Fingerprint Bypass Burp Suite extension.
 * <p>
 * This extension intercepts HTTP/HTTPS requests and forwards them through a local
 * Python worker that uses curl_cffi to impersonate browser TLS fingerprints,
 * effectively bypassing TLS fingerprinting detection mechanisms.
 * </p>
 */
public class BurpExtension implements burp.api.montoya.BurpExtension {

    public static final String EXTENSION_NAME = "TLS Fingerprint Bypass";
    public static final String EXTENSION_VERSION = "1.0.0";

    private MontoyaApi api;
    private Logging logging;
    private ResourceExtractor resourceExtractor;
    private ProcessManager processManager;
    private PythonWorkerClient workerClient;
    private TLSBypassHttpHandler httpHandler;
    private FilterConfig filterConfig;
    private ConfigTab configTab;
    private String extractedScriptPath;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        // Set extension name
        api.extension().setName(EXTENSION_NAME);

        logging.logToOutput("=".repeat(50));
        logging.logToOutput(EXTENSION_NAME + " v" + EXTENSION_VERSION);
        logging.logToOutput("Initializing extension...");
        logging.logToOutput("=".repeat(50));

        try {
            // Initialize components
            initializeComponents();

            // Register HTTP handler for request interception
            api.http().registerHttpHandler(httpHandler);
            logging.logToOutput("[+] HTTP handler registered");

            // Register configuration tab in Burp UI
            api.userInterface().registerSuiteTab(EXTENSION_NAME, configTab);
            logging.logToOutput("[+] Configuration tab registered");

            // Register unload handler for cleanup
            api.extension().registerUnloadingHandler(this::onUnload);
            logging.logToOutput("[+] Unload handler registered");

            logging.logToOutput("=".repeat(50));
            logging.logToOutput("Extension loaded successfully!");
            logging.logToOutput("Go to '" + EXTENSION_NAME + "' tab to configure.");
            logging.logToOutput("=".repeat(50));

        } catch (Exception e) {
            logging.logToError("Failed to initialize extension: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Initializes all extension components in the correct order.
     */
    private void initializeComponents() {
        // Get persistence object for saving/loading settings
        PersistedObject persistence = api.persistence().extensionData();

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
        filterConfig.loadFromPersistence(persistence);
        logging.logToOutput("[+] Filter configuration initialized");

        // Create process manager for Python worker lifecycle
        this.processManager = new ProcessManager(logging);
        logging.logToOutput("[+] Process manager initialized");

        // Create worker client for communication with Python sidecar
        this.workerClient = new PythonWorkerClient(logging);
        logging.logToOutput("[+] Worker client initialized");

        // Create HTTP handler for request interception
        this.httpHandler = new TLSBypassHttpHandler(workerClient, filterConfig, logging);
        logging.logToOutput("[+] HTTP handler initialized");

        // Create configuration tab with persistence and extracted script path
        this.configTab = new ConfigTab(api, processManager, workerClient, httpHandler,
                                        filterConfig, logging, persistence, extractedScriptPath);
        logging.logToOutput("[+] Configuration tab initialized");
    }

    /**
     * Cleanup handler called when the extension is unloaded.
     */
    private void onUnload() {
        logging.logToOutput("Unloading " + EXTENSION_NAME + "...");

        try {
            // Stop Python server if running
            if (processManager != null) {
                processManager.stopPythonServer();
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
     * Gets the Montoya API instance.
     */
    public MontoyaApi getApi() {
        return api;
    }

    /**
     * Gets the logging instance.
     */
    public Logging getLogging() {
        return logging;
    }
}
