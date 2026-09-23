/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.bypasstls.burp.ui.ConfigTab;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;

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

            // Register the Swing tab, strictly on the EDT, through Burp's
            // appearance pass. See registerConfigTab() for why both matter.
            registerConfigTab(callbacks.getHelpers());

            // Register HTTP listener for request interception
            callbacks.registerHttpListener(httpHandler);
            logging.logToOutput("[+] HTTP listener registered");

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
     * Initializes the non-UI extension components.
     * <p>
     * None of these are Swing containers, so they are safe to build on Burp's
     * registering thread. The one component that needs different treatment is
     * {@link ConfigTab}; see {@link #registerConfigTab}.
     * </p>
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
    }

    /**
     * Creates the configuration tab and hands it to Burp.
     * <p>
     * <b>Diagnosing the "check box only redraws on hover" bug.</b> A test
     * extension registered four otherwise identical panels, varying exactly two
     * things: the thread that built them, and whether
     * {@link IBurpExtenderCallbacks#customizeUiComponent} was applied.
     * </p>
     * <pre>
     *   A: built off-EDT, no customize  -> broken
     *   B: built on EDT,  customize     -> fine
     *   C: built on EDT,  no customize  -> broken
     *   D: built off-EDT, customize     -> fine
     * </pre>
     * <p>
     * The building thread therefore is <em>not</em> the deciding factor &mdash;
     * C and D differ on it and still land on opposite outcomes. The deciding
     * factor is {@code customizeUiComponent}: the two panels that called it work,
     * the two that skipped it do not. Without that call the components respond to
     * input correctly (the model changes, listeners fire) but their repaint
     * requests never reach the screen, so the new state only appears when some
     * unrelated event &mdash; hovering, or clicking a sibling control &mdash;
     * forces a full redraw.
     * </p>
     * <p>
     * The building thread is still worth getting right, hence the
     * {@link SwingUtilities#invokeAndWait} below: Burp's API reference states
     * that callbacks touching components must be invoked on the EDT, and Burp
     * calls {@code registerExtenderCallbacks} on its own loader thread.
     * </p>
     *
     * @param helpers the Burp helpers handed to the tab's dependencies
     */
    private void registerConfigTab(IExtensionHelpers helpers) {
        Runnable create = () -> {
            this.configTab = new ConfigTab(callbacks, processManager, workerClient, httpHandler,
                                           filterConfig, logging, extractedScriptPath);

            // The load-bearing call. Burp installs the UI delegate that keeps a
            // plugin's component tree in step with its own look and, crucially,
            // participates in getting its paint requests onto the screen.
            callbacks.customizeUiComponent(configTab);

            callbacks.addSuiteTab(configTab);
        };

        if (SwingUtilities.isEventDispatchThread()) {
            create.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(create);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logging.logToError("[!] Interrupted while creating the configuration tab: " + e);
                return;
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                logging.logToError("[!] Failed to create the configuration tab: " + cause);
                return;
            }
        }
        logging.logToOutput("[+] Configuration tab initialized, customized and registered");
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
