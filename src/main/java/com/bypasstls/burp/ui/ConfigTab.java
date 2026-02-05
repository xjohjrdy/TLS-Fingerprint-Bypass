/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.bypasstls.burp.*;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.File;

/**
 * Main configuration tab panel for the TLS Fingerprint Bypass extension.
 * <p>
 * Provides UI controls for:
 * <ul>
 *   <li>Python worker server configuration (path, port)</li>
 *   <li>Browser impersonation target selection</li>
 *   <li>Server start/stop controls</li>
 *   <li>Filter configuration</li>
 *   <li>Request logging</li>
 * </ul>
 * </p>
 */
public class ConfigTab extends JPanel {

    private final MontoyaApi api;
    private final ProcessManager processManager;
    private final PythonWorkerClient workerClient;
    private final TLSBypassHttpHandler httpHandler;
    private final FilterConfig filterConfig;
    private final Logging logging;
    private final PersistedObject persistence;
    private final String extractedScriptPath;

    // Configuration components
    private JTextField pythonPathField;
    private JTextField scriptPathField;
    private JTextField portField;
    private JComboBox<String> impersonateCombo;

    // Control components
    private JButton startStopButton;
    private JButton testConnectionButton;
    private JCheckBox enableBypassCheckbox;
    private JCheckBox logRequestsCheckbox;
    private JCheckBox autoUserAgentCheckbox;
    private JComboBox<String> highlightColorCombo;
    private JLabel statusLabel;
    private JLabel statsLabel;

    // Sub-panels
    private FilterPanel filterPanel;
    private LogPanel logPanel;

    // Timer for stats update
    private Timer statsTimer;

    // Supported impersonation targets (curl_cffi v0.11+)
    private static final String[] IMPERSONATE_TARGETS = {
        // Generic (auto-select latest)
        "chrome", "firefox", "safari", "chrome_android", "safari_ios",
        // Chrome Desktop
        "chrome136", "chrome133a", "chrome131", "chrome124", "chrome123",
        "chrome120", "chrome119", "chrome116", "chrome110", "chrome107",
        "chrome104", "chrome101", "chrome100", "chrome99",
        // Chrome Android
        "chrome131_android", "chrome99_android",
        // Safari Desktop
        "safari260", "safari184", "safari180", "safari170", "safari155", "safari153",
        // Safari iOS
        "safari260_ios", "safari184_ios", "safari180_ios", "safari172_ios",
        // Firefox
        "firefox133",
        // Edge
        "edge101", "edge99",
        // Tor
        "tor145"
    };

    // Highlight color options (display name -> HighlightColor mapping)
    private static final String HIGHLIGHT_NONE = "None (No Highlight)";
    private static final String[] HIGHLIGHT_OPTIONS = {
        "Green", "Blue", "Cyan", "Yellow", "Orange", "Red", "Pink", "Magenta", "Gray", HIGHLIGHT_NONE
    };

    // Persistence keys
    private static final String KEY_PYTHON_PATH = "pythonPath";
    private static final String KEY_SCRIPT_PATH = "scriptPath";
    private static final String KEY_SERVER_PORT = "serverPort";
    private static final String KEY_IMPERSONATE_TARGET = "impersonateTarget";
    private static final String KEY_LOG_REQUESTS = "logRequests";
    private static final String KEY_HIGHLIGHT_COLOR = "highlightColor";
    private static final String KEY_AUTO_USER_AGENT = "autoUserAgent";

    /**
     * Creates a new ConfigTab instance.
     *
     * @param api the Montoya API instance
     * @param processManager the process manager for Python server
     * @param workerClient the worker client for communication
     * @param httpHandler the HTTP handler for request interception
     * @param filterConfig the filter configuration
     * @param logging the logging interface
     * @param persistence the persistence object for saving settings
     * @param extractedScriptPath the path to the auto-extracted worker.py, or null if not available
     */
    public ConfigTab(MontoyaApi api, ProcessManager processManager,
                     PythonWorkerClient workerClient, TLSBypassHttpHandler httpHandler,
                     FilterConfig filterConfig, Logging logging, PersistedObject persistence,
                     String extractedScriptPath) {
        this.api = api;
        this.processManager = processManager;
        this.workerClient = workerClient;
        this.httpHandler = httpHandler;
        this.filterConfig = filterConfig;
        this.logging = logging;
        this.persistence = persistence;
        this.extractedScriptPath = extractedScriptPath;

        initializeUI();
        loadSettings();  // Load saved settings after UI is initialized
        setupLogListener();
        startStatsTimer();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // Configure tooltip timing for better UX
        ToolTipManager.sharedInstance().setInitialDelay(300);    // Show after 300ms (default: 750ms)
        ToolTipManager.sharedInstance().setDismissDelay(15000);  // Stay visible for 15 seconds (default: 4s)

        // Apply Burp theme
        api.userInterface().applyThemeToComponent(this);

        // Create main split pane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.4);

        // Top panel - Configuration
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));

        // Server configuration panel
        JPanel serverPanel = createServerConfigPanel();
        topPanel.add(serverPanel, BorderLayout.NORTH);

        // Filter panel
        filterPanel = new FilterPanel(filterConfig, logging);
        filterPanel.setOnSettingsChanged(this::saveSettings);  // Auto-save when filter changes
        api.userInterface().applyThemeToComponent(filterPanel);
        topPanel.add(filterPanel, BorderLayout.CENTER);

        mainSplitPane.setTopComponent(topPanel);

        // Bottom panel - Log
        logPanel = new LogPanel();
        api.userInterface().applyThemeToComponent(logPanel);
        mainSplitPane.setBottomComponent(logPanel);

        add(mainSplitPane, BorderLayout.CENTER);

        // Status bar at bottom
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);
    }

    private JPanel createServerConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Python Worker Configuration"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Python path
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Python Executable:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        pythonPathField = new JTextField(getDefaultPythonPath(), 35);
        pythonPathField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                saveSettings();
            }
        });
        panel.add(pythonPathField, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        JButton browsePythonButton = new JButton("Browse...");
        browsePythonButton.addActionListener(e -> browseFile(pythonPathField, "Select Python Executable"));
        panel.add(browsePythonButton, gbc);

        row++;

        // Script path
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Worker Script:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        scriptPathField = new JTextField("", 35);
        scriptPathField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                saveSettings();
            }
        });
        panel.add(scriptPathField, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        JButton browseScriptButton = new JButton("Browse...");
        browseScriptButton.addActionListener(e -> browseFile(scriptPathField, "Select worker.py"));
        panel.add(browseScriptButton, gbc);

        row++;

        // Port
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Server Port:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.NONE;
        portField = new JTextField("8787", 8);
        portField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                saveSettings();
            }
        });
        panel.add(portField, gbc);

        row++;

        // Impersonate target
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("Impersonate Browser:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        impersonateCombo = new JComboBox<>(IMPERSONATE_TARGETS);
        impersonateCombo.setSelectedItem("chrome");
        impersonateCombo.addActionListener(e -> {
            updateImpersonateTarget();
            saveSettings();  // Auto-save when browser selection changes
        });
        panel.add(impersonateCombo, gbc);

        row++;

        // Control buttons
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));

        startStopButton = new JButton("Start Server");
        startStopButton.setPreferredSize(new Dimension(120, 30));
        startStopButton.addActionListener(e -> toggleServer());
        buttonPanel.add(startStopButton);

        testConnectionButton = new JButton("Test Connection");
        testConnectionButton.setEnabled(false);
        testConnectionButton.addActionListener(e -> testConnection());
        buttonPanel.add(testConnectionButton);

        JButton validateButton = new JButton("Validate Python");
        validateButton.addActionListener(e -> validatePythonEnvironment());
        buttonPanel.add(validateButton);

        JButton autoSetupButton = new JButton("Auto Setup");
        autoSetupButton.setToolTipText("Create virtual environment and install dependencies automatically");
        autoSetupButton.addActionListener(e -> autoSetupEnvironment());
        buttonPanel.add(autoSetupButton);

        panel.add(buttonPanel, gbc);

        row++;

        // Enable bypass checkbox - highlighted with red dotted border
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.WEST;

        JPanel checkboxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));

        // Create a highlighted panel for the Enable TLS Bypass checkbox
        JPanel enableBypassPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        enableBypassPanel.setBorder(BorderFactory.createCompoundBorder(
            new DashedBorder(Color.RED, 2, 5, 3),  // Red dotted border
            BorderFactory.createEmptyBorder(3, 8, 3, 8)
        ));

        // Important label
        JLabel importantLabel = new JLabel("IMPORTANT");
        importantLabel.setForeground(Color.RED);
        importantLabel.setFont(importantLabel.getFont().deriveFont(Font.BOLD, 10f));
        enableBypassPanel.add(importantLabel);

        enableBypassCheckbox = new JCheckBox("Enable TLS Bypass");
        enableBypassCheckbox.setEnabled(false);
        enableBypassCheckbox.addActionListener(e -> toggleBypass());
        enableBypassPanel.add(enableBypassCheckbox);

        checkboxPanel.add(enableBypassPanel);

        logRequestsCheckbox = new JCheckBox("Log Requests", true);
        logRequestsCheckbox.addActionListener(e -> {
            httpHandler.setLogRequests(logRequestsCheckbox.isSelected());
            saveSettings();  // Auto-save when log setting changes
        });
        checkboxPanel.add(logRequestsCheckbox);

        autoUserAgentCheckbox = new JCheckBox("Auto User-Agent", true);
        autoUserAgentCheckbox.setToolTipText("ON: Auto-match User-Agent to fingerprint / OFF: Keep original");
        autoUserAgentCheckbox.addActionListener(e -> {
            workerClient.setAutoUserAgent(autoUserAgentCheckbox.isSelected());
            saveSettings();
        });
        checkboxPanel.add(autoUserAgentCheckbox);

        // Highlight color selector with color preview
        checkboxPanel.add(new JLabel("  Highlight:"));
        highlightColorCombo = new JComboBox<>(HIGHLIGHT_OPTIONS);
        highlightColorCombo.setSelectedItem("Green");
        highlightColorCombo.setRenderer(new HighlightColorRenderer());
        highlightColorCombo.addActionListener(e -> {
            updateHighlightColor();
            saveSettings();
        });
        checkboxPanel.add(highlightColorCombo);

        panel.add(checkboxPanel, gbc);

        row++;

        // Status label
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        statusLabel = new JLabel("Status: Server not running");
        statusLabel.setForeground(Color.GRAY);
        panel.add(statusLabel, gbc);

        return panel;
    }

    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY),
            new EmptyBorder(5, 10, 5, 10)
        ));

        statsLabel = new JLabel("Requests: 0 | Bypassed: 0 | Failed: 0");
        statusBar.add(statsLabel, BorderLayout.WEST);

        JButton resetStatsButton = new JButton("Reset Stats");
        resetStatsButton.addActionListener(e -> {
            httpHandler.resetStatistics();
            updateStats();
        });
        statusBar.add(resetStatsButton, BorderLayout.EAST);

        return statusBar;
    }

    private void setupLogListener() {
        httpHandler.setLogListener((method, url, statusCode, elapsedMs, success) ->
            SwingUtilities.invokeLater(() -> {
                logPanel.addLogEntry(method, url, statusCode, elapsedMs, success);
                updateStats();
            })
        );
    }

    private void startStatsTimer() {
        statsTimer = new Timer(1000, e -> updateStats());
        statsTimer.start();
    }

    private void updateStats() {
        long[] stats = httpHandler.getStatistics();
        statsLabel.setText(String.format(
            "Requests: %d | Bypassed: %d | Failed: %d",
            stats[0], stats[1], stats[2]
        ));
    }

    private String getDefaultPythonPath() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return "python";
        } else if (os.contains("mac")) {
            // Check common Python locations on macOS
            String[] paths = {"/usr/local/bin/python3", "/opt/homebrew/bin/python3", "/usr/bin/python3"};
            for (String path : paths) {
                if (new File(path).exists()) {
                    return path;
                }
            }
            return "/usr/bin/python3";
        } else {
            return "/usr/bin/python3";
        }
    }

    private void browseFile(JTextField targetField, String title) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(title);
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        // Set initial directory
        String currentPath = targetField.getText();
        if (!currentPath.isEmpty()) {
            File current = new File(currentPath);
            if (current.getParentFile() != null && current.getParentFile().exists()) {
                chooser.setCurrentDirectory(current.getParentFile());
            }
        }

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            targetField.setText(chooser.getSelectedFile().getAbsolutePath());
            saveSettings();  // Auto-save when file is selected
        }
    }

    private void validatePythonEnvironment() {
        String pythonPath = pythonPathField.getText().trim();
        if (pythonPath.isEmpty()) {
            showError("Python path is empty");
            return;
        }

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                return processManager.validatePythonEnvironment(pythonPath);
            }

            @Override
            protected void done() {
                try {
                    String error = get();
                    if (error == null) {
                        showInfo("Python environment validated successfully!\nAll required packages are installed.");
                    } else {
                        // Check if venv exists and offer to use it
                        String scriptPath = scriptPathField.getText().trim();
                        String venvPython = processManager.getExistingVenvPython(scriptPath);
                        if (venvPython != null) {
                            int choice = JOptionPane.showConfirmDialog(
                                ConfigTab.this,
                                "Validation failed for system Python.\n\n" +
                                "A virtual environment with required packages was found:\n" +
                                venvPython + "\n\n" +
                                "Would you like to use this venv Python instead?",
                                "Use Virtual Environment?",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.QUESTION_MESSAGE
                            );
                            if (choice == JOptionPane.YES_OPTION) {
                                pythonPathField.setText(venvPython);
                                showInfo("Python path updated to use virtual environment.");
                                return;
                            }
                        }
                        showError("Validation failed:\n" + error + "\n\nClick 'Auto Setup' to create a virtual environment.");
                    }
                } catch (Exception e) {
                    showError("Validation error: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void autoSetupEnvironment() {
        String systemPythonPath = pythonPathField.getText().trim();
        String scriptPath = scriptPathField.getText().trim();

        // Validation
        if (systemPythonPath.isEmpty()) {
            showError("Python executable path is required.\nProvide the path to your system Python (e.g., /usr/bin/python3)");
            return;
        }
        if (scriptPath.isEmpty()) {
            showError("Worker script path is required.\nPlease select the worker.py file first.");
            return;
        }
        if (!new File(scriptPath).exists()) {
            showError("Worker script not found: " + scriptPath);
            return;
        }

        // Check if venv already exists
        String existingVenv = processManager.getExistingVenvPython(scriptPath);
        if (existingVenv != null) {
            int choice = JOptionPane.showConfirmDialog(
                this,
                "A valid virtual environment already exists:\n" + existingVenv + "\n\n" +
                "Would you like to use this existing environment?\n" +
                "(Choose 'No' to recreate from scratch)",
                "Virtual Environment Found",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );

            if (choice == JOptionPane.YES_OPTION) {
                pythonPathField.setText(existingVenv);
                showInfo("Python path updated to use existing virtual environment.");
                return;
            } else if (choice == JOptionPane.CANCEL_OPTION) {
                return;
            }
            // If NO, continue to recreate
        }

        // Create progress dialog
        JDialog progressDialog = new JDialog(
            SwingUtilities.getWindowAncestor(this),
            "Setting Up Environment",
            java.awt.Dialog.ModalityType.APPLICATION_MODAL
        );
        progressDialog.setLayout(new BorderLayout(10, 10));
        progressDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(new EmptyBorder(20, 20, 20, 20));

        JLabel titleLabel = new JLabel("Creating Virtual Environment...");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        contentPanel.add(titleLabel, BorderLayout.NORTH);

        JTextArea progressArea = new JTextArea(10, 50);
        progressArea.setEditable(false);
        progressArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(progressArea);
        contentPanel.add(scrollPane, BorderLayout.CENTER);

        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setString("Installing packages...");
        progressBar.setStringPainted(true);
        contentPanel.add(progressBar, BorderLayout.SOUTH);

        progressDialog.add(contentPanel);
        progressDialog.pack();
        progressDialog.setLocationRelativeTo(this);

        // Run setup in background
        SwingWorker<ProcessManager.SetupResult, String> worker = new SwingWorker<>() {
            @Override
            protected ProcessManager.SetupResult doInBackground() {
                return processManager.setupVirtualEnvironment(
                    systemPythonPath,
                    scriptPath,
                    message -> publish(message)
                );
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    progressArea.append(message + "\n");
                    progressArea.setCaretPosition(progressArea.getDocument().getLength());
                }
            }

            @Override
            protected void done() {
                progressDialog.dispose();
                try {
                    ProcessManager.SetupResult result = get();
                    if (result.success) {
                        pythonPathField.setText(result.venvPythonPath);
                        showInfo("Setup completed successfully!\n\n" + result.message +
                            "\n\nThe Python path has been updated to use the virtual environment.");
                    } else {
                        showError("Setup failed:\n\n" + result.message);
                    }
                } catch (Exception e) {
                    showError("Setup error: " + e.getMessage());
                }
            }
        };

        worker.execute();
        progressDialog.setVisible(true);
    }

    private void toggleServer() {
        if (processManager.isRunning()) {
            stopServer();
        } else {
            startServer();
        }
    }

    private void startServer() {
        String pythonPath = pythonPathField.getText().trim();
        String scriptPath = scriptPathField.getText().trim();
        String portStr = portField.getText().trim();

        // Validation
        if (pythonPath.isEmpty()) {
            showError("Python executable path is required");
            return;
        }
        if (scriptPath.isEmpty()) {
            showError("Worker script path is required");
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            showError("Invalid port number (must be 1-65535)");
            return;
        }

        // Disable button during startup
        startStopButton.setEnabled(false);
        startStopButton.setText("Starting...");
        statusLabel.setText("Status: Starting server...");
        statusLabel.setForeground(Color.ORANGE);

        // Start server in background
        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return processManager.startPythonServer(pythonPath, scriptPath, port);
            }

            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        // Configure worker client
                        String serverUrl = "http://127.0.0.1:" + port;
                        String impersonate = (String) impersonateCombo.getSelectedItem();
                        workerClient.configure(serverUrl, impersonate);

                        // Test connection
                        if (workerClient.checkConnection()) {
                            onServerStarted();
                        } else {
                            processManager.stopPythonServer();
                            onServerStopped();
                            showError("Server started but connection test failed");
                        }
                    } else {
                        onServerStopped();
                        showError("Failed to start Python server.\nCheck the Extender output for details.");
                    }
                } catch (Exception e) {
                    onServerStopped();
                    showError("Error starting server: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void stopServer() {
        processManager.stopPythonServer();
        httpHandler.setEnabled(false);
        onServerStopped();
    }

    private void onServerStarted() {
        startStopButton.setText("Stop Server");
        startStopButton.setEnabled(true);
        testConnectionButton.setEnabled(true);
        enableBypassCheckbox.setEnabled(true);
        statusLabel.setText("Status: Server running on port " + portField.getText());
        statusLabel.setForeground(new Color(0, 128, 0));

        // Disable path fields while running
        pythonPathField.setEnabled(false);
        scriptPathField.setEnabled(false);
        portField.setEnabled(false);
    }

    private void onServerStopped() {
        startStopButton.setText("Start Server");
        startStopButton.setEnabled(true);
        testConnectionButton.setEnabled(false);
        enableBypassCheckbox.setEnabled(false);
        enableBypassCheckbox.setSelected(false);
        statusLabel.setText("Status: Server not running");
        statusLabel.setForeground(Color.GRAY);

        // Re-enable path fields
        pythonPathField.setEnabled(true);
        scriptPathField.setEnabled(true);
        portField.setEnabled(true);
    }

    private void testConnection() {
        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return workerClient.checkConnection();
            }

            @Override
            protected void done() {
                try {
                    if (get()) {
                        showInfo("Connection successful!\nServer is responding.");
                    } else {
                        showError("Connection failed.\nIs the server running?");
                    }
                } catch (Exception e) {
                    showError("Connection error: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void toggleBypass() {
        boolean enabled = enableBypassCheckbox.isSelected();
        httpHandler.setEnabled(enabled);

        if (enabled) {
            statusLabel.setText("Status: TLS Bypass ACTIVE - " + impersonateCombo.getSelectedItem());
            statusLabel.setForeground(new Color(0, 128, 0));
        } else {
            statusLabel.setText("Status: Server running (bypass disabled)");
            statusLabel.setForeground(Color.ORANGE);
        }
    }

    private void updateImpersonateTarget() {
        String target = (String) impersonateCombo.getSelectedItem();
        workerClient.configure(workerClient.getServerUrl(), target);

        if (httpHandler.isEnabled()) {
            statusLabel.setText("Status: TLS Bypass ACTIVE - " + target);
        }
    }

    private void updateHighlightColor() {
        String selected = (String) highlightColorCombo.getSelectedItem();
        HighlightColor color = getHighlightColorFromName(selected);
        httpHandler.setHighlightColor(color);
        logging.logToOutput("[ConfigTab] Highlight color changed to: " + selected);
    }

    /**
     * Converts a color name to HighlightColor enum.
     *
     * @param name the color name
     * @return the HighlightColor, or null if "None" is selected
     */
    private HighlightColor getHighlightColorFromName(String name) {
        if (name == null || HIGHLIGHT_NONE.equals(name)) {
            return null;
        }
        switch (name.toLowerCase()) {
            case "green": return HighlightColor.GREEN;
            case "blue": return HighlightColor.BLUE;
            case "cyan": return HighlightColor.CYAN;
            case "yellow": return HighlightColor.YELLOW;
            case "orange": return HighlightColor.ORANGE;
            case "red": return HighlightColor.RED;
            case "pink": return HighlightColor.PINK;
            case "magenta": return HighlightColor.MAGENTA;
            case "gray": return HighlightColor.GRAY;
            default: return HighlightColor.GREEN;
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private void showInfo(String message) {
        JOptionPane.showMessageDialog(this, message, "Info", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Loads saved settings from persistence.
     */
    private void loadSettings() {
        if (persistence == null) return;

        try {
            // Load Python path
            String pythonPath = persistence.getString(KEY_PYTHON_PATH);
            if (pythonPath != null && !pythonPath.isEmpty()) {
                pythonPathField.setText(pythonPath);
            }

            // Load script path - use extracted path as default if no saved value
            String scriptPath = persistence.getString(KEY_SCRIPT_PATH);
            if (scriptPath != null && !scriptPath.isEmpty()) {
                scriptPathField.setText(scriptPath);
            } else if (extractedScriptPath != null && !extractedScriptPath.isEmpty()) {
                // Use auto-extracted script path as default
                scriptPathField.setText(extractedScriptPath);
                logging.logToOutput("[ConfigTab] Using auto-extracted script path: " + extractedScriptPath);
            }

            // Load server port
            String port = persistence.getString(KEY_SERVER_PORT);
            if (port != null && !port.isEmpty()) {
                portField.setText(port);
            }

            // Load impersonate target
            String target = persistence.getString(KEY_IMPERSONATE_TARGET);
            if (target != null && !target.isEmpty()) {
                impersonateCombo.setSelectedItem(target);
            }

            // Load log requests setting
            String logRequests = persistence.getString(KEY_LOG_REQUESTS);
            if (logRequests != null) {
                boolean log = Boolean.parseBoolean(logRequests);
                logRequestsCheckbox.setSelected(log);
                httpHandler.setLogRequests(log);
            }

            // Load highlight color setting
            String highlightColor = persistence.getString(KEY_HIGHLIGHT_COLOR);
            if (highlightColor != null && !highlightColor.isEmpty()) {
                highlightColorCombo.setSelectedItem(highlightColor);
                updateHighlightColor();
            }

            // Load auto user-agent setting
            String autoUserAgent = persistence.getString(KEY_AUTO_USER_AGENT);
            if (autoUserAgent != null) {
                boolean auto = Boolean.parseBoolean(autoUserAgent);
                autoUserAgentCheckbox.setSelected(auto);
                workerClient.setAutoUserAgent(auto);
            }

            logging.logToOutput("[ConfigTab] Settings loaded from persistence");
        } catch (Exception e) {
            logging.logToError("[ConfigTab] Error loading settings: " + e.getMessage());
        }
    }

    /**
     * Saves current settings to persistence.
     */
    private void saveSettings() {
        if (persistence == null) return;

        try {
            persistence.setString(KEY_PYTHON_PATH, pythonPathField.getText());
            persistence.setString(KEY_SCRIPT_PATH, scriptPathField.getText());
            persistence.setString(KEY_SERVER_PORT, portField.getText());
            persistence.setString(KEY_IMPERSONATE_TARGET, (String) impersonateCombo.getSelectedItem());
            persistence.setString(KEY_LOG_REQUESTS, String.valueOf(logRequestsCheckbox.isSelected()));
            persistence.setString(KEY_HIGHLIGHT_COLOR, (String) highlightColorCombo.getSelectedItem());
            persistence.setString(KEY_AUTO_USER_AGENT, String.valueOf(autoUserAgentCheckbox.isSelected()));

            // Also save filter configuration
            filterConfig.saveToPersistence(persistence);

            logging.logToOutput("[ConfigTab] Settings saved to persistence");
        } catch (Exception e) {
            logging.logToError("[ConfigTab] Error saving settings: " + e.getMessage());
        }
    }

    /**
     * Converts a color name to AWT Color for preview display.
     * Colors are matched to Burp Suite's actual highlight colors.
     *
     * @param name the color name
     * @return the AWT Color
     */
    private Color getPreviewColor(String name) {
        if (name == null || HIGHLIGHT_NONE.equals(name)) {
            return null;
        }
        // These colors match Burp Suite's actual highlight colors
        switch (name.toLowerCase()) {
            case "green": return new Color(144, 238, 144);   // Light green (Burp's green)
            case "blue": return new Color(173, 216, 230);    // Light blue (Burp's blue)
            case "cyan": return new Color(175, 238, 238);    // Pale turquoise (Burp's cyan)
            case "yellow": return new Color(255, 255, 153);  // Light yellow (Burp's yellow)
            case "orange": return new Color(255, 200, 128);  // Light orange (Burp's orange)
            case "red": return new Color(255, 182, 193);     // Light pink/red (Burp's red)
            case "pink": return new Color(255, 192, 203);    // Pink (Burp's pink)
            case "magenta": return new Color(255, 170, 255); // Light magenta (Burp's magenta)
            case "gray": return new Color(211, 211, 211);    // Light gray (Burp's gray)
            default: return new Color(144, 238, 144);
        }
    }

    /**
     * Custom renderer for the highlight color combo box that displays color previews.
     */
    private class HighlightColorRenderer extends JPanel implements ListCellRenderer<String> {
        private final JLabel colorLabel;
        private final JPanel colorPreview;

        public HighlightColorRenderer() {
            setLayout(new BorderLayout(5, 0));
            setOpaque(true);

            colorPreview = new JPanel() {
                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    if (getBackground() != null) {
                        g.setColor(Color.DARK_GRAY);
                        g.drawRect(0, 0, getWidth() - 1, getHeight() - 1);
                    }
                }
            };
            colorPreview.setPreferredSize(new Dimension(16, 16));
            colorPreview.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

            colorLabel = new JLabel();
            colorLabel.setOpaque(false);

            add(colorPreview, BorderLayout.WEST);
            add(colorLabel, BorderLayout.CENTER);
            setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends String> list, String value,
                                                       int index, boolean isSelected, boolean cellHasFocus) {
            colorLabel.setText(value);

            Color previewColor = getPreviewColor(value);
            if (previewColor != null) {
                colorPreview.setBackground(previewColor);
                colorPreview.setVisible(true);
            } else {
                // "None" option - show X mark or empty
                colorPreview.setBackground(getBackground());
                colorPreview.setVisible(true);
            }

            if (isSelected) {
                setBackground(list.getSelectionBackground());
                setForeground(list.getSelectionForeground());
                colorLabel.setForeground(list.getSelectionForeground());
            } else {
                setBackground(list.getBackground());
                setForeground(list.getForeground());
                colorLabel.setForeground(list.getForeground());
            }

            return this;
        }
    }

    /**
     * Custom dashed border for highlighting important UI elements.
     */
    private static class DashedBorder extends AbstractBorder {
        private final Color color;
        private final int thickness;
        private final float dashLength;
        private final float gapLength;

        public DashedBorder(Color color, int thickness, float dashLength, float gapLength) {
            this.color = color;
            this.thickness = thickness;
            this.dashLength = dashLength;
            this.gapLength = gapLength;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Graphics2D g2d = (Graphics2D) g.create();
            g2d.setColor(color);
            g2d.setStroke(new BasicStroke(
                thickness,
                BasicStroke.CAP_ROUND,
                BasicStroke.JOIN_ROUND,
                0,
                new float[]{dashLength, gapLength},
                0
            ));
            g2d.drawRoundRect(x + thickness / 2, y + thickness / 2,
                width - thickness, height - thickness, 8, 8);
            g2d.dispose();
        }

        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(thickness + 1, thickness + 1, thickness + 1, thickness + 1);
        }

        @Override
        public Insets getBorderInsets(Component c, Insets insets) {
            insets.left = insets.right = insets.top = insets.bottom = thickness + 1;
            return insets;
        }
    }
}
