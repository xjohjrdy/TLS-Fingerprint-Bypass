/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp.ui;

import burp.api.montoya.logging.Logging;
import com.bypasstls.burp.FilterConfig;
import com.bypasstls.burp.FilterConfig.FilterMode;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;

/**
 * Panel for configuring request filtering options.
 * <p>
 * Allows users to specify which requests should be processed through
 * the TLS bypass mechanism based on:
 * <ul>
 *   <li>All requests</li>
 *   <li>Specific domains</li>
 *   <li>URI patterns (regex)</li>
 * </ul>
 * </p>
 */
public class FilterPanel extends JPanel {

    private final FilterConfig filterConfig;
    private final Logging logging;
    private Runnable onSettingsChanged;

    // Mode selection
    private JRadioButton allRequestsRadio;
    private JRadioButton specificDomainsRadio;
    private JRadioButton specificUrisRadio;
    private ButtonGroup modeGroup;

    // List components
    private DefaultListModel<String> listModel;
    private JList<String> filterList;
    private JTextField inputField;
    private JButton addButton;
    private JButton removeButton;
    private JButton clearButton;

    // Labels
    private JLabel listLabel;
    private JLabel helpLabel;

    /**
     * Creates a new FilterPanel.
     */
    public FilterPanel(FilterConfig filterConfig, Logging logging) {
        this.filterConfig = filterConfig;
        this.logging = logging;

        initializeUI();
        loadCurrentConfig();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Request Filter Configuration"));

        // Mode selection panel (top)
        JPanel modePanel = createModeSelectionPanel();
        add(modePanel, BorderLayout.NORTH);

        // List management panel (center)
        JPanel listPanel = createListPanel();
        add(listPanel, BorderLayout.CENTER);

        // Update UI based on initial mode
        updateUIForMode(filterConfig.getMode());
    }

    private JPanel createModeSelectionPanel() {
        JPanel panel = new JPanel(new GridLayout(3, 1, 5, 5));
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));

        modeGroup = new ButtonGroup();

        allRequestsRadio = new JRadioButton("Apply to ALL requests");
        allRequestsRadio.setToolTipText("TLS bypass will be applied to every HTTP/HTTPS request");
        allRequestsRadio.addActionListener(e -> onModeChanged(FilterMode.ALL_REQUESTS));

        specificDomainsRadio = new JRadioButton("Apply to SPECIFIC DOMAINS only");
        specificDomainsRadio.setToolTipText("TLS bypass will only be applied to requests matching the specified domains");
        specificDomainsRadio.addActionListener(e -> onModeChanged(FilterMode.SPECIFIC_DOMAINS));

        specificUrisRadio = new JRadioButton("Apply to SPECIFIC URI PATTERNS (Regex)");
        specificUrisRadio.setToolTipText("TLS bypass will only be applied to requests matching the specified regex patterns");
        specificUrisRadio.addActionListener(e -> onModeChanged(FilterMode.SPECIFIC_URIS));

        modeGroup.add(allRequestsRadio);
        modeGroup.add(specificDomainsRadio);
        modeGroup.add(specificUrisRadio);

        panel.add(allRequestsRadio);
        panel.add(specificDomainsRadio);
        panel.add(specificUrisRadio);

        return panel;
    }

    private JPanel createListPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Label
        JPanel labelPanel = new JPanel(new BorderLayout());
        listLabel = new JLabel("Domains/Patterns:");
        labelPanel.add(listLabel, BorderLayout.WEST);

        helpLabel = new JLabel();
        helpLabel.setForeground(Color.GRAY);
        helpLabel.setFont(helpLabel.getFont().deriveFont(Font.ITALIC, 11f));
        labelPanel.add(helpLabel, BorderLayout.EAST);

        panel.add(labelPanel, BorderLayout.NORTH);

        // List
        listModel = new DefaultListModel<>();
        filterList = new JList<>(listModel);
        filterList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        filterList.addListSelectionListener(e -> updateButtonStates());

        JScrollPane scrollPane = new JScrollPane(filterList);
        scrollPane.setPreferredSize(new Dimension(400, 150));
        panel.add(scrollPane, BorderLayout.CENTER);

        // Input and buttons panel
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));

        inputField = new JTextField();
        inputField.addActionListener(e -> addItem());
        inputPanel.add(inputField, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));

        addButton = new JButton("Add");
        addButton.addActionListener(e -> addItem());
        buttonPanel.add(addButton);

        removeButton = new JButton("Remove");
        removeButton.setEnabled(false);
        removeButton.addActionListener(e -> removeSelectedItems());
        buttonPanel.add(removeButton);

        clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> clearAllItems());
        buttonPanel.add(clearButton);

        inputPanel.add(buttonPanel, BorderLayout.EAST);

        panel.add(inputPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void onModeChanged(FilterMode mode) {
        filterConfig.setMode(mode);
        updateUIForMode(mode);
        logging.logToOutput("[FilterPanel] Mode changed to: " + mode.getDisplayName());
        notifySettingsChanged();
    }

    private void updateUIForMode(FilterMode mode) {
        boolean listEnabled = (mode != FilterMode.ALL_REQUESTS);

        // Update radio buttons
        switch (mode) {
            case ALL_REQUESTS:
                allRequestsRadio.setSelected(true);
                listLabel.setText("(No list needed - all requests will be bypassed)");
                helpLabel.setText("");
                break;
            case SPECIFIC_DOMAINS:
                specificDomainsRadio.setSelected(true);
                listLabel.setText("Domains to bypass:");
                helpLabel.setText("Example: example.com, api.target.com");
                break;
            case SPECIFIC_URIS:
                specificUrisRadio.setSelected(true);
                listLabel.setText("URI patterns to bypass (Regex):");
                helpLabel.setText("Example: .*\\.example\\.com/api/.*");
                break;
        }

        // Enable/disable list components
        filterList.setEnabled(listEnabled);
        inputField.setEnabled(listEnabled);
        addButton.setEnabled(listEnabled);
        clearButton.setEnabled(listEnabled && listModel.getSize() > 0);

        // Load appropriate list content
        loadListForMode(mode);

        updateButtonStates();
    }

    private void loadListForMode(FilterMode mode) {
        listModel.clear();

        switch (mode) {
            case SPECIFIC_DOMAINS:
                for (String domain : filterConfig.getDomains()) {
                    listModel.addElement(domain);
                }
                break;
            case SPECIFIC_URIS:
                for (String pattern : filterConfig.getUriPatterns()) {
                    listModel.addElement(pattern);
                }
                break;
            default:
                // No list for ALL_REQUESTS mode
                break;
        }
    }

    private void loadCurrentConfig() {
        FilterMode mode = filterConfig.getMode();
        updateUIForMode(mode);
    }

    private void addItem() {
        String input = inputField.getText().trim();
        if (input.isEmpty()) {
            return;
        }

        FilterMode mode = filterConfig.getMode();

        try {
            switch (mode) {
                case SPECIFIC_DOMAINS:
                    // Validate domain format (basic check)
                    if (!input.matches("^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$")) {
                        showError("Invalid domain format: " + input);
                        return;
                    }
                    filterConfig.addDomain(input);
                    listModel.addElement(input.toLowerCase());
                    logging.logToOutput("[FilterPanel] Added domain: " + input);
                    break;

                case SPECIFIC_URIS:
                    // Validate regex pattern
                    String error = FilterConfig.validatePattern(input);
                    if (error != null) {
                        showError(error);
                        return;
                    }
                    filterConfig.addUriPattern(input);
                    listModel.addElement(input);
                    logging.logToOutput("[FilterPanel] Added URI pattern: " + input);
                    break;

                default:
                    return;
            }

            inputField.setText("");
            updateButtonStates();
            notifySettingsChanged();

        } catch (IllegalArgumentException e) {
            showError(e.getMessage());
        }
    }

    private void removeSelectedItems() {
        int[] indices = filterList.getSelectedIndices();
        if (indices.length == 0) {
            return;
        }

        FilterMode mode = filterConfig.getMode();

        // Remove in reverse order to maintain indices
        for (int i = indices.length - 1; i >= 0; i--) {
            String item = listModel.getElementAt(indices[i]);

            switch (mode) {
                case SPECIFIC_DOMAINS:
                    filterConfig.removeDomain(item);
                    break;
                case SPECIFIC_URIS:
                    filterConfig.removeUriPattern(item);
                    break;
                default:
                    break;
            }

            listModel.remove(indices[i]);
            logging.logToOutput("[FilterPanel] Removed: " + item);
        }

        updateButtonStates();
        notifySettingsChanged();
    }

    private void clearAllItems() {
        int result = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to clear all items?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            FilterMode mode = filterConfig.getMode();

            switch (mode) {
                case SPECIFIC_DOMAINS:
                    filterConfig.clearDomains();
                    break;
                case SPECIFIC_URIS:
                    filterConfig.clearUriPatterns();
                    break;
                default:
                    break;
            }

            listModel.clear();
            updateButtonStates();
            logging.logToOutput("[FilterPanel] Cleared all items");
            notifySettingsChanged();
        }
    }

    private void updateButtonStates() {
        boolean hasSelection = !filterList.isSelectionEmpty();
        boolean hasItems = listModel.getSize() > 0;
        boolean listEnabled = filterConfig.getMode() != FilterMode.ALL_REQUESTS;

        removeButton.setEnabled(listEnabled && hasSelection);
        clearButton.setEnabled(listEnabled && hasItems);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Gets a summary of the current filter configuration.
     */
    public String getConfigSummary() {
        return filterConfig.getConfigSummary();
    }

    /**
     * Sets a callback to be invoked when filter settings change.
     *
     * @param callback the callback to invoke
     */
    public void setOnSettingsChanged(Runnable callback) {
        this.onSettingsChanged = callback;
    }

    /**
     * Notifies that settings have changed.
     */
    private void notifySettingsChanged() {
        if (onSettingsChanged != null) {
            onSettingsChanged.run();
        }
    }
}
