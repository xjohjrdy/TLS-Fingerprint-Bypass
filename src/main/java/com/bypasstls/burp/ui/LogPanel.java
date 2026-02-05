/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp.ui;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Panel for displaying request/response logs.
 * <p>
 * Shows a table of all requests processed through the TLS bypass,
 * including timestamp, method, URL, status code, and timing information.
 * </p>
 */
public class LogPanel extends JPanel {

    private static final int MAX_LOG_ENTRIES = 1000;

    private DefaultTableModel tableModel;
    private JTable logTable;
    private JCheckBox autoScrollCheckbox;
    private JLabel countLabel;

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    /**
     * Creates a new LogPanel.
     */
    public LogPanel() {
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Request Log"));

        // Create table model
        String[] columns = {"Time", "Method", "URL", "Status", "Time (ms)", "Result"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                switch (columnIndex) {
                    case 3: // Status
                    case 4: // Time (ms)
                        return Integer.class;
                    default:
                        return String.class;
                }
            }
        };

        // Create table
        logTable = new JTable(tableModel);
        logTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logTable.setRowHeight(20);

        // Set column widths
        TableColumnModel columnModel = logTable.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(90);   // Time
        columnModel.getColumn(0).setMaxWidth(100);
        columnModel.getColumn(1).setPreferredWidth(60);   // Method
        columnModel.getColumn(1).setMaxWidth(80);
        columnModel.getColumn(2).setPreferredWidth(400);  // URL
        columnModel.getColumn(3).setPreferredWidth(60);   // Status
        columnModel.getColumn(3).setMaxWidth(80);
        columnModel.getColumn(4).setPreferredWidth(70);   // Time (ms)
        columnModel.getColumn(4).setMaxWidth(90);
        columnModel.getColumn(5).setPreferredWidth(70);   // Result
        columnModel.getColumn(5).setMaxWidth(90);

        // Custom renderer for status column (color coding)
        columnModel.getColumn(3).setCellRenderer(new StatusCellRenderer());
        columnModel.getColumn(5).setCellRenderer(new ResultCellRenderer());

        // Scroll pane
        JScrollPane scrollPane = new JScrollPane(logTable);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(scrollPane, BorderLayout.CENTER);

        // Controls panel
        JPanel controlsPanel = new JPanel(new BorderLayout());
        controlsPanel.setBorder(new EmptyBorder(5, 0, 0, 0));

        // Left side - auto scroll and count
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        autoScrollCheckbox = new JCheckBox("Auto-scroll", true);
        leftPanel.add(autoScrollCheckbox);

        countLabel = new JLabel("Entries: 0");
        leftPanel.add(countLabel);

        controlsPanel.add(leftPanel, BorderLayout.WEST);

        // Right side - clear button
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        JButton clearButton = new JButton("Clear Log");
        clearButton.addActionListener(e -> clearLog());
        rightPanel.add(clearButton);

        JButton exportButton = new JButton("Export...");
        exportButton.addActionListener(e -> exportLog());
        rightPanel.add(exportButton);

        controlsPanel.add(rightPanel, BorderLayout.EAST);

        add(controlsPanel, BorderLayout.SOUTH);
    }

    /**
     * Adds a log entry to the table.
     *
     * @param method HTTP method
     * @param url request URL
     * @param statusCode HTTP status code (0 if request failed)
     * @param elapsedMs request time in milliseconds
     * @param success true if request was successful
     */
    public void addLogEntry(String method, String url, int statusCode, long elapsedMs, boolean success) {
        // Trim old entries if needed
        while (tableModel.getRowCount() >= MAX_LOG_ENTRIES) {
            tableModel.removeRow(0);
        }

        // Add new entry
        String time = dateFormat.format(new Date());
        String result = success ? "Success" : "Failed";

        Object[] row = {time, method, url, statusCode, (int) elapsedMs, result};
        tableModel.addRow(row);

        // Update count
        countLabel.setText("Entries: " + tableModel.getRowCount());

        // Auto-scroll to bottom
        if (autoScrollCheckbox.isSelected()) {
            SwingUtilities.invokeLater(() -> {
                int lastRow = logTable.getRowCount() - 1;
                if (lastRow >= 0) {
                    logTable.scrollRectToVisible(logTable.getCellRect(lastRow, 0, true));
                }
            });
        }
    }

    /**
     * Clears all log entries.
     */
    public void clearLog() {
        tableModel.setRowCount(0);
        countLabel.setText("Entries: 0");
    }

    /**
     * Exports the log to a file.
     */
    private void exportLog() {
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "No log entries to export", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Log");
        chooser.setSelectedFile(new java.io.File("tls_bypass_log.csv"));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (java.io.PrintWriter writer = new java.io.PrintWriter(chooser.getSelectedFile())) {
                // Write header
                writer.println("Time,Method,URL,Status,Time(ms),Result");

                // Write data
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    StringBuilder line = new StringBuilder();
                    for (int j = 0; j < tableModel.getColumnCount(); j++) {
                        if (j > 0) line.append(",");
                        Object value = tableModel.getValueAt(i, j);
                        String str = value != null ? value.toString() : "";
                        // Escape CSV special characters
                        if (str.contains(",") || str.contains("\"") || str.contains("\n")) {
                            str = "\"" + str.replace("\"", "\"\"") + "\"";
                        }
                        line.append(str);
                    }
                    writer.println(line);
                }

                JOptionPane.showMessageDialog(this,
                    "Log exported successfully to:\n" + chooser.getSelectedFile().getAbsolutePath(),
                    "Export", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "Failed to export log: " + e.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Custom cell renderer for status code column.
     */
    private static class StatusCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && value instanceof Integer) {
                int status = (Integer) value;
                if (status == 0) {
                    c.setForeground(Color.RED);
                } else if (status >= 200 && status < 300) {
                    c.setForeground(new Color(0, 128, 0));
                } else if (status >= 300 && status < 400) {
                    c.setForeground(Color.BLUE);
                } else if (status >= 400 && status < 500) {
                    c.setForeground(Color.ORANGE);
                } else if (status >= 500) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(table.getForeground());
                }
            }

            setHorizontalAlignment(SwingConstants.CENTER);
            return c;
        }
    }

    /**
     * Custom cell renderer for result column.
     */
    private static class ResultCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && value != null) {
                String result = value.toString();
                if ("Success".equals(result)) {
                    c.setForeground(new Color(0, 128, 0));
                } else if ("Failed".equals(result)) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(table.getForeground());
                }
            }

            setHorizontalAlignment(SwingConstants.CENTER);
            return c;
        }
    }
}
