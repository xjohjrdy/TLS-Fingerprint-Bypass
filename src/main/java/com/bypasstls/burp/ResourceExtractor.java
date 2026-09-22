/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import com.bypasstls.burp.Logging;

import java.io.*;
import java.nio.file.*;
import java.util.stream.Stream;

/**
 * Extracts embedded Python resources from the JAR to the filesystem.
 * <p>
 * This class handles extracting the worker.py and requirements.txt files
 * that are bundled inside the JAR, making the extension self-contained
 * and easier to distribute via BApp Store.
 * </p>
 */
public class ResourceExtractor {

    private static final String PYTHON_RESOURCE_PATH = "/python/";
    private static final String[] PYTHON_FILES = {"worker.py", "requirements.txt"};

    private final Logging logging;
    private Path extractionDir;

    /**
     * Creates a new ResourceExtractor.
     *
     * @param logging the logging interface
     */
    public ResourceExtractor(Logging logging) {
        this.logging = logging;
    }

    /**
     * Gets the default extraction directory for Python files.
     * Uses user home directory to ensure write permissions.
     *
     * @return the extraction directory path
     */
    public Path getExtractionDirectory() {
        if (extractionDir != null) {
            return extractionDir;
        }

        String userHome = System.getProperty("user.home");
        String os = System.getProperty("os.name").toLowerCase();

        Path baseDir;
        if (os.contains("win")) {
            // Windows: %APPDATA%\tls-bypass-burp
            String appData = System.getenv("APPDATA");
            if (appData != null) {
                baseDir = Paths.get(appData, "tls-bypass-burp");
            } else {
                baseDir = Paths.get(userHome, ".tls-bypass-burp");
            }
        } else if (os.contains("mac")) {
            // macOS: ~/Library/Application Support/tls-bypass-burp
            baseDir = Paths.get(userHome, "Library", "Application Support", "tls-bypass-burp");
        } else {
            // Linux/Unix: ~/.local/share/tls-bypass-burp
            baseDir = Paths.get(userHome, ".local", "share", "tls-bypass-burp");
        }

        extractionDir = baseDir.resolve("python");
        return extractionDir;
    }

    /**
     * Extracts all Python resources from the JAR to the filesystem.
     *
     * @return the path to the extracted worker.py, or null if extraction failed
     */
    public String extractResources() {
        Path targetDir = getExtractionDirectory();

        try {
            // Create directory if it doesn't exist
            Files.createDirectories(targetDir);
            logging.logToOutput("[ResourceExtractor] Extraction directory: " + targetDir);

            // Extract each Python file
            for (String filename : PYTHON_FILES) {
                extractResource(PYTHON_RESOURCE_PATH + filename, targetDir.resolve(filename));
            }

            Path workerPath = targetDir.resolve("worker.py");
            if (Files.exists(workerPath)) {
                logging.logToOutput("[ResourceExtractor] Successfully extracted Python files");
                return workerPath.toString();
            } else {
                logging.logToError("[ResourceExtractor] worker.py not found after extraction");
                return null;
            }

        } catch (IOException e) {
            logging.logToError("[ResourceExtractor] Failed to extract resources: " + e.getMessage());
            return null;
        }
    }

    /**
     * Extracts a single resource from the JAR.
     *
     * @param resourcePath the path to the resource inside the JAR
     * @param targetPath the path to write the resource to
     * @throws IOException if extraction fails
     */
    private void extractResource(String resourcePath, Path targetPath) throws IOException {
        try (InputStream in = getClass().getResourceAsStream(resourcePath)) {
            if (in == null) {
                logging.logToError("[ResourceExtractor] Resource not found: " + resourcePath);
                return;
            }

            // Always overwrite to ensure latest version
            Files.copy(in, targetPath, StandardCopyOption.REPLACE_EXISTING);
            logging.logToOutput("[ResourceExtractor] Extracted: " + targetPath.getFileName());
        }
    }

    /**
     * Checks if Python resources have already been extracted.
     *
     * @return true if worker.py exists in the extraction directory
     */
    public boolean isExtracted() {
        Path workerPath = getExtractionDirectory().resolve("worker.py");
        return Files.exists(workerPath);
    }

    /**
     * Gets the path to the extracted worker.py.
     *
     * @return the path to worker.py, or null if not extracted
     */
    public String getWorkerScriptPath() {
        Path workerPath = getExtractionDirectory().resolve("worker.py");
        if (Files.exists(workerPath)) {
            return workerPath.toString();
        }
        return null;
    }

    /**
     * Cleans up extracted resources.
     *
     * @return true if cleanup was successful
     */
    public boolean cleanup() {
        try {
            Path targetDir = getExtractionDirectory();
            if (Files.exists(targetDir)) {
                // Delete files in directory
                try (Stream<Path> stream = Files.list(targetDir)) {
                    stream.forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException e) {
                            logging.logToError("[ResourceExtractor] Failed to delete: " + path);
                        }
                    });
                }
                // Delete directory
                Files.deleteIfExists(targetDir);
                logging.logToOutput("[ResourceExtractor] Cleanup completed");
            }
            return true;
        } catch (IOException e) {
            logging.logToError("[ResourceExtractor] Cleanup failed: " + e.getMessage());
            return false;
        }
    }
}
