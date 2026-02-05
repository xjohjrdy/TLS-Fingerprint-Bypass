/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.api.montoya.logging.Logging;

import java.io.*;
import java.nio.file.*;
import java.util.concurrent.*;

/**
 * Manages the lifecycle of the Python worker process.
 * <p>
 * Handles starting, stopping, and monitoring the Python FastAPI server
 * that performs TLS fingerprint impersonation using curl_cffi.
 * </p>
 */
public class ProcessManager {

    private final Logging logging;
    private Process pythonProcess;
    private ExecutorService outputReader;
    private volatile boolean running = false;
    private volatile boolean stopRequested = false;

    // Process info
    private String currentPythonPath;
    private String currentScriptPath;
    private int currentPort;

    /**
     * Creates a new ProcessManager instance.
     *
     * @param logging the Burp logging interface for output
     */
    public ProcessManager(Logging logging) {
        this.logging = logging;
        this.outputReader = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "PythonOutputReader");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Starts the Python worker server.
     *
     * @param pythonPath path to the Python executable
     * @param scriptPath path to the worker.py script
     * @param port the port to run the server on
     * @return true if the server started successfully, false otherwise
     */
    public synchronized boolean startPythonServer(String pythonPath, String scriptPath, int port) {
        if (running) {
            logging.logToOutput("[ProcessManager] Python server already running");
            return true;
        }

        stopRequested = false;

        // Validate Python executable
        Path pythonFile = Paths.get(pythonPath);
        if (!Files.exists(pythonFile)) {
            logging.logToError("[ProcessManager] Python executable not found: " + pythonPath);
            return false;
        }

        // Validate script path
        Path scriptFile = Paths.get(scriptPath);
        if (!Files.exists(scriptFile)) {
            logging.logToError("[ProcessManager] Worker script not found: " + scriptPath);
            return false;
        }

        try {
            // Build command
            ProcessBuilder pb = new ProcessBuilder(
                pythonPath,
                scriptPath,
                "--host", "127.0.0.1",
                "--port", String.valueOf(port)
            );

            // Set working directory to script location
            pb.directory(scriptFile.getParent().toFile());
            pb.redirectErrorStream(false);

            // Environment setup
            pb.environment().put("PYTHONUNBUFFERED", "1");

            logging.logToOutput("[ProcessManager] Starting Python worker...");
            logging.logToOutput("[ProcessManager] Command: " + String.join(" ", pb.command()));

            pythonProcess = pb.start();
            running = true;

            // Store current configuration
            currentPythonPath = pythonPath;
            currentScriptPath = scriptPath;
            currentPort = port;

            // Start output readers
            startOutputReaders();

            // Wait for server to start (check if process is still alive after short delay)
            Thread.sleep(2000);

            if (!pythonProcess.isAlive()) {
                int exitCode = pythonProcess.exitValue();
                running = false;
                logging.logToError("[ProcessManager] Python server failed to start (exit code: " + exitCode + ")");
                logging.logToError("[ProcessManager] Check if curl_cffi and FastAPI are installed:");
                logging.logToError("[ProcessManager]   pip install -r requirements.txt");
                return false;
            }

            logging.logToOutput("[ProcessManager] Python server started on port " + port);
            return true;

        } catch (IOException e) {
            logging.logToError("[ProcessManager] Failed to start Python server: " + e.getMessage());
            running = false;
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logging.logToError("[ProcessManager] Interrupted while starting server");
            running = false;
            return false;
        }
    }

    /**
     * Starts threads to capture stdout and stderr from the Python process.
     */
    private void startOutputReaders() {
        // Read stdout
        outputReader.submit(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(pythonProcess.getInputStream()))) {
                String line;
                while (!stopRequested && (line = reader.readLine()) != null) {
                    logging.logToOutput("[Python] " + line);
                }
            } catch (IOException e) {
                if (!stopRequested) {
                    logging.logToError("[ProcessManager] Error reading Python stdout: " + e.getMessage());
                }
            }
        });

        // Read stderr
        outputReader.submit(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(pythonProcess.getErrorStream()))) {
                String line;
                while (!stopRequested && (line = reader.readLine()) != null) {
                    // uvicorn logs to stderr by default, so not all stderr is errors
                    if (line.contains("ERROR") || line.contains("Exception") || line.contains("Traceback")) {
                        logging.logToError("[Python] " + line);
                    } else {
                        logging.logToOutput("[Python] " + line);
                    }
                }
            } catch (IOException e) {
                if (!stopRequested) {
                    logging.logToError("[ProcessManager] Error reading Python stderr: " + e.getMessage());
                }
            }
        });
    }

    /**
     * Stops the Python worker server.
     */
    public synchronized void stopPythonServer() {
        stopRequested = true;
        running = false;

        if (pythonProcess != null && pythonProcess.isAlive()) {
            logging.logToOutput("[ProcessManager] Stopping Python server...");

            // Try graceful shutdown first
            pythonProcess.destroy();

            try {
                // Wait for graceful shutdown
                if (!pythonProcess.waitFor(5, TimeUnit.SECONDS)) {
                    // Force kill if not stopped
                    logging.logToOutput("[ProcessManager] Force killing Python process...");
                    pythonProcess.destroyForcibly();
                    pythonProcess.waitFor(2, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                pythonProcess.destroyForcibly();
            }

            logging.logToOutput("[ProcessManager] Python server stopped");
        }

        pythonProcess = null;
    }

    /**
     * Restarts the Python worker server with the same configuration.
     *
     * @return true if restart was successful, false otherwise
     */
    public synchronized boolean restartPythonServer() {
        if (currentPythonPath == null || currentScriptPath == null) {
            logging.logToError("[ProcessManager] Cannot restart: no previous configuration");
            return false;
        }

        stopPythonServer();

        // Brief pause before restart
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return startPythonServer(currentPythonPath, currentScriptPath, currentPort);
    }

    /**
     * Checks if the Python server is currently running.
     *
     * @return true if running, false otherwise
     */
    public boolean isRunning() {
        return running && pythonProcess != null && pythonProcess.isAlive();
    }

    /**
     * Gets the current server port.
     *
     * @return the port number, or -1 if not running
     */
    public int getCurrentPort() {
        return running ? currentPort : -1;
    }

    /**
     * Validates that Python and required dependencies are installed.
     *
     * @param pythonPath path to Python executable
     * @return error message if validation fails, null if successful
     */
    public String validatePythonEnvironment(String pythonPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                pythonPath, "-c",
                "import fastapi; import uvicorn; import curl_cffi; print('OK')"
            );
            pb.redirectErrorStream(true);

            Process process = pb.start();
            StringBuilder output = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            boolean finished = process.waitFor(10, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return "Python validation timed out";
            }

            if (process.exitValue() != 0 || !output.toString().contains("OK")) {
                return "Required packages not installed. Run:\npip install fastapi uvicorn curl-cffi";
            }

            return null; // Success

        } catch (IOException e) {
            return "Cannot execute Python: " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Validation interrupted";
        }
    }

    /**
     * Result class for setup operations.
     */
    public static class SetupResult {
        public final boolean success;
        public final String message;
        public final String venvPythonPath;

        public SetupResult(boolean success, String message, String venvPythonPath) {
            this.success = success;
            this.message = message;
            this.venvPythonPath = venvPythonPath;
        }
    }

    /**
     * Creates a virtual environment and installs required dependencies.
     * This method will create a venv in the same directory as the worker script
     * and install all required packages.
     *
     * @param systemPythonPath path to the system Python executable
     * @param scriptPath path to the worker.py script (used to determine venv location)
     * @param progressCallback callback for progress updates (can be null)
     * @return SetupResult containing success status, message, and venv Python path
     */
    public SetupResult setupVirtualEnvironment(String systemPythonPath, String scriptPath,
                                                java.util.function.Consumer<String> progressCallback) {
        Path scriptDir = Paths.get(scriptPath).getParent();
        Path venvPath = scriptDir.resolve(".venv");
        Path requirementsPath = scriptDir.resolve("requirements.txt");

        // Determine venv Python path based on OS
        String os = System.getProperty("os.name").toLowerCase();
        Path venvPython;
        if (os.contains("win")) {
            venvPython = venvPath.resolve("Scripts").resolve("python.exe");
        } else {
            venvPython = venvPath.resolve("bin").resolve("python");
        }

        try {
            // Step 1: Check if venv already exists and is valid
            if (Files.exists(venvPython)) {
                log(progressCallback, "Checking existing virtual environment...");
                String validation = validatePythonEnvironment(venvPython.toString());
                if (validation == null) {
                    log(progressCallback, "Existing virtual environment is valid.");
                    return new SetupResult(true, "Virtual environment already set up.", venvPython.toString());
                }
                log(progressCallback, "Existing venv missing packages, will reinstall...");
            }

            // Step 2: Check if system Python exists
            if (!Files.exists(Paths.get(systemPythonPath))) {
                return new SetupResult(false, "Python executable not found: " + systemPythonPath, null);
            }

            // Step 3: Create virtual environment
            log(progressCallback, "Creating virtual environment at: " + venvPath);
            logging.logToOutput("[ProcessManager] Creating venv: " + venvPath);

            ProcessBuilder createVenv = new ProcessBuilder(
                systemPythonPath, "-m", "venv", venvPath.toString()
            );
            createVenv.redirectErrorStream(true);
            Process venvProcess = createVenv.start();

            String venvOutput = captureProcessOutput(venvProcess);
            boolean venvFinished = venvProcess.waitFor(60, TimeUnit.SECONDS);

            if (!venvFinished) {
                venvProcess.destroyForcibly();
                return new SetupResult(false, "Virtual environment creation timed out", null);
            }

            if (venvProcess.exitValue() != 0) {
                return new SetupResult(false, "Failed to create virtual environment:\n" + venvOutput, null);
            }

            log(progressCallback, "Virtual environment created successfully.");

            // Step 4: Upgrade pip
            log(progressCallback, "Upgrading pip...");
            logging.logToOutput("[ProcessManager] Upgrading pip in venv...");

            ProcessBuilder upgradePip = new ProcessBuilder(
                venvPython.toString(), "-m", "pip", "install", "--upgrade", "pip"
            );
            upgradePip.redirectErrorStream(true);
            Process pipUpgradeProcess = upgradePip.start();

            captureProcessOutput(pipUpgradeProcess);
            pipUpgradeProcess.waitFor(120, TimeUnit.SECONDS);

            // Step 5: Install requirements
            log(progressCallback, "Installing required packages (this may take a few minutes)...");
            logging.logToOutput("[ProcessManager] Installing requirements...");

            ProcessBuilder installReqs;
            if (Files.exists(requirementsPath)) {
                log(progressCallback, "Installing from requirements.txt...");
                installReqs = new ProcessBuilder(
                    venvPython.toString(), "-m", "pip", "install", "-r", requirementsPath.toString()
                );
            } else {
                log(progressCallback, "Installing packages directly...");
                installReqs = new ProcessBuilder(
                    venvPython.toString(), "-m", "pip", "install",
                    "fastapi>=0.109.0",
                    "uvicorn[standard]>=0.27.0",
                    "curl-cffi>=0.7.0",
                    "pydantic>=2.0.0"
                );
            }
            installReqs.redirectErrorStream(true);
            installReqs.directory(scriptDir.toFile());

            Process installProcess = installReqs.start();

            // Stream output for progress
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(installProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    logging.logToOutput("[pip] " + line);
                    if (line.contains("Installing") || line.contains("Successfully") ||
                        line.contains("Downloading") || line.contains("Building")) {
                        log(progressCallback, line);
                    }
                }
            }

            boolean installFinished = installProcess.waitFor(300, TimeUnit.SECONDS);

            if (!installFinished) {
                installProcess.destroyForcibly();
                return new SetupResult(false, "Package installation timed out", null);
            }

            if (installProcess.exitValue() != 0) {
                return new SetupResult(false, "Failed to install required packages", null);
            }

            log(progressCallback, "Packages installed successfully.");

            // Step 6: Validate installation
            log(progressCallback, "Validating installation...");
            String validation = validatePythonEnvironment(venvPython.toString());

            if (validation != null) {
                return new SetupResult(false, "Installation validation failed:\n" + validation, null);
            }

            log(progressCallback, "Setup completed successfully!");
            logging.logToOutput("[ProcessManager] Virtual environment setup complete: " + venvPython);

            return new SetupResult(true,
                "Virtual environment created and packages installed successfully.\n" +
                "Python path: " + venvPython,
                venvPython.toString());

        } catch (IOException e) {
            logging.logToError("[ProcessManager] Setup error: " + e.getMessage());
            return new SetupResult(false, "Setup error: " + e.getMessage(), null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new SetupResult(false, "Setup was interrupted", null);
        }
    }

    /**
     * Checks if a virtual environment exists for the given script path.
     *
     * @param scriptPath path to the worker.py script
     * @return path to venv Python if exists and valid, null otherwise
     */
    public String getExistingVenvPython(String scriptPath) {
        if (scriptPath == null || scriptPath.isEmpty()) {
            return null;
        }

        Path scriptDir = Paths.get(scriptPath).getParent();
        if (scriptDir == null) {
            return null;
        }

        Path venvPath = scriptDir.resolve(".venv");
        String os = System.getProperty("os.name").toLowerCase();
        Path venvPython;

        if (os.contains("win")) {
            venvPython = venvPath.resolve("Scripts").resolve("python.exe");
        } else {
            venvPython = venvPath.resolve("bin").resolve("python");
        }

        if (Files.exists(venvPython)) {
            // Validate the venv has required packages
            String validation = validatePythonEnvironment(venvPython.toString());
            if (validation == null) {
                return venvPython.toString();
            }
        }

        return null;
    }

    /**
     * Helper method to log progress.
     */
    private void log(java.util.function.Consumer<String> callback, String message) {
        logging.logToOutput("[ProcessManager] " + message);
        if (callback != null) {
            callback.accept(message);
        }
    }

    /**
     * Helper method to capture process output.
     */
    private String captureProcessOutput(Process process) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return output.toString();
    }

    /**
     * Shuts down the output reader executor service.
     */
    public void shutdown() {
        stopPythonServer();
        outputReader.shutdownNow();
    }
}
