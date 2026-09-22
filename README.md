# TLS Fingerprint Bypass - Burp Suite Extension

> **One-line summary:** Bypass TLS/JA3 fingerprinting by routing requests through curl_cffi with browser impersonation.

A professional Burp Suite extension that bypasses TLS fingerprinting detection using `curl_cffi` for browser impersonation.

## Features

- **TLS Fingerprint Bypass**: Routes HTTP/HTTPS requests through curl_cffi to impersonate real browser TLS fingerprints
- **Multiple Browser Support**: Impersonate Chrome, Firefox, Safari, Edge, and Tor browsers
- **Flexible Filtering**: Apply bypass to all requests, specific domains, or URI patterns (regex)
- **Real-time Logging**: Monitor all bypassed requests with timing information
- **Easy Configuration**: User-friendly GUI integrated into Burp Suite
- **Customizable Highlighting**: Choose highlight colors for bypassed requests in HTTP History, or disable highlighting
- **Settings Persistence**: All settings are automatically saved and restored when Burp Suite restarts
- **Auto Setup**: One-click virtual environment creation and dependency installation
- **Connection Pooling**: Efficient HTTP communication with the Python worker

## Supported Browsers

### Generic (Auto-select Latest)
- `chrome`, `firefox`, `safari`, `chrome_android`, `safari_ios`

### Chrome
- Desktop: `chrome136`, `chrome133a`, `chrome131`, `chrome124`, `chrome123`, `chrome120`, `chrome119`, `chrome116`, `chrome110`, `chrome107`, `chrome104`, `chrome101`, `chrome100`, `chrome99`
- Android: `chrome131_android`, `chrome99_android`

### Safari
- Desktop: `safari260`, `safari184`, `safari180`, `safari170`, `safari155`, `safari153`
- iOS: `safari260_ios`, `safari184_ios`, `safari180_ios`, `safari172_ios`

### Firefox
- `firefox133`

### Edge
- `edge101`, `edge99`

### Tor
- `tor145`

## Requirements

### Java (Burp Extension)
- Java 11 or higher
- Burp Suite Professional/Community with legacy Extender API support (any version exposing
  the `burp.IBurpExtender` API)

### Python (Worker Server)
- Python 3.9 or higher
- Required packages:
  - `fastapi>=0.109.0`
  - `uvicorn[standard]>=0.27.0`
  - `curl-cffi>=0.7.0`
  - `pydantic>=2.0.0`

## Installation

### 1. Install Python Dependencies

```bash
cd python
pip install -r requirements.txt
```

### 2. Build the Extension

```bash
# Using Gradle wrapper (recommended)
./gradlew shadowJar

# Or using installed Gradle
gradle shadowJar
```

The built JAR will be located at `build/libs/tls-bypass-burp-1.0.0.jar`

### 3. Load in Burp Suite

1. Open Burp Suite
2. Go to **Extender** → **Extensions**
3. Click **Add**
4. Select the JAR file from `build/libs/`
5. Click **Next** to load the extension

## Usage

### Configuration

1. Go to the **TLS Fingerprint Bypass** tab in Burp Suite
2. Configure the following settings:
   - **Python Executable**: Path to your Python interpreter
   - **Worker Script**: Path to `python/worker.py`
   - **Server Port**: Port for the local worker server (default: 8787)
   - **Impersonate Browser**: Select which browser to impersonate

### Automatic Setup (Recommended)

If you don't have curl_cffi installed, use the **Auto Setup** feature:

1. Select the **Worker Script** (python/worker.py)
2. Ensure **Python Executable** points to your system Python (e.g., `/usr/bin/python3`)
3. Click **Auto Setup**
4. The extension will automatically:
   - Create a virtual environment (`.venv`) in the python directory
   - Install all required dependencies (FastAPI, uvicorn, curl_cffi)
   - Update the Python path to use the venv

### Starting the Bypass

1. Click **Validate Python** to verify your environment (or use **Auto Setup**)
2. Click **Start Server** to launch the Python worker
3. Check **Enable TLS Bypass** to activate the bypass

### Filter Configuration

Choose one of three filter modes:

- **All Requests**: Apply bypass to every HTTP/HTTPS request
- **Specific Domains**: Only bypass requests to listed domains
- **Specific URI Patterns**: Use regex patterns to match requests

### Settings Persistence

All your configuration settings are automatically saved and will be restored when you restart Burp Suite:

| Setting | Auto-saved |
|---------|------------|
| Python executable path | ✓ |
| Worker script path | ✓ |
| Server port | ✓ |
| Selected browser | ✓ |
| Log requests toggle | ✓ |
| Highlight color | ✓ |
| Filter mode | ✓ |
| Domain/URI pattern list | ✓ |

Settings are stored in Burp's user-level extension settings, so they are shared across projects.

### Highlight Color Customization

Bypassed requests are highlighted in Burp's HTTP History for easy identification. You can customize the highlight color or disable it entirely:

| Color Option | Description |
|--------------|-------------|
| Green | Default highlight color |
| Blue | Blue highlight |
| Cyan | Cyan highlight |
| Yellow | Yellow highlight |
| Orange | Orange highlight |
| Red | Red highlight |
| Pink | Pink highlight |
| Magenta | Magenta highlight |
| Gray | Gray highlight |
| None (No Highlight) | Disable highlighting completely |

The highlight color selection is located next to the "Log Requests" checkbox in the configuration panel.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Burp Suite                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              TLS Bypass Extension                   │    │
│  │  ┌───────────────┐    ┌──────────────────────────┐  │    │
│  │  │ HTTP Handler  │───▶│ Python Worker Client     │  │    │
│  │  │ (Intercept)   │    │ (OkHttp + JSON)          │  │    │
│  │  └───────────────┘    └────────────┬─────────────┘  │    │
│  └────────────────────────────────────┼────────────────┘    │
└───────────────────────────────────────┼─────────────────────┘
                                        │ HTTP (localhost)
                                        ▼
┌─────────────────────────────────────────────────────────────┐
│                 Python Worker (FastAPI)                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    curl_cffi                        │    │
│  │              (TLS Fingerprint Impersonation)        │    │
│  └─────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┼─────────────────────┘
                                        │ HTTPS (Impersonated TLS)
                                        ▼
                               ┌─────────────────┐
                               │  Target Server  │
                               └─────────────────┘
```

## API Endpoints (Python Worker)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/targets` | GET | List supported impersonation targets |
| `/proxy` | POST | Forward request with TLS impersonation |
| `/batch` | POST | Forward multiple requests concurrently |

## Project Structure

```
Bypass_TLS_Detection/
├── build.gradle                     # Gradle build configuration
├── settings.gradle                  # Project settings
├── LICENSE                          # MIT License
├── THIRD_PARTY_LICENSES.md          # Third-party license notices
├── README.md                        # This file
├── CLAUDE.md                        # Development documentation
├── src/main/java/burp/
│   └── BurpExtender.java            # Legacy API entry point (reflection target)
├── src/main/java/com/bypasstls/burp/
│   ├── BurpExtension.java           # Component wiring
│   ├── TLSBypassHttpHandler.java    # HTTP request handler (IHttpListener)
│   ├── PythonWorkerClient.java      # Python worker communication
│   ├── ProcessManager.java          # Python process lifecycle
│   ├── FilterConfig.java            # Filter configuration
│   ├── Logging.java                 # Logging adapter
│   ├── ResourceExtractor.java       # Unpacks bundled Python files
│   └── ui/
│       ├── ConfigTab.java           # Main configuration tab (ITab)
│       ├── FilterPanel.java         # Filter settings panel
│       └── LogPanel.java            # Request log viewer
└── python/
    ├── worker.py                    # FastAPI + curl_cffi server
    └── requirements.txt             # Python dependencies
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/your-repo/tls-bypass-burp.git
cd tls-bypass-burp

# Build with Gradle (requires Java 11+)
./gradlew build

# Create fat JAR with dependencies
./gradlew shadowJar
```

## Troubleshooting

### "Python executable not found"
Ensure Python 3.9+ is installed and provide the full path to the executable.

### "Required packages not installed"
Install dependencies with:
```bash
pip install fastapi uvicorn curl-cffi pydantic
```

### "Connection failed"
- Verify the Python server is running
- Check if the port is not in use by another application
- Review Burp's Extender output for error messages

### "TLS Bypass not working"
- Ensure "Enable TLS Bypass" is checked
- Verify the target matches your filter configuration
- Check the log panel for request status

## Security Considerations

- The Python worker binds to `127.0.0.1` only (localhost)
- Sensitive headers are handled securely
- SSL verification can be enabled/disabled per configuration

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

For third-party license information, see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Acknowledgments

- [curl_cffi](https://github.com/lexiforest/curl_cffi) - Python binding for curl-impersonate (MIT License)
- [Burp Suite Extender API](https://portswigger.net/burp/extender/api/) - PortSwigger's extension API
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework (MIT License)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
