/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package burp;

/**
 * Legacy Extender API entry point.
 * <p>
 * The legacy Burp API discovers the extension by reflection: the class MUST be
 * named {@code BurpExtender}, MUST live in the {@code burp} package, and MUST
 * have a public no-argument constructor. This is why this thin shim exists in a
 * separate package from the rest of the extension.
 * </p>
 * <p>
 * All real work is delegated to {@link com.bypasstls.burp.BurpExtension}.
 * </p>
 */
public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        new com.bypasstls.burp.BurpExtension().initialize(callbacks);
    }
}
