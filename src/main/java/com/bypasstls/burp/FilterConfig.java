/*
 * TLS Fingerprint Bypass - Burp Suite Extension
 * Copyright (c) 2024 TLS Bypass Project
 * Licensed under the MIT License
 */
package com.bypasstls.burp;

import burp.api.montoya.persistence.PersistedObject;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Manages filter configuration for determining which requests should be
 * processed through the TLS bypass mechanism.
 * <p>
 * Supports three filtering modes:
 * <ul>
 *   <li>ALL_REQUESTS - All HTTP/HTTPS requests are bypassed</li>
 *   <li>SPECIFIC_DOMAINS - Only requests to specified domains are bypassed</li>
 *   <li>SPECIFIC_URIS - Only requests matching URI patterns (regex) are bypassed</li>
 * </ul>
 * </p>
 * <p>
 * Thread-safe implementation using concurrent collections.
 * </p>
 */
public class FilterConfig {

    /**
     * Filter mode enumeration
     */
    public enum FilterMode {
        /** Apply TLS bypass to all requests */
        ALL_REQUESTS("All Requests"),
        /** Apply TLS bypass only to specific domains */
        SPECIFIC_DOMAINS("Specific Domains"),
        /** Apply TLS bypass only to requests matching URI patterns */
        SPECIFIC_URIS("Specific URI Patterns (Regex)");

        private final String displayName;

        FilterMode(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }

    private volatile FilterMode mode = FilterMode.ALL_REQUESTS;
    private final Set<String> domains = new CopyOnWriteArraySet<>();
    private final List<Pattern> uriPatterns = new CopyOnWriteArrayList<>();
    private final List<String> uriPatternStrings = new CopyOnWriteArrayList<>();

    /**
     * Sets the filter mode.
     *
     * @param mode the filter mode to set
     */
    public void setMode(FilterMode mode) {
        this.mode = mode;
    }

    /**
     * Gets the current filter mode.
     *
     * @return the current filter mode
     */
    public FilterMode getMode() {
        return mode;
    }

    /**
     * Adds a domain to the filter list.
     * Domain comparison is case-insensitive.
     *
     * @param domain the domain to add (e.g., "example.com")
     */
    public void addDomain(String domain) {
        if (domain != null && !domain.trim().isEmpty()) {
            domains.add(domain.toLowerCase().trim());
        }
    }

    /**
     * Removes a domain from the filter list.
     *
     * @param domain the domain to remove
     */
    public void removeDomain(String domain) {
        if (domain != null) {
            domains.remove(domain.toLowerCase().trim());
        }
    }

    /**
     * Gets all configured domains.
     *
     * @return unmodifiable set of domains
     */
    public Set<String> getDomains() {
        return Collections.unmodifiableSet(new HashSet<>(domains));
    }

    /**
     * Clears all domains from the filter list.
     */
    public void clearDomains() {
        domains.clear();
    }

    /**
     * Adds a URI pattern (regex) to the filter list.
     *
     * @param pattern the regex pattern to add
     * @throws IllegalArgumentException if the pattern is invalid
     */
    public void addUriPattern(String pattern) throws IllegalArgumentException {
        if (pattern == null || pattern.trim().isEmpty()) {
            throw new IllegalArgumentException("Pattern cannot be empty");
        }

        try {
            Pattern compiled = Pattern.compile(pattern.trim(), Pattern.CASE_INSENSITIVE);
            uriPatterns.add(compiled);
            uriPatternStrings.add(pattern.trim());
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regex pattern: " + e.getMessage());
        }
    }

    /**
     * Removes a URI pattern from the filter list.
     *
     * @param pattern the pattern string to remove
     */
    public void removeUriPattern(String pattern) {
        int index = uriPatternStrings.indexOf(pattern);
        if (index >= 0) {
            uriPatternStrings.remove(index);
            if (index < uriPatterns.size()) {
                uriPatterns.remove(index);
            }
        }
    }

    /**
     * Gets all URI pattern strings.
     *
     * @return unmodifiable list of pattern strings
     */
    public List<String> getUriPatterns() {
        return Collections.unmodifiableList(new ArrayList<>(uriPatternStrings));
    }

    /**
     * Clears all URI patterns from the filter list.
     */
    public void clearUriPatterns() {
        uriPatterns.clear();
        uriPatternStrings.clear();
    }

    /**
     * Determines whether a request should be bypassed based on the current filter configuration.
     *
     * @param host the request host (e.g., "example.com")
     * @param path the request path (e.g., "/api/v1/users")
     * @return true if the request should be processed through TLS bypass, false otherwise
     */
    public boolean shouldBypass(String host, String path) {
        switch (mode) {
            case ALL_REQUESTS:
                return true;

            case SPECIFIC_DOMAINS:
                if (host == null) {
                    return false;
                }
                String normalizedHost = host.toLowerCase().trim();
                // Check exact match
                if (domains.contains(normalizedHost)) {
                    return true;
                }
                // Check wildcard subdomain match (e.g., "example.com" matches "api.example.com")
                for (String domain : domains) {
                    if (normalizedHost.endsWith("." + domain)) {
                        return true;
                    }
                }
                return false;

            case SPECIFIC_URIS:
                if (host == null || path == null) {
                    return false;
                }
                String fullUri = host + path;
                for (Pattern pattern : uriPatterns) {
                    if (pattern.matcher(fullUri).find()) {
                        return true;
                    }
                }
                return false;

            default:
                return false;
        }
    }

    /**
     * Gets a human-readable summary of the current filter configuration.
     *
     * @return configuration summary string
     */
    public String getConfigSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Filter Mode: ").append(mode.getDisplayName()).append("\n");

        switch (mode) {
            case SPECIFIC_DOMAINS:
                sb.append("Domains (").append(domains.size()).append("): ");
                sb.append(String.join(", ", domains));
                break;
            case SPECIFIC_URIS:
                sb.append("URI Patterns (").append(uriPatternStrings.size()).append("): ");
                sb.append(String.join(", ", uriPatternStrings));
                break;
            default:
                sb.append("All requests will be processed");
        }

        return sb.toString();
    }

    /**
     * Validates a regex pattern without adding it.
     *
     * @param pattern the pattern to validate
     * @return null if valid, error message if invalid
     */
    public static String validatePattern(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            return "Pattern cannot be empty";
        }
        try {
            Pattern.compile(pattern.trim());
            return null;
        } catch (PatternSyntaxException e) {
            return "Invalid regex: " + e.getMessage();
        }
    }

    // Persistence keys
    private static final String KEY_FILTER_MODE = "filterMode";
    private static final String KEY_DOMAINS = "filterDomains";
    private static final String KEY_URI_PATTERNS = "filterUriPatterns";

    /**
     * Saves the current filter configuration to persistence.
     *
     * @param persistence the Burp persistence object
     */
    public void saveToPersistence(PersistedObject persistence) {
        if (persistence == null) return;

        // Save filter mode
        persistence.setString(KEY_FILTER_MODE, mode.name());

        // Save domains as comma-separated string
        persistence.setString(KEY_DOMAINS, String.join(",", domains));

        // Save URI patterns as comma-separated string (using | as delimiter since , might be in patterns)
        persistence.setString(KEY_URI_PATTERNS, String.join("|", uriPatternStrings));
    }

    /**
     * Loads filter configuration from persistence.
     *
     * @param persistence the Burp persistence object
     */
    public void loadFromPersistence(PersistedObject persistence) {
        if (persistence == null) return;

        // Load filter mode
        String modeStr = persistence.getString(KEY_FILTER_MODE);
        if (modeStr != null && !modeStr.isEmpty()) {
            try {
                this.mode = FilterMode.valueOf(modeStr);
            } catch (IllegalArgumentException e) {
                this.mode = FilterMode.ALL_REQUESTS;
            }
        }

        // Load domains
        String domainsStr = persistence.getString(KEY_DOMAINS);
        if (domainsStr != null && !domainsStr.isEmpty()) {
            domains.clear();
            for (String domain : domainsStr.split(",")) {
                if (!domain.trim().isEmpty()) {
                    domains.add(domain.trim().toLowerCase());
                }
            }
        }

        // Load URI patterns
        String patternsStr = persistence.getString(KEY_URI_PATTERNS);
        if (patternsStr != null && !patternsStr.isEmpty()) {
            uriPatterns.clear();
            uriPatternStrings.clear();
            for (String pattern : patternsStr.split("\\|")) {
                if (!pattern.trim().isEmpty()) {
                    try {
                        Pattern compiled = Pattern.compile(pattern.trim(), Pattern.CASE_INSENSITIVE);
                        uriPatterns.add(compiled);
                        uriPatternStrings.add(pattern.trim());
                    } catch (PatternSyntaxException e) {
                        // Skip invalid patterns
                    }
                }
            }
        }
    }
}
