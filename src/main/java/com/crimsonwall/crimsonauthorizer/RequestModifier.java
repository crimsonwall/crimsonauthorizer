/*
 * Crimson Authorizer - Automated Authorization Testing for OWASP ZAP.
 *
 * Renico Koen / crimsonwall.com / 2026.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.crimsonwall.crimsonauthorizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;

/** Creates modified copies of HTTP messages with substituted credentials and applied rules. */
public class RequestModifier {

    private static final Logger LOGGER = LogManager.getLogger(RequestModifier.class);

    private static final List<String> DEFAULT_AUTH_HEADERS =
            Arrays.asList(
                    "Cookie", "Authorization", "If-None-Match",
                    "If-Modified-Since", "If-Range", "If-Match");

    /**
     * Creates an unauthenticated version of the message by removing authentication-related headers.
     *
     * @param original The original authenticated message.
     * @param headersToStrip Additional exact header names to remove on top of the defaults.
     * @param headerRegexToStrip Regex patterns — any header whose name matches is removed.
     * @param maxMessageSize Maximum message size in bytes (0 for no limit).
     * @return A cloned message with auth headers removed, or null if message is too large.
     */
    public static HttpMessage createUnauthenticatedRequest(
            HttpMessage original, List<String> headersToStrip, List<String> headerRegexToStrip,
            int maxMessageSize) {
        try {
            if (maxMessageSize > 0) {
                int msgSize = getMessageSize(original);
                if (msgSize > maxMessageSize) {
                    LOGGER.warn("Message too large ({}), skipping unauthenticated test", formatSize(msgSize));
                    return null;
                }
            }

            HttpMessage clone = cloneMessage(original);
            // Always strip the default auth headers (Cookie, Authorization, etc.) for
            // unauthenticated tests, then add any custom headers on top.
            List<String> combined = new ArrayList<>(DEFAULT_AUTH_HEADERS);
            if (headersToStrip != null) {
                for (String h : headersToStrip) {
                    if (!combined.contains(h)) {
                        combined.add(h);
                    }
                }
            }
            stripAuthHeaders(clone, combined, headerRegexToStrip);
            return clone;
        } catch (Exception e) {
            LOGGER.error("Failed to create unauthenticated request", e);
            return null;
        }
    }

    /** Creates an unauthenticated request with exact header list and no regex stripping. */
    public static HttpMessage createUnauthenticatedRequest(
            HttpMessage original, List<String> headersToStrip, int maxMessageSize) {
        return createUnauthenticatedRequest(original, headersToStrip, null, maxMessageSize);
    }

    /** Creates an unauthenticated request using the default set of auth headers to strip. */
    public static HttpMessage createUnauthenticatedRequest(HttpMessage original, int maxMessageSize) {
        return createUnauthenticatedRequest(original, DEFAULT_AUTH_HEADERS, null, maxMessageSize);
    }

    /**
     * Creates a user-specific version of the message by applying match/replace rules then injecting
     * the user's credential headers.
     *
     * <p>Headers are only injected if they already exist in the original request. This prevents
     * unintended credential leakage to servers that are not in scope. If any of the user's
     * configured headers are not present in the original request, this method returns null and the
     * user should be excluded from testing that specific request.
     *
     * @param original The original authenticated message.
     * @param credentials The user's authentication credentials.
     * @param matchReplaceRules Optional match/replace rules to apply before credential injection.
     * @param headersToStrip Exact header names to remove before injecting credentials.
     * @param headerRegexToStrip Regex patterns — any header whose name matches is removed.
     * @param maxMessageSize Maximum message size in bytes (0 for no limit).
     * @return A cloned message with modified content and injected credentials, or null if any of the
     *     user's headers are not present in the original request or if message is too large.
     */
    public static HttpMessage createUserRequest(
            HttpMessage original,
            AuthCredentials credentials,
            List<MatchReplaceRule> matchReplaceRules,
            List<String> headersToStrip,
            List<String> headerRegexToStrip,
            int maxMessageSize) {

        try {
            if (maxMessageSize > 0) {
                int msgSize = getMessageSize(original);
                if (msgSize > maxMessageSize) {
                    LOGGER.warn("Message too large ({}), skipping user '{}' test",
                            formatSize(msgSize), credentials.getUserName());
                    return null;
                }
            }

            HttpMessage clone = cloneMessage(original);

            stripAuthHeaders(clone, headersToStrip, headerRegexToStrip);

            if (matchReplaceRules != null) {
                applyMatchReplaceRules(clone, matchReplaceRules);
            }

            // Check if all user headers exist in the original request before injecting.
            // This prevents sending credentials to servers that didn't receive them originally.
            for (AuthCredentials.HeaderEntry header : credentials.getHeaders()) {
                String headerName = header.getName();
                if (original.getRequestHeader().getHeader(headerName) == null) {
                    LOGGER.debug(
                            "Skipping user '{}': header '{}' not found in original request for {}",
                            credentials.getUserName(),
                            headerName,
                            original.getRequestHeader().getURI());
                    return null;
                }
            }

            // All headers present - inject them
            for (AuthCredentials.HeaderEntry header : credentials.getHeaders()) {
                clone.getRequestHeader().setHeader(header.getName(), header.getValue());
            }

            return clone;
        } catch (Exception e) {
            LOGGER.error("Failed to create user request for {}", credentials.getUserName(), e);
            return null;
        }
    }

    /** Creates a user request with exact header list and no regex stripping. */
    public static HttpMessage createUserRequest(
            HttpMessage original,
            AuthCredentials credentials,
            List<MatchReplaceRule> matchReplaceRules,
            List<String> headersToStrip,
            int maxMessageSize) {
        return createUserRequest(original, credentials, matchReplaceRules, headersToStrip, null, maxMessageSize);
    }

    /** Creates a user request using the default set of auth headers to strip. */
    public static HttpMessage createUserRequest(
            HttpMessage original,
            AuthCredentials credentials,
            List<MatchReplaceRule> matchReplaceRules,
            int maxMessageSize) {
        return createUserRequest(original, credentials, matchReplaceRules, DEFAULT_AUTH_HEADERS, null, maxMessageSize);
    }

    /** Deep-clones an HttpMessage so modifications don't affect the original. */
    public static HttpMessage cloneMessage(HttpMessage original) throws Exception {
        HttpMessage clone = new HttpMessage(original.getRequestHeader().getURI());
        clone.getRequestHeader().setMethod(original.getRequestHeader().getMethod());
        clone.getRequestHeader().setVersion(original.getRequestHeader().getVersion());

        // Copy all headers using setHeader to replace defaults (including User-Agent)
        String headersStr = original.getRequestHeader().getHeadersAsString();
        String[] headerLines = headersStr.split("\r\n");
        for (String line : headerLines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String value = line.substring(colonIdx + 1).trim();
                // Use setHeader instead of addHeader to replace defaults
                clone.getRequestHeader().setHeader(name, value);
            }
        }

        // Copy body
        byte[] body = original.getRequestBody().getBytes();
        if (body != null && body.length > 0) {
            clone.getRequestBody().setBody(body);
            clone.getRequestHeader().setContentLength(body.length);
        }

        return clone;
    }

    private static final java.util.Map<String, Pattern> regexCache = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Removes the specified headers from the message, by exact name and/or regex pattern.
     *
     * <p>Header names are matched case-insensitively. Removal is performed using the header's
     * actual stored name (not the canonical form from the strip list) so that the call to
     * {@code setHeader(name, null)} always finds an exact match — avoiding any case-sensitivity
     * issue in ZAP's internal header lookup.
     */
    private static void stripAuthHeaders(
            HttpMessage msg, List<String> headersToStrip, List<String> headerRegexToStrip) {

        List<String> exact =
                (headersToStrip != null && !headersToStrip.isEmpty())
                        ? headersToStrip
                        : DEFAULT_AUTH_HEADERS;

        // Build a lowercase set for O(1) case-insensitive lookup
        Set<String> stripLower = new HashSet<>();
        for (String h : exact) {
            stripLower.add(h.toLowerCase(Locale.ROOT));
        }

        // Read actual header names as stored, then remove using those exact names.
        // This guarantees setHeader(name, null) finds the entry even if the browser
        // sent the header in a different case than our strip-list (e.g. "authorization"
        // vs "Authorization").
        String headersStr = msg.getRequestHeader().getHeadersAsString();
        for (String line : headersStr.split("\r\n")) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                if (stripLower.contains(name.toLowerCase(Locale.ROOT))) {
                    msg.getRequestHeader().setHeader(name, null);
                }
            }
        }

        if (headerRegexToStrip != null && !headerRegexToStrip.isEmpty()) {
            // Re-read after exact-name removals above
            headersStr = msg.getRequestHeader().getHeadersAsString();
            for (String line : headersStr.split("\r\n")) {
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String name = line.substring(0, colonIdx).trim();
                    for (String regex : headerRegexToStrip) {
                        Pattern p = getCachedPattern(regex);
                        if (p != null && p.matcher(name).matches()) {
                            msg.getRequestHeader().setHeader(name, null);
                            break;
                        }
                    }
                }
            }
        }
    }

    private static Pattern getCachedPattern(String regex) {
        return regexCache.computeIfAbsent(regex, key -> {
            try {
                return Pattern.compile(key, Pattern.CASE_INSENSITIVE);
            } catch (PatternSyntaxException e) {
                return null;
            }
        });
    }

    /** Applies match/replace rules to the message. */
    private static void applyMatchReplaceRules(HttpMessage msg, List<MatchReplaceRule> rules) {
        for (MatchReplaceRule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }
            applySingleRule(msg, rule);
        }
    }

    private static void applySingleRule(HttpMessage msg, MatchReplaceRule rule) {
        switch (rule.getTarget()) {
            case HEADERS_SIMPLE:
                {
                    String headers = msg.getRequestHeader().getHeadersAsString();
                    if (headers.contains(rule.getMatchPattern())) {
                        String newHeaders = headers.replace(rule.getMatchPattern(), rule.getReplacePattern());
                        rebuildHeaders(msg, newHeaders);
                    }
                    break;
                }
            case HEADERS_REGEX:
                {
                    java.util.regex.Pattern p = rule.getCompiledRegex();
                    if (p != null) {
                        String headers = msg.getRequestHeader().getHeadersAsString();
                        Matcher m = p.matcher(headers);
                        if (m.find()) {
                            String newHeaders = m.replaceAll(rule.getReplacePattern());
                            rebuildHeaders(msg, newHeaders);
                        }
                    }
                    break;
                }
            case BODY_SIMPLE:
                {
                    String body = msg.getRequestBody().toString();
                    if (body.contains(rule.getMatchPattern())) {
                        String newBody = body.replace(rule.getMatchPattern(), rule.getReplacePattern());
                        msg.getRequestBody().setBody(newBody);
                        msg.getRequestHeader().setContentLength(newBody.length());
                    }
                    break;
                }
            case BODY_REGEX:
                {
                    java.util.regex.Pattern p = rule.getCompiledRegex();
                    if (p != null) {
                        String body = msg.getRequestBody().toString();
                        Matcher m = p.matcher(body);
                        if (m.find()) {
                            String newBody = m.replaceAll(rule.getReplacePattern());
                            msg.getRequestBody().setBody(newBody);
                            msg.getRequestHeader().setContentLength(newBody.length());
                        }
                    }
                    break;
                }
        }
    }

    /** Rebuilds request headers from a raw header string. */
    private static void rebuildHeaders(HttpMessage msg, String newHeaders) {
        String[] lines = newHeaders.split("\r\n");
        for (String line : lines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String value = line.substring(colonIdx + 1).trim();
                msg.getRequestHeader().setHeader(name, value);
            }
        }
    }

    /**
     * Calculates the total size of an HTTP message (headers + body).
     */
    private static int getMessageSize(HttpMessage msg) {
        int size = 0;
        if (msg.getRequestHeader() != null) {
            size += msg.getRequestHeader().toString().length();
        }
        if (msg.getRequestBody() != null) {
            size += msg.getRequestBody().length();
        }
        if (msg.getResponseHeader() != null) {
            size += msg.getResponseHeader().toString().length();
        }
        if (msg.getResponseBody() != null) {
            size += msg.getResponseBody().length();
        }
        return size;
    }

    /**
     * Formats a byte count as a human-readable string.
     */
    private static String formatSize(int bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }
}
