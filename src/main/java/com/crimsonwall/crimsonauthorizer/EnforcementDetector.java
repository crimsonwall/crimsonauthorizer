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

import java.util.List;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Compares an original (high-privilege) response against a test (low-privilege or unauthenticated)
 * response to determine authorization enforcement status.
 */
public class EnforcementDetector {

    /**
     * Detects whether authorization is properly enforced by comparing responses.
     *
     * @param original The response from the authenticated (high-privilege) request.
     * @param test The response from the modified (low-privilege/unauthenticated) request.
     * @param rules Configured enforcement detector rules (may be empty).
     * @param useAndLogic If true, all rules must match for ENFORCED; if false, any rule matching
     *     means ENFORCED.
     * @return The enforcement status.
     */
    public static EnforcementStatus detect(
            HttpMessage original,
            HttpMessage test,
            List<EnforcementDetectorRule> rules,
            boolean useAndLogic) {

        if (original == null || test == null) {
            return EnforcementStatus.UNDETERMINED;
        }

        int origStatus = original.getResponseHeader().getStatusCode();
        int testStatus = test.getResponseHeader().getStatusCode();

        // Special handling for 304 Not Modified - these have no body, rely on status only
        if (origStatus == 304 || testStatus == 304) {
            if (origStatus != testStatus) {
                return EnforcementStatus.ENFORCED;
            }
            // Both are 304 - both could access the resource (both get cached)
            // This typically means bypass - unauthorized user also gets cached response
            return EnforcementStatus.BYPASSED;
        }

        // Different status codes strongly imply the server treated requests differently
        if (origStatus != testStatus) {
            return EnforcementStatus.ENFORCED;
        }

        // Same status code - check detector rules
        if (rules != null && !rules.isEmpty()) {
            boolean rulesEnforced = evaluateRules(test, rules, useAndLogic);
            if (rulesEnforced) {
                return EnforcementStatus.ENFORCED;
            }
        }

        // Fall back to body comparison
        String origBody = original.getResponseBody() != null ? original.getResponseBody().toString() : "";
        String testBody = test.getResponseBody() != null ? test.getResponseBody().toString() : "";

        if (origBody.equals(testBody)) {
            // Same status code and identical body - if the server returned an error,
            // enforcement is likely in place (e.g. both got 403 "Access Denied").
            if (origStatus >= 400) {
                return EnforcementStatus.ENFORCED;
            }
            return EnforcementStatus.BYPASSED;
        }

        return EnforcementStatus.UNDETERMINED;
    }

    /**
     * Evaluates enforcement detector rules against a test response.
     *
     * @return true if the rules indicate enforcement is detected.
     */
    private static boolean evaluateRules(
            HttpMessage test, List<EnforcementDetectorRule> rules, boolean useAndLogic) {

        boolean hasEnabledRules = false;

        for (EnforcementDetectorRule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }
            hasEnabledRules = true;
            boolean matched = evaluateSingleRule(test, rule);

            if (useAndLogic) {
                if (!matched) {
                    return false; // AND: any non-match means not enforced
                }
            } else {
                if (matched) {
                    return true; // OR: any match means enforced
                }
            }
        }

        // AND logic: all matched -> enforced. OR logic: none matched -> not enforced.
        return hasEnabledRules && useAndLogic;
    }

    private static boolean evaluateSingleRule(HttpMessage msg, EnforcementDetectorRule rule) {
        String testContent;
        switch (rule.getType()) {
            case STATUS_CODE_EQUALS:
            case STATUS_CODE_NOT_EQUALS:
                testContent = String.valueOf(msg.getResponseHeader().getStatusCode());
                break;
            case HEADERS_CONTAIN:
            case HEADERS_NOT_CONTAIN:
            case HEADERS_REGEX:
            case HEADERS_NOT_REGEX:
                testContent = msg.getResponseHeader().getHeadersAsString();
                break;
            case BODY_CONTAINS:
            case BODY_NOT_CONTAINS:
            case BODY_REGEX:
            case BODY_NOT_REGEX:
                testContent = msg.getResponseBody() != null ? msg.getResponseBody().toString() : "";
                break;
            case FULL_RESPONSE_CONTAINS:
            case FULL_RESPONSE_NOT_CONTAINS:
            case FULL_RESPONSE_REGEX:
            case FULL_RESPONSE_NOT_REGEX:
                testContent =
                        msg.getResponseHeader().getHeadersAsString()
                                + (msg.getResponseBody() != null ? msg.getResponseBody().toString() : "");
                break;
            case RESPONSE_LENGTH_EQUALS:
            case RESPONSE_LENGTH_NOT_EQUALS:
                testContent =
                        String.valueOf(
                                msg.getResponseBody() != null ? msg.getResponseBody().length() : 0);
                break;
            default:
                return false;
        }

        String pattern = rule.getPattern();

        switch (rule.getType()) {
            case STATUS_CODE_EQUALS:
            case HEADERS_CONTAIN:
            case BODY_CONTAINS:
            case FULL_RESPONSE_CONTAINS:
                return testContent.contains(pattern);
            case STATUS_CODE_NOT_EQUALS:
            case HEADERS_NOT_CONTAIN:
            case BODY_NOT_CONTAINS:
            case FULL_RESPONSE_NOT_CONTAINS:
                return !testContent.contains(pattern);
            case HEADERS_REGEX:
            case BODY_REGEX:
            case FULL_RESPONSE_REGEX:
                {
                    Pattern p = rule.getCompiledRegex();
                    return p != null && p.matcher(testContent).find();
                }
            case HEADERS_NOT_REGEX:
            case BODY_NOT_REGEX:
            case FULL_RESPONSE_NOT_REGEX:
                {
                    Pattern p = rule.getCompiledRegex();
                    return p == null || !p.matcher(testContent).find();
                }
            case RESPONSE_LENGTH_EQUALS:
                try {
                    return Integer.parseInt(pattern) == Integer.parseInt(testContent);
                } catch (NumberFormatException e) {
                    return false;
                }
            case RESPONSE_LENGTH_NOT_EQUALS:
                try {
                    return Integer.parseInt(pattern) != Integer.parseInt(testContent);
                } catch (NumberFormatException e) {
                    return false;
                }
            default:
                return false;
        }
    }
}
