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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

/**
 * Orchestrates authorization testing: takes an intercepted request, replays it with modified
 * credentials for each configured user (and optionally unauthenticated), then evaluates enforcement
 * status by comparing responses.
 */
public class AuthorizationTester {

    private static final Logger LOGGER = LogManager.getLogger(AuthorizationTester.class);

    /** Marker set on replayed messages to prevent infinite interception loops. */
    public static final String REPLAY_MARKER = "CrimsonAutorize";

    public AuthorizationTester() {
    }

    /**
     * Tests a single intercepted request against all configured users and optionally unauthenticated
     * access.
     *
     * @param originalMessage The intercepted authenticated message (with response).
     * @param users List of user credentials to test.
     * @param testUnauthenticated Whether to also test without any credentials.
     * @param unauthDetectorRules Rules for unauthenticated enforcement detection.
     * @param useAndLogic Whether to use AND logic for detector rules.
     * @param authHeadersToStrip Exact header names to remove when swapping authentication credentials.
     * @param authHeaderRegexToStrip Regex patterns for header names to remove.
     * @param maxMessageSize Maximum message size in bytes (0 for no limit).
     * @return The authorization result, or null if testing failed.
     */
    public AuthorizationResult testRequest(
            HttpMessage originalMessage,
            List<AuthCredentials> users,
            boolean testUnauthenticated,
            List<EnforcementDetectorRule> unauthDetectorRules,
            boolean useAndLogic,
            List<String> authHeadersToStrip,
            List<String> authHeaderRegexToStrip,
            int maxMessageSize) {

        String method = originalMessage.getRequestHeader().getMethod();
        String url = originalMessage.getRequestHeader().getURI().toString();
        int origLength =
                originalMessage.getResponseBody() != null ? originalMessage.getResponseBody().length() : 0;

        AuthorizationResult result = new AuthorizationResult(0, method, url, originalMessage, origLength);
        HttpSender sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

        if (testUnauthenticated) {
            testUnauthenticated(
                    sender, originalMessage, result, unauthDetectorRules, useAndLogic,
                    authHeadersToStrip, authHeaderRegexToStrip, maxMessageSize);
        }

        for (AuthCredentials user : users) {
            if (!user.isEnabled()) {
                result.addUserResult(
                        new AuthorizationResult.UserTestResult(
                                user.getUserName(), null, EnforcementStatus.DISABLED));
                continue;
            }
            testUser(sender, originalMessage, user, result, useAndLogic,
                    authHeadersToStrip, authHeaderRegexToStrip, maxMessageSize);
        }

        return result;
    }

    private void testUnauthenticated(
            HttpSender sender,
            HttpMessage original,
            AuthorizationResult result,
            List<EnforcementDetectorRule> detectorRules,
            boolean useAndLogic,
            List<String> authHeadersToStrip,
            List<String> authHeaderRegexToStrip,
            int maxMessageSize) {

        try {
            HttpMessage unauthMsg =
                    RequestModifier.createUnauthenticatedRequest(
                            original, authHeadersToStrip, authHeaderRegexToStrip, maxMessageSize);
            if (unauthMsg == null) {
                LOGGER.warn("Failed to create unauthenticated request for {}", result.getUrl());
                result.setUnauthenticatedStatus(EnforcementStatus.UNDETERMINED);
                return;
            }

            unauthMsg.setUserObject(REPLAY_MARKER);
            sender.sendAndReceive(unauthMsg);

            EnforcementStatus status =
                    EnforcementDetector.detect(original, unauthMsg, detectorRules, useAndLogic);

            result.setUnauthenticatedMessage(unauthMsg);
            result.setUnauthenticatedStatus(status);

            LOGGER.debug(
                    "Unauthenticated test for {} -> {}", result.getUrl(), status.getDisplayText());

        } catch (Exception e) {
            LOGGER.error("Error testing unauthenticated access for {}", result.getUrl(), e);
            result.setUnauthenticatedStatus(EnforcementStatus.UNDETERMINED);
        }
    }

    private void testUser(
            HttpSender sender,
            HttpMessage original,
            AuthCredentials user,
            AuthorizationResult result,
            boolean useAndLogic,
            List<String> authHeadersToStrip,
            List<String> authHeaderRegexToStrip,
            int maxMessageSize) {

        try {
            HttpMessage userMsg =
                    RequestModifier.createUserRequest(
                            original, user, user.getMatchReplaceRules(),
                            authHeadersToStrip, authHeaderRegexToStrip, maxMessageSize);

            if (userMsg == null) {
                LOGGER.debug(
                        "Skipping user '{}' for {} (required headers not present in original request)",
                        user.getUserName(),
                        result.getUrl());
                result.addUserResult(
                        new AuthorizationResult.UserTestResult(
                                user.getUserName(), null, EnforcementStatus.SKIPPED));
                return;
            }

            userMsg.setUserObject(REPLAY_MARKER);
            sender.sendAndReceive(userMsg);

            List<EnforcementDetectorRule> rules = user.getDetectorRules();
            EnforcementStatus status =
                    EnforcementDetector.detect(original, userMsg, rules, useAndLogic);

            result.addUserResult(
                    new AuthorizationResult.UserTestResult(user.getUserName(), userMsg, status));

            LOGGER.debug(
                    "User '{}' test for {} -> {}",
                    user.getUserName(),
                    result.getUrl(),
                    status.getDisplayText());

        } catch (Exception e) {
            LOGGER.error(
                    "Error testing user '{}' access for {}",
                    user.getUserName(),
                    result.getUrl(),
                    e);
            result.addUserResult(
                    new AuthorizationResult.UserTestResult(
                            user.getUserName(), null, EnforcementStatus.UNDETERMINED));
        }
    }
}
