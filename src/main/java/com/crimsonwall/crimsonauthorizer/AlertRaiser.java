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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * Raises ZAP alerts when authorization bypasses are detected.
 * Integrates findings into ZAP's core Alert reporting system.
 */
public class AlertRaiser {

    private static final Logger LOGGER = LogManager.getLogger(AlertRaiser.class);

    private static final int PLUGIN_ID = 90001;
    private static final String ALERT_REF = "90001-1";

    private static final int CWE_IMPROPER_ACCESS_CONTROL = 284;
    private static final int WASC_PRIVILEGE_ABUSE = 2;

    private static volatile ExtensionAlert alertExtension;

    private AlertRaiser() {}

    private static ExtensionAlert getAlertExtension() {
        if (alertExtension == null) {
            try {
                alertExtension = Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAlert.class);
            } catch (Exception e) {
                LOGGER.warn("Failed to get ExtensionAlert: {}", e.getMessage());
            }
        }
        return alertExtension;
    }

    public static void raiseAuthorizationBypass(
            HttpMessage message, AuthorizationResult result, String testType) {
        ExtensionAlert extAlert = getAlertExtension();
        if (extAlert == null) {
            logAuthorizationBypass(message, result, testType);
            return;
        }

        String url = message.getRequestHeader().getURI().toString();
        String method = message.getRequestHeader().getMethod();

        Alert alert = new Alert(PLUGIN_ID);
        alert.setAlertRef(ALERT_REF);
        alert.setRisk(Alert.RISK_HIGH);
        alert.setConfidence(Alert.CONFIDENCE_MEDIUM);
        alert.setName("Authorization Bypass: " + testType);
        alert.setDescription(
                "An authorization bypass was detected when testing " + url + ".\n\n"
                + "Test Type: " + testType + "\n"
                + "Method: " + method + "\n"
                + "Worst Status: " + result.getWorstStatus().getDisplayText() + "\n\n"
                + "The application failed to properly enforce authorization checks, "
                + "allowing access to resources that should be restricted.");
        alert.setSolution(
                "Implement proper server-side authorization checks for all restricted resources. "
                + "Verify that authentication and authorization are enforced consistently "
                + "across all HTTP methods and user roles.");
        alert.setReference(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
                + "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include");
        alert.setCweId(CWE_IMPROPER_ACCESS_CONTROL);
        alert.setWascId(WASC_PRIVILEGE_ABUSE);
        alert.setMessage(message);
        alert.setEvidence(buildBypassEvidence(result));
        alert.setParam(buildBypassParam(result));

        try {
            alert.setUri(message.getRequestHeader().getURI().toString());
        } catch (Exception e) {
            LOGGER.warn("Failed to set alert URI: {}", e.getMessage());
        }

        extAlert.alertFound(alert, null);
        LOGGER.warn("Raised ZAP alert for authorization bypass at {}", url);
    }

    private static String buildBypassEvidence(AuthorizationResult result) {
        StringBuilder sb = new StringBuilder();
        if (result.getUnauthenticatedStatus() == EnforcementStatus.BYPASSED) {
            sb.append("Unauthenticated access bypassed; ");
        }
        for (AuthorizationResult.UserTestResult ur : result.getUserResults().values()) {
            if (ur.getStatus() == EnforcementStatus.BYPASSED) {
                sb.append("User '").append(ur.getUserName()).append("' bypassed; ");
            }
        }
        return sb.length() > 0 ? sb.toString() : "Authorization bypass detected";
    }

    private static String buildBypassParam(AuthorizationResult result) {
        StringBuilder sb = new StringBuilder();
        if (result.getUnauthenticatedStatus() != null) {
            sb.append("Unauth: ").append(result.getUnauthenticatedStatus().getDisplayText()).append("; ");
        }
        for (AuthorizationResult.UserTestResult ur : result.getUserResults().values()) {
            sb.append(ur.getUserName()).append(": ")
              .append(ur.getStatus().getDisplayText()).append("; ");
        }
        return sb.toString();
    }

    // --- Logging fallbacks (when ZAP alert extension unavailable) ---

    public static void logAuthorizationBypass(
            HttpMessage message, AuthorizationResult result, String testType) {
        String url = message.getRequestHeader().getURI().toString();
        String method = message.getRequestHeader().getMethod();

        LOGGER.warn(
                "=== AUTHORIZATION BYPASS DETECTED ===\n" +
                "URL: {}\nMethod: {}\nTest Type: {}\nStatus: {}\nCWE: {} (Improper Access Control)\nWASC: {} (Privilege Abuse)\n===",
                url, method, testType,
                result.getWorstStatus().getDisplayText(),
                CWE_IMPROPER_ACCESS_CONTROL, WASC_PRIVILEGE_ABUSE);
        logBypassDetails(result);
    }

    private static void logBypassDetails(AuthorizationResult result) {
        StringBuilder sb = new StringBuilder("Bypass Details:\n");
        if (result.getUnauthenticatedStatus() != null) {
            sb.append("  - Unauthenticated: ")
              .append(result.getUnauthenticatedStatus().getDisplayText()).append("\n");
        }
        for (AuthorizationResult.UserTestResult ur : result.getUserResults().values()) {
            if (ur.getStatus() == EnforcementStatus.BYPASSED) {
                sb.append("  - User '").append(ur.getUserName()).append("': BYPASSED\n");
            }
        }
        LOGGER.warn("{}", sb);
    }

    public static int getPluginId() {
        return PLUGIN_ID;
    }

    public static int getPrimaryCweId() {
        return CWE_IMPROPER_ACCESS_CONTROL;
    }

    public static int getWascId() {
        return WASC_PRIVILEGE_ABUSE;
    }
}
