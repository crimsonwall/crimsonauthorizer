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
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Utility class for ZAP context and scope operations using reflection.
 * Provides methods to check if messages are within scope.
 */
public class ScopeUtils {

    private static final Logger LOGGER = LogManager.getLogger(ScopeUtils.class);

    private ScopeUtils() {
        // Utility class
    }

    /**
     * Checks if an HTTP message is within the current ZAP scope/context.
     *
     * @param msg The HTTP message to check.
     * @return true if the message is in scope, false otherwise.
     */
    public static boolean isInScope(HttpMessage msg) {
        if (msg == null || msg.getRequestHeader() == null) {
            return false;
        }

        try {
            String url = msg.getRequestHeader().getURI().toString();
            return isInScope(url);
        } catch (Exception e) {
            LOGGER.warn("Failed to check if message is in scope", e);
            return false;
        }
    }

    /**
     * Checks if a URL is within scope.
     *
     * @param url The URL to check.
     * @return true if in scope, false otherwise.
     */
    public static boolean isInScope(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        try {
            Model model = Model.getSingleton();
            if (model == null) {
                LOGGER.warn("ZAP Model not available — cannot check scope. Defaulting to in-scope.");
                return true;
            }
            Session session = model.getSession();
            if (session == null) {
                LOGGER.warn("ZAP Session not available — cannot check scope. Defaulting to in-scope.");
                return true;
            }
            return session.isInScope(url);
        } catch (Exception e) {
            LOGGER.warn("Scope check failed for {} — defaulting to in-scope: {}", url, e.getMessage());
            return true;
        }
    }

    /**
     * Checks if any contexts are configured in the session.
     *
     * @return true if contexts exist, false otherwise.
     */
    public static boolean hasContexts() {
        try {
            Model model = Model.getSingleton();
            if (model == null) return false;
            Session session = model.getSession();
            if (session == null) return false;
            Object contextsObj = ReflectionUtils.invokeMethod(session, "getContexts");
            if (contextsObj instanceof List<?>) {
                return !((List<?>) contextsObj).isEmpty();
            }
            return false;
        } catch (Exception e) {
            LOGGER.debug("Failed to check contexts: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Gets a description of the current scope configuration.
     *
     * @return Scope description string.
     */
    public static String getScopeDescription() {
        try {
            Model model = Model.getSingleton();
            if (model == null) return "Scope unavailable";
            Session session = model.getSession();
            if (session == null) return "Scope unavailable";

            Object contextsObj = ReflectionUtils.invokeMethod(session, "getContexts");
            if (contextsObj instanceof List<?>) {
                List<?> contexts = (List<?>) contextsObj;
                if (contexts.isEmpty()) {
                    Boolean hasPatterns = (Boolean) ReflectionUtils.invokeMethod(session, "hasInScopePatterns");
                    if (hasPatterns != null && hasPatterns) {
                        return "Using session patterns";
                    }
                    return "No scope defined";
                }

                if (contexts.size() == 1) {
                    Object context = contexts.get(0);
                    String name = (String) ReflectionUtils.invokeMethod(context, "getName");
                    return "Context: " + (name != null ? name : "Unknown");
                }

                return contexts.size() + " contexts configured";
            }

            return "No scope defined";

        } catch (Exception e) {
            LOGGER.debug("Failed to get scope description: {}", e.getMessage());
            return "Scope unavailable";
        }
    }

}
