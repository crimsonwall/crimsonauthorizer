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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.parosproxy.paros.network.HttpMessage;

/** Data model holding the result of authorization testing for a single intercepted request. */
public class AuthorizationResult {

    private int id;
    private final String method;
    private final String url;
    private final HttpMessage originalMessage;
    private final int originalResponseLength;

    private HttpMessage unauthenticatedMessage;
    private EnforcementStatus unauthenticatedStatus;

    private final Map<String, UserTestResult> userResults;

    /** Result for a single user test. */
    public static class UserTestResult {
        private String userName;
        private final HttpMessage modifiedMessage;
        private final EnforcementStatus status;

        public UserTestResult(String userName, HttpMessage modifiedMessage, EnforcementStatus status) {
            this.userName = userName;
            this.modifiedMessage = modifiedMessage;
            this.status = status;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public HttpMessage getModifiedMessage() {
            return modifiedMessage;
        }

        public EnforcementStatus getStatus() {
            return status;
        }
    }

    public AuthorizationResult(
            int id, String method, String url, HttpMessage originalMessage, int originalResponseLength) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.originalMessage = originalMessage;
        this.originalResponseLength = originalResponseLength;
        this.userResults = new LinkedHashMap<>();
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public HttpMessage getOriginalMessage() {
        return originalMessage;
    }

    public int getOriginalResponseLength() {
        return originalResponseLength;
    }

    public HttpMessage getUnauthenticatedMessage() {
        return unauthenticatedMessage;
    }

    public void setUnauthenticatedMessage(HttpMessage unauthenticatedMessage) {
        this.unauthenticatedMessage = unauthenticatedMessage;
    }

    public EnforcementStatus getUnauthenticatedStatus() {
        return unauthenticatedStatus;
    }

    public void setUnauthenticatedStatus(EnforcementStatus unauthenticatedStatus) {
        this.unauthenticatedStatus = unauthenticatedStatus;
    }

    public void addUserResult(UserTestResult result) {
        userResults.put(result.getUserName(), result);
    }

    public Map<String, UserTestResult> getUserResults() {
        return Collections.unmodifiableMap(userResults);
    }

    /** Returns the worst-case enforcement status across all tests, ignoring DISABLED/SKIPPED. */
    public EnforcementStatus getWorstStatus() {
        EnforcementStatus worst = null;

        if (unauthenticatedStatus != null
                && unauthenticatedStatus != EnforcementStatus.DISABLED
                && unauthenticatedStatus != EnforcementStatus.SKIPPED) {
            worst = unauthenticatedStatus;
        }

        for (UserTestResult r : userResults.values()) {
            EnforcementStatus s = r.getStatus();
            if (s == EnforcementStatus.DISABLED || s == EnforcementStatus.SKIPPED) {
                continue;
            }
            worst = worst == null ? s : worseOf(worst, s);
        }

        // No real tests ran (all users disabled/skipped)
        return worst != null ? worst : EnforcementStatus.DISABLED;
    }

    private static EnforcementStatus worseOf(EnforcementStatus a, EnforcementStatus b) {
        // BYPASSED is worst, then UNDETERMINED, then ENFORCED
        if (a == EnforcementStatus.BYPASSED || b == EnforcementStatus.BYPASSED) {
            return EnforcementStatus.BYPASSED;
        }
        if (a == EnforcementStatus.UNDETERMINED || b == EnforcementStatus.UNDETERMINED) {
            return EnforcementStatus.UNDETERMINED;
        }
        return EnforcementStatus.ENFORCED;
    }

    /**
     * Renames a user in this result's user results map.
     *
     * @param oldName The current user name.
     * @param newName The new user name.
     */
    public void renameUser(String oldName, String newName) {
        UserTestResult result = userResults.get(oldName);
        if (result != null) {
            result.setUserName(newName);
            userResults.remove(oldName);
            userResults.put(newName, result);
        }
    }
}
