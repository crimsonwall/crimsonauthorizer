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
import java.util.Collections;
import java.util.List;

/** Stores authentication headers for a single test user/role. */
public class AuthCredentials {

    private String userName;
    private final List<HeaderEntry> headers;
    private final List<EnforcementDetectorRule> detectorRules;
    private final List<MatchReplaceRule> matchReplaceRules;
    private boolean enabled;

    /** A single header name/value pair. */
    public static class HeaderEntry {
        private String name;
        private String value;

        public HeaderEntry() {
            this("", "");
        }

        public HeaderEntry(String name, String value) {
            this.name = name != null ? name : "";
            this.value = value != null ? value : "";
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name != null ? name : "";
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value != null ? value : "";
        }

        @Override
        public String toString() {
            return name + ": " + value;
        }
    }

    public AuthCredentials() {
        this("User");
    }

    public AuthCredentials(String userName) {
        this.userName = userName;
        this.headers = new ArrayList<>();
        this.detectorRules = new ArrayList<>();
        this.matchReplaceRules = new ArrayList<>();
        this.enabled = true;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public List<HeaderEntry> getHeaders() {
        return Collections.unmodifiableList(headers);
    }

    public void addHeader(String name, String value) {
        headers.add(new HeaderEntry(name, value));
    }

    public List<EnforcementDetectorRule> getDetectorRules() {
        return Collections.unmodifiableList(detectorRules);
    }

    public void addDetectorRule(EnforcementDetectorRule rule) {
        detectorRules.add(rule);
    }

    public List<MatchReplaceRule> getMatchReplaceRules() {
        return Collections.unmodifiableList(matchReplaceRules);
    }

    public void addMatchReplaceRule(MatchReplaceRule rule) {
        matchReplaceRules.add(rule);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String toString() {
        return userName + " (" + headers.size() + " headers)";
    }
}
