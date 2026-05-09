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
package com.crimsonwall.crimsonauthorizer.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.parosproxy.paros.common.AbstractParam;
import com.crimsonwall.crimsonauthorizer.AuthCredentials;
import com.crimsonwall.crimsonauthorizer.EnforcementDetectorRule;
import com.crimsonwall.crimsonauthorizer.EnforcementDetectorRule.RuleType;
import com.crimsonwall.crimsonauthorizer.InterceptionFilterRule;
import com.crimsonwall.crimsonauthorizer.InterceptionFilterRule.FilterType;

/** Persistent configuration for the Crimson Authorizer add-on. */
public class CrimsonAutorizeOptions extends AbstractParam {

    private static final String BASE_KEY = "crimsonautorize";

    private static final String IGNORE_304_KEY = BASE_KEY + ".ignore304";
    private static final String TEST_UNAUTH_KEY = BASE_KEY + ".testUnauthenticated";
    private static final String USE_AND_LOGIC_KEY = BASE_KEY + ".useAndLogic";
    private static final String TEST_REQUESTER_KEY = BASE_KEY + ".testRequester";
    private static final String AUTH_HEADERS_KEY = BASE_KEY + ".authHeadersToStrip";
    private static final String AUTH_HEADERS_REGEX_KEY = BASE_KEY + ".authHeaderRegexToStrip";
    private static final String EXCLUDE_EXTENSIONS_KEY = BASE_KEY + ".excludeExtensions";
    private static final String UNAUTH_DETECTOR_RULES_KEY = BASE_KEY + ".unauthDetectorRules";
    private static final String INTERCEPTION_FILTER_RULES_KEY = BASE_KEY + ".interceptionFilterRules";
    private static final String MAX_MESSAGE_SIZE_KEY = BASE_KEY + ".maxMessageSize";
    private static final String MAX_RESULTS_KEY = BASE_KEY + ".maxResults";
    /** Legacy key — users are no longer persisted; cleared on startup to remove stale credentials. */
    private static final String LEGACY_USERS_KEY = BASE_KEY + ".users";
    private static final String DEFAULT_AUTH_HEADERS =
            "Cookie,Authorization,If-None-Match,If-Modified-Since,If-Range,If-Match";
    private static final String DEFAULT_AUTH_HEADERS_REGEX = "";
    private static final String DEFAULT_EXCLUDE_EXTENSIONS =
            "js,wasm,woff2,woff,ttf,otf,eot,css,jpg,jpeg,png,gif,bmp,svg,ico,webp,mp4,avi,mov,wmv,flv,webm,mkv,mp3,wav,ogg,mid,aac,flac";

    // Default limits (in MB for message size)
    private static final int DEFAULT_MAX_MESSAGE_SIZE_MB = 2;
    private static final int DEFAULT_MAX_RESULTS = 10000;

    private boolean ignore304;
    private boolean testUnauthenticated;
    private boolean useAndLogic;
    private boolean testRequester;
    private int maxMessageSize; // in bytes
    private int maxResults;

    private final List<String> authHeadersToStrip = new ArrayList<>();
    private final List<String> authHeaderRegexToStrip = new ArrayList<>();
    private final List<String> excludeExtensions = new ArrayList<>();

    private final List<EnforcementDetectorRule> unauthDetectorRules = new ArrayList<>();
    private final List<InterceptionFilterRule> interceptionFilterRules = new ArrayList<>();
    private final List<AuthCredentials> users = new ArrayList<>();

    private CrimsonAutorizeOptionsPanel optionsPanel;

    public CrimsonAutorizeOptions() {
        this.ignore304 = false;
        this.testUnauthenticated = true;
        this.useAndLogic = false;
        this.testRequester = false;
        this.maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE_MB * 1024 * 1024;
        this.maxResults = DEFAULT_MAX_RESULTS;
        authHeadersToStrip.addAll(
                Arrays.asList(
                        "Cookie", "Authorization", "If-None-Match",
                        "If-Modified-Since", "If-Range", "If-Match"));
    }

    @Override
    protected void parse() {
        ignore304 = getConfig().getBoolean(IGNORE_304_KEY, false);
        testUnauthenticated = getConfig().getBoolean(TEST_UNAUTH_KEY, true);
        useAndLogic = getConfig().getBoolean(USE_AND_LOGIC_KEY, false);
        testRequester = getConfig().getBoolean(TEST_REQUESTER_KEY, false);

        // Read limits - convert MB to bytes
        int maxSizeMb = getConfig().getInt(MAX_MESSAGE_SIZE_KEY, DEFAULT_MAX_MESSAGE_SIZE_MB);
        maxMessageSize = maxSizeMb * 1024 * 1024;
        maxResults = getConfig().getInt(MAX_RESULTS_KEY, DEFAULT_MAX_RESULTS);

        String headersStr = getConfig().getString(AUTH_HEADERS_KEY, DEFAULT_AUTH_HEADERS);
        authHeadersToStrip.clear();
        for (String h : headersStr.split(",")) {
            String trimmed = h.trim();
            if (!trimmed.isEmpty()) {
                authHeadersToStrip.add(trimmed);
            }
        }

        String regexStr = getConfig().getString(AUTH_HEADERS_REGEX_KEY, DEFAULT_AUTH_HEADERS_REGEX);
        authHeaderRegexToStrip.clear();
        for (String r : regexStr.split(",")) {
            String trimmed = r.trim();
            if (!trimmed.isEmpty()) {
                authHeaderRegexToStrip.add(trimmed);
            }
        }

        String extensionsStr = getConfig().getString(EXCLUDE_EXTENSIONS_KEY, DEFAULT_EXCLUDE_EXTENSIONS);
        excludeExtensions.clear();
        for (String ext : extensionsStr.split(",")) {
            String trimmed = ext.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                // Remove leading dot if present
                if (trimmed.startsWith(".")) {
                    trimmed = trimmed.substring(1);
                }
                excludeExtensions.add(trimmed);
            }
        }

        // Users are never persisted — wipe any stale credential data left by older versions.
        getConfig().clearProperty(LEGACY_USERS_KEY);
        users.clear();
        loadUnauthDetectorRules();
        loadInterceptionFilterRules();
    }

    // --- JSON Serialization ---

    private void loadUnauthDetectorRules() {
        unauthDetectorRules.clear();
        String json = getConfig().getString(UNAUTH_DETECTOR_RULES_KEY, "");
        if (json.isEmpty()) return;
        try {
            JSONArray arr = JSONArray.fromObject(json);
            for (Object obj : arr) {
                unauthDetectorRules.add(detectorRuleFromJson((JSONObject) obj));
            }
        } catch (Exception e) {
            unauthDetectorRules.clear();
        }
    }

    private void saveUnauthDetectorRules() {
        JSONArray arr = new JSONArray();
        for (EnforcementDetectorRule rule : unauthDetectorRules) {
            arr.add(detectorRuleToJson(rule));
        }
        getConfig().setProperty(UNAUTH_DETECTOR_RULES_KEY, arr.toString());
    }

    private void loadInterceptionFilterRules() {
        interceptionFilterRules.clear();
        String json = getConfig().getString(INTERCEPTION_FILTER_RULES_KEY, "");
        if (json.isEmpty()) return;
        try {
            JSONArray arr = JSONArray.fromObject(json);
            for (Object obj : arr) {
                interceptionFilterRules.add(filterRuleFromJson((JSONObject) obj));
            }
        } catch (Exception e) {
            interceptionFilterRules.clear();
        }
    }

    private void saveInterceptionFilterRules() {
        JSONArray arr = new JSONArray();
        for (InterceptionFilterRule rule : interceptionFilterRules) {
            arr.add(filterRuleToJson(rule));
        }
        getConfig().setProperty(INTERCEPTION_FILTER_RULES_KEY, arr.toString());
    }

    private static JSONObject detectorRuleToJson(EnforcementDetectorRule rule) {
        JSONObject json = new JSONObject();
        json.put("type", rule.getType().name());
        json.put("pattern", rule.getPattern());
        json.put("enabled", rule.isEnabled());
        json.put("regexCaseSensitive", rule.isRegexCaseSensitive());
        return json;
    }

    private static EnforcementDetectorRule detectorRuleFromJson(JSONObject json) {
        EnforcementDetectorRule rule = new EnforcementDetectorRule();
        try {
            rule.setType(RuleType.valueOf(json.optString("type", "BODY_CONTAINS")));
        } catch (IllegalArgumentException e) {
            rule.setType(RuleType.BODY_CONTAINS);
        }
        rule.setPattern(json.optString("pattern", ""));
        rule.setEnabled(json.optBoolean("enabled", true));
        rule.setRegexCaseSensitive(json.optBoolean("regexCaseSensitive", false));
        return rule;
    }

    private static JSONObject filterRuleToJson(InterceptionFilterRule rule) {
        JSONObject json = new JSONObject();
        json.put("type", rule.getType().name());
        json.put("pattern", rule.getPattern());
        json.put("enabled", rule.isEnabled());
        return json;
    }

    private static InterceptionFilterRule filterRuleFromJson(JSONObject json) {
        InterceptionFilterRule rule = new InterceptionFilterRule();
        try {
            rule.setType(FilterType.valueOf(json.optString("type", "URL_CONTAINS")));
        } catch (IllegalArgumentException e) {
            rule.setType(FilterType.URL_CONTAINS);
        }
        rule.setPattern(json.optString("pattern", ""));
        rule.setEnabled(json.optBoolean("enabled", true));
        return rule;
    }

    // --- Simple Settings ---

    public boolean isIgnore304() {
        return ignore304;
    }

    public void setIgnore304(boolean ignore304) {
        this.ignore304 = ignore304;
        getConfig().setProperty(IGNORE_304_KEY, ignore304);
    }

    public boolean isTestUnauthenticated() {
        return testUnauthenticated;
    }

    public void setTestUnauthenticated(boolean testUnauthenticated) {
        this.testUnauthenticated = testUnauthenticated;
        getConfig().setProperty(TEST_UNAUTH_KEY, testUnauthenticated);
    }

    public boolean isUseAndLogic() {
        return useAndLogic;
    }

    public void setUseAndLogic(boolean useAndLogic) {
        this.useAndLogic = useAndLogic;
        getConfig().setProperty(USE_AND_LOGIC_KEY, useAndLogic);
    }

    public boolean isTestRequester() {
        return testRequester;
    }

    public void setTestRequester(boolean testRequester) {
        this.testRequester = testRequester;
        getConfig().setProperty(TEST_REQUESTER_KEY, testRequester);
    }

    public int getMaxMessageSize() {
        return maxMessageSize;
    }

    public int getMaxMessageSizeMb() {
        return maxMessageSize / (1024 * 1024);
    }

    public void setMaxMessageSizeMb(int maxSizeMb) {
        this.maxMessageSize = maxSizeMb * 1024 * 1024;
        getConfig().setProperty(MAX_MESSAGE_SIZE_KEY, maxSizeMb);
    }

    public int getMaxResults() {
        return maxResults;
    }

    public void setMaxResults(int maxResults) {
        this.maxResults = maxResults;
        getConfig().setProperty(MAX_RESULTS_KEY, maxResults);
    }

    public List<String> getAuthHeadersToStrip() {
        return Collections.unmodifiableList(authHeadersToStrip);
    }

    public void setAuthHeadersToStrip(List<String> headers) {
        authHeadersToStrip.clear();
        authHeadersToStrip.addAll(headers);
        getConfig().setProperty(AUTH_HEADERS_KEY, String.join(",", authHeadersToStrip));
    }

    public List<String> getAuthHeaderRegexToStrip() {
        return Collections.unmodifiableList(authHeaderRegexToStrip);
    }

    public void setAuthHeaderRegexToStrip(List<String> patterns) {
        authHeaderRegexToStrip.clear();
        authHeaderRegexToStrip.addAll(patterns);
        getConfig().setProperty(AUTH_HEADERS_REGEX_KEY, String.join(",", authHeaderRegexToStrip));
    }

    public List<String> getExcludeExtensions() {
        return Collections.unmodifiableList(excludeExtensions);
    }

    public void setExcludeExtensions(List<String> extensions) {
        excludeExtensions.clear();
        for (String ext : extensions) {
            String trimmed = ext.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                // Remove leading dot if present
                if (trimmed.startsWith(".")) {
                    trimmed = trimmed.substring(1);
                }
                excludeExtensions.add(trimmed);
            }
        }
        getConfig().setProperty(EXCLUDE_EXTENSIONS_KEY, String.join(",", excludeExtensions));
    }

    // --- Complex Setting Persistence ---

    public List<EnforcementDetectorRule> getUnauthDetectorRules() {
        return Collections.unmodifiableList(unauthDetectorRules);
    }

    public void setUnauthDetectorRules(List<EnforcementDetectorRule> rules) {
        unauthDetectorRules.clear();
        unauthDetectorRules.addAll(rules);
        saveUnauthDetectorRules();
    }

    public List<InterceptionFilterRule> getInterceptionFilterRules() {
        return Collections.unmodifiableList(interceptionFilterRules);
    }

    public void setInterceptionFilterRules(List<InterceptionFilterRule> rules) {
        interceptionFilterRules.clear();
        interceptionFilterRules.addAll(rules);
        saveInterceptionFilterRules();
    }

    public List<AuthCredentials> getUsers() {
        return Collections.unmodifiableList(users);
    }

    public void addUser(AuthCredentials user) {
        // Check for duplicate user names
        for (AuthCredentials existing : users) {
            if (existing.getUserName().equals(user.getUserName())) {
                return;
            }
        }
        users.add(user);
    }

    public void removeUser(String userName) {
        users.removeIf(u -> u.getUserName().equals(userName));
    }

    public CrimsonAutorizeOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new CrimsonAutorizeOptionsPanel(this);
        }
        return optionsPanel;
    }
}
