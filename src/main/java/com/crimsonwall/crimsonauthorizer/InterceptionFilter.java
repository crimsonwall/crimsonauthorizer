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

/** Evaluates whether an HTTP message should be intercepted for authorization testing. */
public class InterceptionFilter {

    private final List<InterceptionFilterRule> rules;

    public InterceptionFilter(List<InterceptionFilterRule> rules) {
        this.rules = rules;
    }

    /** Returns true if the message passes all enabled filter rules (or if no rules are defined). */
    public boolean shouldTest(HttpMessage msg) {
        if (rules == null || rules.isEmpty()) {
            return true;
        }

        boolean hasEnabledRules = false;
        for (InterceptionFilterRule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }
            hasEnabledRules = true;
            if (!evaluateRule(msg, rule)) {
                return false;
            }
        }

        // All enabled rules passed (or none existed) — test this message
        return true;
    }

    private boolean evaluateRule(HttpMessage msg, InterceptionFilterRule rule) {
        switch (rule.getType()) {
            case URL_CONTAINS:
                return msg.getRequestHeader().getURI().toString().contains(rule.getPattern());
            case URL_NOT_CONTAINS:
                return !msg.getRequestHeader().getURI().toString().contains(rule.getPattern());
            case URL_REGEX:
                {
                    Pattern p = rule.getCompiledRegex();
                    return p != null && p.matcher(msg.getRequestHeader().getURI().toString()).find();
                }
            case URL_NOT_REGEX:
                {
                    Pattern p = rule.getCompiledRegex();
                    return p == null || !p.matcher(msg.getRequestHeader().getURI().toString()).find();
                }
            case REQUEST_HEADERS_CONTAIN:
                return msg.getRequestHeader().getHeadersAsString().contains(rule.getPattern());
            case REQUEST_HEADERS_NOT_CONTAIN:
                return !msg.getRequestHeader().getHeadersAsString().contains(rule.getPattern());
            case RESPONSE_BODY_CONTAINS:
                {
                    String body = msg.getResponseBody() != null ? msg.getResponseBody().toString() : "";
                    return body.contains(rule.getPattern());
                }
            case RESPONSE_BODY_NOT_CONTAINS:
                {
                    String body = msg.getResponseBody() != null ? msg.getResponseBody().toString() : "";
                    return !body.contains(rule.getPattern());
                }
            case METHODS_ALLOWED:
                {
                    String method = msg.getRequestHeader().getMethod();
                    for (String m : rule.getPattern().toUpperCase().split(",")) {
                        if (method.equalsIgnoreCase(m.trim())) return true;
                    }
                    return false;
                }
            case METHODS_IGNORED:
                {
                    String method = msg.getRequestHeader().getMethod();
                    for (String m : rule.getPattern().toUpperCase().split(",")) {
                        if (method.equalsIgnoreCase(m.trim())) return false;
                    }
                    return true;
                }
            case SCOPE_ONLY:
                return ScopeUtils.isInScope(msg);
            case IGNORE_OPTIONS:
                return !"OPTIONS".equalsIgnoreCase(msg.getRequestHeader().getMethod());
            default:
                return true;
        }
    }
}
