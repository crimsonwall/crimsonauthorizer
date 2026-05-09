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

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** A single rule that determines whether an HTTP message should be intercepted for testing. */
public class InterceptionFilterRule {

    /** The type of filter comparison. */
    public enum FilterType {
        URL_CONTAINS,
        URL_NOT_CONTAINS,
        URL_REGEX,
        URL_NOT_REGEX,
        REQUEST_HEADERS_CONTAIN,
        REQUEST_HEADERS_NOT_CONTAIN,
        RESPONSE_BODY_CONTAINS,
        RESPONSE_BODY_NOT_CONTAINS,
        METHODS_ALLOWED,
        METHODS_IGNORED,
        SCOPE_ONLY,
        IGNORE_OPTIONS
    }

    private FilterType type;
    private String pattern;
    private boolean enabled;
    private transient Pattern compiledRegex;

    public InterceptionFilterRule() {
        this(FilterType.URL_CONTAINS, "", true);
    }

    public InterceptionFilterRule(FilterType type, String pattern, boolean enabled) {
        this.type = type;
        this.pattern = pattern != null ? pattern : "";
        this.enabled = enabled;
    }

    public FilterType getType() {
        return type;
    }

    public void setType(FilterType type) {
        this.type = type;
        this.compiledRegex = null;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern != null ? pattern : "";
        this.compiledRegex = null;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /** Compiles a regex pattern for regex-type filters, caching the result. */
    public Pattern getCompiledRegex() {
        if (type == FilterType.URL_REGEX || type == FilterType.URL_NOT_REGEX) {
            if (compiledRegex == null) {
                try {
                    compiledRegex = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                } catch (PatternSyntaxException e) {
                    return null;
                }
            }
            return compiledRegex;
        }
        return null;
    }

    @Override
    public String toString() {
        return type.name() + ": " + pattern;
    }
}
