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

/** A single rule used by the enforcement detector to evaluate responses. */
public class EnforcementDetectorRule {

    /** The type of comparison this rule performs. */
    public enum RuleType {
        STATUS_CODE_EQUALS,
        STATUS_CODE_NOT_EQUALS,
        HEADERS_CONTAIN,
        HEADERS_NOT_CONTAIN,
        HEADERS_REGEX,
        HEADERS_NOT_REGEX,
        BODY_CONTAINS,
        BODY_NOT_CONTAINS,
        BODY_REGEX,
        BODY_NOT_REGEX,
        FULL_RESPONSE_CONTAINS,
        FULL_RESPONSE_NOT_CONTAINS,
        FULL_RESPONSE_REGEX,
        FULL_RESPONSE_NOT_REGEX,
        RESPONSE_LENGTH_EQUALS,
        RESPONSE_LENGTH_NOT_EQUALS
    }

    private RuleType type;
    private String pattern;
    private boolean enabled;
    private transient Pattern compiledRegex;
    private boolean regexCaseSensitive;

    public EnforcementDetectorRule() {
        this(RuleType.BODY_CONTAINS, "", true);
    }

    public EnforcementDetectorRule(RuleType type, String pattern, boolean enabled) {
        this(type, pattern, enabled, false);
    }

    public EnforcementDetectorRule(RuleType type, String pattern, boolean enabled, boolean regexCaseSensitive) {
        this.type = type;
        this.pattern = pattern != null ? pattern : "";
        this.enabled = enabled;
        this.regexCaseSensitive = regexCaseSensitive;
    }

    public RuleType getType() {
        return type;
    }

    public void setType(RuleType type) {
        this.type = type;
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

    public boolean isRegexCaseSensitive() {
        return regexCaseSensitive;
    }

    public void setRegexCaseSensitive(boolean regexCaseSensitive) {
        this.regexCaseSensitive = regexCaseSensitive;
        this.compiledRegex = null;
    }

    /** Gets the compiled regex pattern, compiling on first access. Returns null if pattern is invalid. */
    public Pattern getCompiledRegex() {
        if (compiledRegex == null && isRegexType()) {
            try {
                int flags = Pattern.DOTALL;
                if (!regexCaseSensitive) {
                    flags |= Pattern.CASE_INSENSITIVE;
                }
                compiledRegex = Pattern.compile(pattern, flags);
            } catch (PatternSyntaxException e) {
                return null;
            }
        }
        return compiledRegex;
    }

    /** Validates that the current pattern is a valid regex (for regex-type rules). */
    public boolean validateRegex() {
        if (!isRegexType()) {
            return true;
        }
        try {
            Pattern.compile(pattern, Pattern.DOTALL);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    private boolean isRegexType() {
        return type == RuleType.HEADERS_REGEX
                || type == RuleType.HEADERS_NOT_REGEX
                || type == RuleType.BODY_REGEX
                || type == RuleType.BODY_NOT_REGEX
                || type == RuleType.FULL_RESPONSE_REGEX
                || type == RuleType.FULL_RESPONSE_NOT_REGEX;
    }

    @Override
    public String toString() {
        return type.name() + ": " + pattern;
    }
}
