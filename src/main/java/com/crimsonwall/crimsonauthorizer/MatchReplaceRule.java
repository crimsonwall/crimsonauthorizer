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

/** A rule that matches and replaces content in a request before replaying. */
public class MatchReplaceRule {

    /** Where the rule is applied. */
    public enum ApplyTarget {
        HEADERS_SIMPLE,
        HEADERS_REGEX,
        BODY_SIMPLE,
        BODY_REGEX
    }

    private ApplyTarget target;
    private String matchPattern;
    private String replacePattern;
    private boolean enabled;
    private transient Pattern compiledRegex;
    private boolean regexCaseSensitive;

    public MatchReplaceRule() {
        this(ApplyTarget.HEADERS_SIMPLE, "", "", true);
    }

    public MatchReplaceRule(ApplyTarget target, String matchPattern, String replacePattern, boolean enabled) {
        this(target, matchPattern, replacePattern, enabled, false);
    }

    public MatchReplaceRule(ApplyTarget target, String matchPattern, String replacePattern, boolean enabled, boolean regexCaseSensitive) {
        this.target = target;
        this.matchPattern = matchPattern != null ? matchPattern : "";
        this.replacePattern = replacePattern != null ? replacePattern : "";
        this.enabled = enabled;
        this.regexCaseSensitive = regexCaseSensitive;
    }

    public ApplyTarget getTarget() {
        return target;
    }

    public void setTarget(ApplyTarget target) {
        this.target = target;
        this.compiledRegex = null;
    }

    public String getMatchPattern() {
        return matchPattern;
    }

    public void setMatchPattern(String matchPattern) {
        this.matchPattern = matchPattern != null ? matchPattern : "";
        this.compiledRegex = null;
    }

    public String getReplacePattern() {
        return replacePattern;
    }

    public void setReplacePattern(String replacePattern) {
        this.replacePattern = replacePattern != null ? replacePattern : "";
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
        if (compiledRegex == null && isRegexTarget()) {
            try {
                int flags = Pattern.DOTALL;
                if (!regexCaseSensitive) {
                    flags |= Pattern.CASE_INSENSITIVE;
                }
                compiledRegex = Pattern.compile(matchPattern, flags);
            } catch (PatternSyntaxException e) {
                return null;
            }
        }
        return compiledRegex;
    }

    /** Validates that the current pattern is a valid regex (for regex-type rules). */
    public boolean validateRegex() {
        if (!isRegexTarget()) {
            return true;
        }
        try {
            Pattern.compile(matchPattern, Pattern.DOTALL);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    private boolean isRegexTarget() {
        return target == ApplyTarget.HEADERS_REGEX || target == ApplyTarget.BODY_REGEX;
    }

    @Override
    public String toString() {
        return target.name() + ": " + matchPattern + " -> " + replacePattern;
    }
}
