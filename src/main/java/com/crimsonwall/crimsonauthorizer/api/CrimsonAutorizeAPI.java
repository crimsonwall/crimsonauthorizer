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
package com.crimsonwall.crimsonauthorizer.api;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONObject;
import com.crimsonwall.crimsonauthorizer.AuthCredentials;
import com.crimsonwall.crimsonauthorizer.AuthorizationResult;
import com.crimsonwall.crimsonauthorizer.ExtensionCrimsonAutorize;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

/** ZAP API endpoints for Crimson Authorizer automation. */
public final class CrimsonAutorizeAPI extends ApiImplementor {

    private static final String PREFIX = "crimsonautorize";
    private static final String ACTION_START = "start";
    private static final String ACTION_STOP = "stop";
    private static final String ACTION_CLEAR = "clearResults";
    private static final String ACTION_ADD_USER = "addUser";
    private static final String ACTION_REMOVE_USER = "removeUser";
    private static final String VIEW_RESULTS = "results";
    private static final String VIEW_STATUS = "status";
    private static final String VIEW_USERS = "users";

    private final ExtensionCrimsonAutorize extension;

    public CrimsonAutorizeAPI(ExtensionCrimsonAutorize extension) {
        this.extension = extension;

        addApiAction(new ApiAction(ACTION_START));
        addApiAction(new ApiAction(ACTION_STOP));
        addApiAction(new ApiAction(ACTION_CLEAR));
        addApiAction(new ApiAction(ACTION_ADD_USER, new String[]{"name"}, new String[]{"headers"}));
        addApiAction(new ApiAction(ACTION_REMOVE_USER, new String[]{"name"}));

        addApiView(new ApiView(VIEW_RESULTS));
        addApiView(new ApiView(VIEW_STATUS));
        addApiView(new ApiView(VIEW_USERS));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_START:
                extension.startTesting();
                return ApiResponseElement.OK;

            case ACTION_STOP:
                extension.stopTesting();
                return ApiResponseElement.OK;

            case ACTION_CLEAR:
                extension.clearResults();
                return ApiResponseElement.OK;

            case ACTION_ADD_USER:
                {
                    String userName = params.getString("name");
                    if (userName == null || userName.trim().isEmpty()) {
                        throw new ApiException(ApiException.Type.MISSING_PARAMETER, "name");
                    }
                    AuthCredentials creds = new AuthCredentials(userName.trim());
                    if (params.has("headers")) {
                        String headersStr = params.getString("headers");
                        String parseError = parseHeaders(creds, headersStr);
                        if (parseError != null) {
                            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, "headers: " + parseError);
                        }
                    }
                    extension.addUser(creds);
                    return ApiResponseElement.OK;
                }

            case ACTION_REMOVE_USER:
                {
                    String userName = params.getString("name");
                    extension.removeUser(userName);
                    return ApiResponseElement.OK;
                }

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        switch (name) {
            case VIEW_RESULTS:
                {
                    ApiResponseList list = new ApiResponseList("results");
                    for (AuthorizationResult result : extension.getResults()) {
                        Map<String, String> map = new HashMap<>();
                        map.put("id", String.valueOf(result.getId()));
                        map.put("method", result.getMethod());
                        map.put("url", result.getUrl());
                        map.put("originalLength", String.valueOf(result.getOriginalResponseLength()));
                        map.put("worstStatus", result.getWorstStatus().getDisplayText());
                        if (result.getUnauthenticatedStatus() != null) {
                            map.put("unauthenticatedStatus", result.getUnauthenticatedStatus().getDisplayText());
                        }
                        for (Map.Entry<String, AuthorizationResult.UserTestResult> entry :
                                result.getUserResults().entrySet()) {
                            map.put(entry.getKey() + "Status", entry.getValue().getStatus().getDisplayText());
                        }
                        list.addItem(new ApiResponseSet<>("result", map));
                    }
                    return list;
                }

            case VIEW_STATUS:
                {
                    Map<String, String> stats = new HashMap<>();
                    int enforced = 0, bypassed = 0, undetermined = 0;
                    for (AuthorizationResult result : extension.getResults()) {
                        switch (result.getWorstStatus()) {
                            case ENFORCED: enforced++; break;
                            case BYPASSED: bypassed++; break;
                            case UNDETERMINED: undetermined++; break;
                            default: break;
                        }
                    }
                    stats.put("total", String.valueOf(extension.getResults().size()));
                    stats.put("enforced", String.valueOf(enforced));
                    stats.put("bypassed", String.valueOf(bypassed));
                    stats.put("undetermined", String.valueOf(undetermined));
                    stats.put("active", String.valueOf(extension.isActive()));
                    return new ApiResponseSet<>("status", stats);
                }

            case VIEW_USERS:
                {
                    ApiResponseList list = new ApiResponseList("users");
                    for (AuthCredentials user : extension.getUsers()) {
                        Map<String, String> map = new HashMap<>();
                        map.put("name", user.getUserName());
                        map.put("enabled", String.valueOf(user.isEnabled()));
                        map.put("headerCount", String.valueOf(user.getHeaders().size()));
                        list.addItem(new ApiResponseSet<>("user", map));
                    }
                    return list;
                }

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    /**
     * Parses a header string in format "Name: Value\nName: Value" into credential headers.
     * @return null if successful, or an error message if parsing failed
     */
    private String parseHeaders(AuthCredentials creds, String headersStr) {
        if (headersStr == null || headersStr.trim().isEmpty()) {
            return null;
        }
        String[] lines = headersStr.split("\\\\n|\\r?\\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            int colonIdx = line.indexOf(':');
            if (colonIdx <= 0) {
                return "Invalid header format: " + line;
            }
            String name = line.substring(0, colonIdx).trim();
            String value = line.substring(colonIdx + 1).trim();
            
            if (name.isEmpty()) {
                return "Empty header name in: " + line;
            }
            
            if (!isValidHeaderName(name)) {
                return "Invalid header name: " + name;
            }
            
            creds.addHeader(name, value);
        }
        return null;
    }

    /**
     * Validates a header name according to RFC 7230.
     * Header names must consist of visible ASCII characters excluding separators.
     */
    private static boolean isValidHeaderName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                return false;
            }
            if ("()<>@,;:\\\"/[]?{}".indexOf(c) >= 0) {
                return false;
            }
        }
        return true;
    }
}
