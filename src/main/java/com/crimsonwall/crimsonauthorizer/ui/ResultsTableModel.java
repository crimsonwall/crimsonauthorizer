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
package com.crimsonwall.crimsonauthorizer.ui;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import com.crimsonwall.crimsonauthorizer.AuthCredentials;
import com.crimsonwall.crimsonauthorizer.AuthorizationResult;
import com.crimsonwall.crimsonauthorizer.EnforcementStatus;

/** Table model for displaying authorization test results with dynamic columns per user. */
public class ResultsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private final transient List<AuthorizationResult> results = new ArrayList<>();
    private transient List<AuthCredentials> users = new ArrayList<>();
    private boolean testUnauthenticated = true;
    private int maxResults = 10000; // Default, can be configured

    private int bypassedCount;
    private int enforcedCount;
    private int undeterminedCount;

    /** Fixed column indices. */
    private static final int COL_ID = 0;
    private static final int COL_METHOD = 1;
    private static final int COL_URL = 2;
    private static final int COL_ORIG_LEN = 3;
    private static final int FIXED_COL_COUNT = 4;

    public void setUsers(List<AuthCredentials> users) {
        // Deduplicate users by name using LinkedHashMap to preserve order
        Map<String, AuthCredentials> uniqueUsers = new LinkedHashMap<>();
        for (AuthCredentials user : users) {
            String userName = user.getUserName();
            if (userName != null && !uniqueUsers.containsKey(userName)) {
                uniqueUsers.put(userName, user);
            }
        }
        this.users = new ArrayList<>(uniqueUsers.values());
        fireTableStructureChanged();
    }

    public void setTestUnauthenticated(boolean testUnauthenticated) {
        this.testUnauthenticated = testUnauthenticated;
        fireTableStructureChanged();
    }

    public void setMaxResults(int maxResults) {
        this.maxResults = maxResults;
    }

    @Override
    public int getColumnCount() {
        int count = FIXED_COL_COUNT;
        // Per user: length + status
        count += users.size() * 2;
        // Unauthenticated: length + status
        if (testUnauthenticated) {
            count += 2;
        }
        return count;
    }

    @Override
    public String getColumnName(int column) {
        if (column < FIXED_COL_COUNT) {
            switch (column) {
                case COL_ID:
                    return Constant.messages.getString("crimsonautorize.table.id");
                case COL_METHOD:
                    return Constant.messages.getString("crimsonautorize.table.method");
                case COL_URL:
                    return Constant.messages.getString("crimsonautorize.table.url");
                case COL_ORIG_LEN:
                    return Constant.messages.getString("crimsonautorize.table.origlen");
            }
        }

        int dynamicCol = column - FIXED_COL_COUNT;
        int userCols = users.size() * 2;

        if (dynamicCol < userCols) {
            int userIndex = dynamicCol / 2;
            boolean isStatus = dynamicCol % 2 == 1;
            String userName = users.get(userIndex).getUserName();
            String pattern = isStatus
                    ? Constant.messages.getString("crimsonautorize.table.userStatus")
                    : Constant.messages.getString("crimsonautorize.table.userLen");
            return MessageFormat.format(pattern, userName);
        }

        // Unauthenticated columns
        int unauthCol = dynamicCol - userCols;
        boolean isStatus = unauthCol % 2 == 1;
        return isStatus
                ? Constant.messages.getString("crimsonautorize.table.unauthStatus")
                : Constant.messages.getString("crimsonautorize.table.unauthLen");
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == COL_ID || columnIndex == COL_ORIG_LEN) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AuthorizationResult result = results.get(rowIndex);

        if (columnIndex < FIXED_COL_COUNT) {
            switch (columnIndex) {
                case COL_ID:
                    return result.getId();
                case COL_METHOD:
                    return result.getMethod();
                case COL_URL:
                    return truncateUrl(result.getUrl(), 80);
                case COL_ORIG_LEN:
                    return result.getOriginalResponseLength();
            }
        }

        int dynamicCol = columnIndex - FIXED_COL_COUNT;
        int userCols = users.size() * 2;

        if (dynamicCol < userCols) {
            int userIndex = dynamicCol / 2;
            boolean isStatus = dynamicCol % 2 == 1;
            AuthCredentials user = users.get(userIndex);
            String userName = user.getUserName();
            Map<String, AuthorizationResult.UserTestResult> userResults = result.getUserResults();
            AuthorizationResult.UserTestResult userResult = userResults.get(userName);

            if (userResult == null || !user.isEnabled()) {
                return isStatus ? EnforcementStatus.DISABLED.getDisplayText() : 0;
            }

            if (isStatus) {
                return userResult.getStatus().getDisplayText();
            } else {
                if (userResult.getModifiedMessage() != null
                        && userResult.getModifiedMessage().getResponseBody() != null) {
                    return userResult.getModifiedMessage().getResponseBody().length();
                }
                return 0;
            }
        }

        // Unauthenticated columns
        int unauthCol = dynamicCol - userCols;
        boolean isStatus = unauthCol % 2 == 1;

        if (isStatus) {
            return result.getUnauthenticatedStatus() != null
                    ? result.getUnauthenticatedStatus().getDisplayText()
                    : "";
        } else {
            if (result.getUnauthenticatedMessage() != null
                    && result.getUnauthenticatedMessage().getResponseBody() != null) {
                return result.getUnauthenticatedMessage().getResponseBody().length();
            }
            return 0;
        }
    }

    /** Gets the enforcement status for a specific column, used by the cell renderer. */
    public EnforcementStatus getStatusAt(int rowIndex, int columnIndex) {
        AuthorizationResult result = results.get(rowIndex);

        if (columnIndex < FIXED_COL_COUNT) {
            return null;
        }

        int dynamicCol = columnIndex - FIXED_COL_COUNT;
        int userCols = users.size() * 2;

        if (dynamicCol < userCols) {
            boolean isStatus = dynamicCol % 2 == 1;
            if (!isStatus) return null;

            int userIndex = dynamicCol / 2;
            AuthCredentials user = users.get(userIndex);
            if (!user.isEnabled()) return EnforcementStatus.DISABLED;

            String userName = user.getUserName();
            AuthorizationResult.UserTestResult userResult = result.getUserResults().get(userName);
            return userResult != null ? userResult.getStatus() : EnforcementStatus.DISABLED;
        }

        int unauthCol = dynamicCol - userCols;
        boolean isStatus = unauthCol % 2 == 1;
        if (!isStatus) return null;

        return result.getUnauthenticatedStatus() != null
                ? result.getUnauthenticatedStatus()
                : EnforcementStatus.DISABLED;
    }

    public void addResult(AuthorizationResult result) {
        // Enforce maximum results limit to prevent memory issues
        if (results.size() >= maxResults) {
            decrementCount(results.get(0).getWorstStatus());
            results.remove(0);
            fireTableRowsDeleted(0, 0);
        }
        incrementCount(result.getWorstStatus());
        results.add(result);
        fireTableRowsInserted(results.size() - 1, results.size() - 1);
    }

    private void incrementCount(EnforcementStatus status) {
        switch (status) {
            case BYPASSED: bypassedCount++; break;
            case ENFORCED: enforcedCount++; break;
            case UNDETERMINED: undeterminedCount++; break;
            default: break;
        }
    }

    private void decrementCount(EnforcementStatus status) {
        switch (status) {
            case BYPASSED: if (bypassedCount > 0) bypassedCount--; break;
            case ENFORCED: if (enforcedCount > 0) enforcedCount--; break;
            case UNDETERMINED: if (undeterminedCount > 0) undeterminedCount--; break;
            default: break;
        }
    }

    public int getBypassedCount() { return bypassedCount; }
    public int getEnforcedCount() { return enforcedCount; }
    public int getUndeterminedCount() { return undeterminedCount; }

    public void clearResults() {
        results.clear();
        bypassedCount = 0;
        enforcedCount = 0;
        undeterminedCount = 0;
        fireTableDataChanged();
    }

    public AuthorizationResult getResultAt(int row) {
        if (row >= 0 && row < results.size()) {
            return results.get(row);
        }
        return null;
    }

    public List<AuthorizationResult> getAllResults() {
        return new ArrayList<>(results);
    }

    /**
     * Returns the user name if {@code columnIndex} belongs to a named user's columns, or
     * {@code null} for fixed columns and the unauthenticated columns.
     */
    public String getUserNameForColumn(int columnIndex) {
        if (columnIndex < FIXED_COL_COUNT) {
            return null;
        }
        int dynamicCol = columnIndex - FIXED_COL_COUNT;
        int userCols = users.size() * 2;
        if (dynamicCol < userCols) {
            return users.get(dynamicCol / 2).getUserName();
        }
        return null;
    }

    private String truncateUrl(String url, int maxLen) {
        if (url == null) return "";
        if (url.length() <= maxLen) return url;
        return url.substring(0, maxLen - 3) + "...";
    }
}
