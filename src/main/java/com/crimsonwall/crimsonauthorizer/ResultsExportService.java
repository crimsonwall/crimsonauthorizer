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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Exports authorization test results to CSV and HTML formats. */
public class ResultsExportService {

    private ResultsExportService() {
        // Utility class
    }

    /** Exports results to a CSV file. */
    public static void exportToCsv(List<AuthorizationResult> results, File outputFile) throws IOException {
        try (BufferedWriter writer =
                new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {

            // Collect all unique user names across all results for consistent columns
            Set<String> allUserNames = new LinkedHashSet<>();
            for (AuthorizationResult result : results) {
                allUserNames.addAll(result.getUserResults().keySet());
            }
            List<String> userList = new ArrayList<>(allUserNames);

            // Build header row with user columns
            StringBuilder header = new StringBuilder("ID,Method,URL,Original Length,Worst Status,Unauth Status");
            for (String userName : userList) {
                header.append(",").append(escapeCsv(userName)).append(" Status");
            }
            writer.write(header.toString());
            writer.newLine();

            // Data rows
            for (AuthorizationResult result : results) {
                writer.write(String.valueOf(result.getId()));
                writer.write(",");
                writer.write(escapeCsv(result.getMethod()));
                writer.write(",");
                writer.write(escapeCsv(result.getUrl()));
                writer.write(",");
                writer.write(String.valueOf(result.getOriginalResponseLength()));
                writer.write(",");
                writer.write(escapeCsv(result.getWorstStatus().getDisplayText()));
                writer.write(",");

                if (result.getUnauthenticatedStatus() != null) {
                    writer.write(escapeCsv(result.getUnauthenticatedStatus().getDisplayText()));
                }

                // Per-user results (use consistent column order)
                for (String userName : userList) {
                    writer.write(",");
                    AuthorizationResult.UserTestResult ur = result.getUserResults().get(userName);
                    if (ur != null) {
                        writer.write(escapeCsv(ur.getStatus().getDisplayText()));
                    }
                }

                writer.newLine();
            }
        }
    }

    /** Exports results to an HTML file with color-coded status cells. */
    public static void exportToHtml(List<AuthorizationResult> results, File outputFile) throws IOException {
        try (BufferedWriter writer =
                new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {

            // Collect all unique user names for consistent columns
            Set<String> allUserNames = new LinkedHashSet<>();
            for (AuthorizationResult result : results) {
                allUserNames.addAll(result.getUserResults().keySet());
            }
            List<String> userList = new ArrayList<>(allUserNames);

            writer.write("<!DOCTYPE html>\n<html>\n<head>\n");
            writer.write("<meta charset=\"UTF-8\">\n");
            writer.write("<title>Crimson Authorizer Results</title>\n");
            writer.write("<style>\n");
            writer.write("body { font-family: Arial, sans-serif; margin: 20px; }\n");
            writer.write("table { border-collapse: collapse; width: 100%; }\n");
            writer.write("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
            writer.write("th { background-color: #333; color: white; }\n");
            writer.write("tr:nth-child(even) { background-color: #f2f2f2; }\n");
            writer.write(".enforced { background-color: #ccff99 !important; }\n");
            writer.write(".bypassed { background-color: #ff9999 !important; }\n");
            writer.write(".undetermined { background-color: #ffcc99 !important; }\n");
            writer.write(".disabled { background-color: #d3d3d3 !important; }\n");
            writer.write("</style>\n");
            writer.write("</head>\n<body>\n");

            writer.write("<h1>Crimson Authorizer Results</h1>\n");
            writer.write("<p>Total: " + results.size() + " requests tested</p>\n");

            // Summary
            int enforced = 0, bypassed = 0, undetermined = 0;
            for (AuthorizationResult r : results) {
                switch (r.getWorstStatus()) {
                    case ENFORCED: enforced++; break;
                    case BYPASSED: bypassed++; break;
                    case UNDETERMINED: undetermined++; break;
                    default: break;
                }
            }

            writer.write("<div style=\"margin: 10px 0;\">");
            writer.write("<span class=\"enforced\" style=\"padding: 5px 10px; margin-right: 10px;\">Enforced: " + enforced + "</span>");
            writer.write("<span class=\"bypassed\" style=\"padding: 5px 10px; margin-right: 10px;\">Bypassed: " + bypassed + "</span>");
            writer.write("<span class=\"undetermined\" style=\"padding: 5px 10px;\">Undetermined: " + undetermined + "</span>");
            writer.write("</div>\n");

            // Results table header
            StringBuilder headerRow = new StringBuilder("<tr><th>ID</th><th>Method</th><th>URL</th><th>Orig Len</th><th>Status</th><th>Unauth</th>");
            for (String userName : userList) {
                headerRow.append("<th>").append(escapeHtml(userName)).append("</th>");
            }
            headerRow.append("</tr>\n");
            writer.write("<table>\n");
            writer.write(headerRow.toString());

            for (AuthorizationResult result : results) {
                String cssClass = getCssClass(result.getWorstStatus());
                writer.write("<tr>");
                writer.write("<td>" + result.getId() + "</td>");
                writer.write("<td>" + escapeHtml(result.getMethod()) + "</td>");
                writer.write("<td>" + escapeHtml(result.getUrl()) + "</td>");
                writer.write("<td>" + result.getOriginalResponseLength() + "</td>");
                writer.write("<td class=\"" + cssClass + "\">" + escapeHtml(result.getWorstStatus().getDisplayText()) + "</td>");
                writer.write("<td class=\"" + (result.getUnauthenticatedStatus() != null ? getCssClass(result.getUnauthenticatedStatus()) : "") + "\">"
                        + (result.getUnauthenticatedStatus() != null ? escapeHtml(result.getUnauthenticatedStatus().getDisplayText()) : "") + "</td>");

                // Per-user status columns
                for (String userName : userList) {
                    AuthorizationResult.UserTestResult ur = result.getUserResults().get(userName);
                    if (ur != null) {
                        writer.write("<td class=\"" + getCssClass(ur.getStatus()) + "\">"
                                + escapeHtml(ur.getStatus().getDisplayText()) + "</td>");
                    } else {
                        writer.write("<td></td>");
                    }
                }

                writer.write("</tr>\n");
            }

            writer.write("</table>\n");
            writer.write("</body>\n</html>\n");
        }
    }

    private static String getCssClass(EnforcementStatus status) {
        if (status == null) return "";
        switch (status) {
            case ENFORCED: return "enforced";
            case BYPASSED: return "bypassed";
            case UNDETERMINED: return "undetermined";
            case DISABLED: return "disabled";
            default: return "";
        }
    }

    private static String escapeCsv(String value) {
        if (value == null) return "";
        // Prevent Excel formula injection (leading =, +, -, @)
        if (!value.isEmpty() && "+-=@".indexOf(value.charAt(0)) >= 0) {
            value = "'" + value;
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private static String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }
}
