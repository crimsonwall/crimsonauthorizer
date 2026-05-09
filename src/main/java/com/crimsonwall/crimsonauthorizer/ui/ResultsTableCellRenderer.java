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

import java.awt.Color;
import java.awt.Component;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import com.crimsonwall.crimsonauthorizer.EnforcementStatus;

/** Color-coded cell renderer for enforcement status columns. */
public class ResultsTableCellRenderer extends DefaultTableCellRenderer {

    private static final long serialVersionUID = 1L;

    private static boolean isDarkTheme() {
        Color bg = UIManager.getColor("Table.background");
        if (bg == null) return false;
        double luminance = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return luminance < 128;
    }

    private static final boolean DARK = isDarkTheme();

    private static final Color COLOR_BYPASSED = DARK ? new Color(90, 40, 40) : new Color(255, 185, 185);
    private static final Color COLOR_UNDETERMINED = DARK ? new Color(90, 80, 30) : new Color(255, 255, 185);
    private static final Color COLOR_ENFORCED = DARK ? new Color(30, 60, 90) : new Color(185, 220, 255);
    private static final Color COLOR_DISABLED = DARK ? new Color(60, 60, 60) : new Color(211, 211, 211);
    private static final Color COLOR_SKIPPED = DARK ? new Color(60, 60, 60) : new Color(240, 240, 240);

    private final ResultsTableModel model;

    public ResultsTableCellRenderer(ResultsTableModel model) {
        this.model = model;
    }

    @Override
    public Component getTableCellRendererComponent(
            JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {

        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (!isSelected) {
            int modelRow = table.convertRowIndexToModel(row);
            int modelCol = table.convertColumnIndexToModel(column);

            EnforcementStatus status = model.getStatusAt(modelRow, modelCol);
            if (status != null) {
                c.setBackground(getColorForStatus(status));
            } else {
                c.setBackground(table.getBackground());
            }
        }

        return c;
    }

    public static Color getColorForStatus(EnforcementStatus status) {
        if (status == null) return null;
        switch (status) {
            case BYPASSED:
                return COLOR_BYPASSED;
            case UNDETERMINED:
                return COLOR_UNDETERMINED;
            case ENFORCED:
                return COLOR_ENFORCED;
            case DISABLED:
                return COLOR_DISABLED;
            case SKIPPED:
                return COLOR_SKIPPED;
            default:
                return null;
        }
    }
}
