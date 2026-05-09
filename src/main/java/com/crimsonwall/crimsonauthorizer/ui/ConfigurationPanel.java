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

import java.awt.BorderLayout;
import javax.swing.JPanel;
import com.crimsonwall.crimsonauthorizer.config.CrimsonAutorizeOptions;

public final class ConfigurationPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final UserManagementPanel userPanel;

    public ConfigurationPanel(CrimsonAutorizeOptions options, Runnable usersChangedCallback,
            UserManagementPanel.UserRenameCallback userRenameCallback) {
        setLayout(new BorderLayout());

        userPanel = new UserManagementPanel(options);
        if (usersChangedCallback != null) {
            userPanel.setUsersChangedCallback(usersChangedCallback);
        }
        if (userRenameCallback != null) {
            userPanel.setUserRenameCallback(userRenameCallback);
        }
        add(userPanel, BorderLayout.CENTER);
    }

    public UserManagementPanel getUserPanel() {
        return userPanel;
    }
}
