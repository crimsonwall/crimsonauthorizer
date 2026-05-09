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
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import org.parosproxy.paros.Constant;
import com.crimsonwall.crimsonauthorizer.AuthCredentials;
import com.crimsonwall.crimsonauthorizer.config.CrimsonAutorizeOptions;

/** UI panel for managing test users and their credentials. */
public final class UserManagementPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final UsersTableModel usersTableModel;
    private final JTable usersTable;
    private final transient CrimsonAutorizeOptions options;
    private transient Runnable usersChangedCallback;
    private transient UserRenameCallback userRenameCallback;

    private JButton editButton;
    private JButton removeButton;
    private JButton duplicateButton;
    private JButton renameButton;

    /** Callback for handling user renames across results. */
    public interface UserRenameCallback {
        void renameUser(String oldName, String newName);
    }

    public UserManagementPanel() {
        this(null);
    }

    public UserManagementPanel(CrimsonAutorizeOptions options) {
        this.options = options;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top section: Users table with toolbar
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        // Toolbar with buttons
        JPanel toolbar = createToolbar();
        topPanel.add(toolbar, BorderLayout.NORTH);

        // Users table
        usersTableModel = new UsersTableModel();
        usersTableModel.setOnEnabledChanged(this::notifyUsersChanged);
        usersTable = new JTable(usersTableModel);
        usersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        usersTable.getTableHeader().setReorderingAllowed(false);

        // Set column widths - User name and Enabled should be small, Headers should take majority
        usersTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // User name
        usersTable.getColumnModel().getColumn(0).setMaxWidth(150);
        usersTable.getColumnModel().getColumn(1).setPreferredWidth(60);   // Enabled
        usersTable.getColumnModel().getColumn(1).setMaxWidth(80);
        usersTable.getColumnModel().getColumn(2).setPreferredWidth(500); // Headers - takes most space

        // Set custom renderer for headers column to show tooltips
        usersTable.getColumnModel().getColumn(2).setCellRenderer(new HeadersCellRenderer());

        usersTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtonStates();
            }
        });

        // Double-click to edit user
        usersTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    editUser();
                }
            }
        });

        JScrollPane usersScrollPane = new JScrollPane(usersTable);
        usersScrollPane.setBorder(BorderFactory.createTitledBorder(
                Constant.messages.getString("crimsonautorize.users.title")));
        topPanel.add(usersScrollPane, BorderLayout.CENTER);

        // Populate table from persisted options (handles session reload case)
        if (options != null) {
            usersTableModel.setUsers(options.getUsers());
        }

        add(topPanel, BorderLayout.NORTH);
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 4));

        // Action buttons grouped in a JToolBar for native separator support
        JToolBar actionsBar = new JToolBar();
        actionsBar.setFloatable(false);

        JButton addButton = new JButton(Constant.messages.getString("crimsonautorize.users.add"));
        editButton = new JButton(Constant.messages.getString("crimsonautorize.users.edit"));
        removeButton = new JButton(Constant.messages.getString("crimsonautorize.users.remove"));
        duplicateButton = new JButton(Constant.messages.getString("crimsonautorize.users.duplicate"));
        renameButton = new JButton(Constant.messages.getString("crimsonautorize.users.rename"));

        addButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.addUser"));
        editButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.editUser"));
        removeButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.removeUser"));
        duplicateButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.duplicateUser"));
        renameButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.renameUser"));

        addButton.addActionListener(e -> addUser());
        editButton.addActionListener(e -> editUser());
        removeButton.addActionListener(e -> removeUser());
        duplicateButton.addActionListener(e -> duplicateUser());
        renameButton.addActionListener(e -> renameUser());

        editButton.setEnabled(false);
        removeButton.setEnabled(false);
        duplicateButton.setEnabled(false);
        renameButton.setEnabled(false);

        actionsBar.add(addButton);
        actionsBar.addSeparator();
        actionsBar.add(editButton);
        actionsBar.addSeparator();
        actionsBar.add(removeButton);
        actionsBar.addSeparator();
        actionsBar.add(duplicateButton);
        actionsBar.addSeparator();
        actionsBar.add(renameButton);

        toolbar.add(actionsBar, BorderLayout.CENTER);

        return toolbar;
    }

    private void updateButtonStates() {
        boolean hasSelection = usersTable.getSelectedRow() >= 0;
        editButton.setEnabled(hasSelection);
        removeButton.setEnabled(hasSelection);
        duplicateButton.setEnabled(hasSelection);
        renameButton.setEnabled(hasSelection);
    }

    private void addUser() {
        AddUserDialog dialog = new AddUserDialog(this);
        dialog.setVisible(true);

        AuthCredentials creds = dialog.getCredentials();
        if (creds != null && creds.getUserName() != null && !creds.getUserName().trim().isEmpty()) {
            // Check for duplicate user name
            for (AuthCredentials existing : usersTableModel.getUsers()) {
                if (existing.getUserName().equals(creds.getUserName())) {
                    JOptionPane.showMessageDialog(this,
                            Constant.messages.getString("crimsonautorize.dialog.addUser.error.duplicateUser"),
                            Constant.messages.getString("crimsonautorize.dialog.addUser.error.validation"),
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            usersTableModel.addUser(creds);

            if (options != null) {
                options.addUser(creds);
            }

            // Select the new user
            int newIndex = usersTableModel.getRowCount() - 1;
            usersTable.setRowSelectionInterval(newIndex, newIndex);

            notifyUsersChanged();
            warnIfDuplicateTokens();
        }
    }

    private void removeUser() {
        int idx = usersTable.getSelectedRow();
        if (idx < 0) {
            JOptionPane.showMessageDialog(this,
                    Constant.messages.getString("crimsonautorize.users.error.noSelection"),
                    Constant.messages.getString("crimsonautorize.users.error.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        AuthCredentials creds = usersTableModel.getUserAt(idx);
        String userName = creds != null ? creds.getUserName() : "";

        int confirm = JOptionPane.showConfirmDialog(
                this,
                Constant.messages.getString("crimsonautorize.dialog.removeUser.message", userName),
                Constant.messages.getString("crimsonautorize.dialog.removeUser.title"),
                JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            usersTableModel.removeUser(idx);

            if (options != null) {
                options.removeUser(userName);
            }

            int rowCount = usersTableModel.getRowCount();
            if (rowCount > 0) {
                int newIdx = Math.min(idx, rowCount - 1);
                usersTable.setRowSelectionInterval(newIdx, newIdx);
            }

            notifyUsersChanged();
        }
    }

    private void duplicateUser() {
        int idx = usersTable.getSelectedRow();
        if (idx < 0) {
            JOptionPane.showMessageDialog(this,
                    Constant.messages.getString("crimsonautorize.users.error.noSelection"),
                    Constant.messages.getString("crimsonautorize.users.error.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        AuthCredentials originalCreds = usersTableModel.getUserAt(idx);
        if (originalCreds == null) return;

        String name = (String) JOptionPane.showInputDialog(
                this,
                Constant.messages.getString("crimsonautorize.dialog.duplicateUser.prompt"),
                Constant.messages.getString("crimsonautorize.dialog.duplicateUser.title"),
                JOptionPane.PLAIN_MESSAGE,
                null, null, originalCreds.getUserName() + " (copy)");

        if (name == null || name.trim().isEmpty()) return;

        AuthCredentials newCreds = new AuthCredentials(name.trim());
        newCreds.setEnabled(originalCreds.isEnabled());

        for (AuthCredentials.HeaderEntry header : originalCreds.getHeaders()) {
            newCreds.addHeader(header.getName(), header.getValue());
        }

        usersTableModel.addUser(newCreds);

        if (options != null) {
            options.addUser(newCreds);
        }

        usersTable.setRowSelectionInterval(idx, idx);

        notifyUsersChanged();
    }

    private void renameUser() {
        int idx = usersTable.getSelectedRow();
        if (idx < 0) {
            JOptionPane.showMessageDialog(this,
                    Constant.messages.getString("crimsonautorize.users.error.noSelection"),
                    Constant.messages.getString("crimsonautorize.users.error.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        AuthCredentials creds = usersTableModel.getUserAt(idx);
        if (creds == null) return;

        String oldName = creds.getUserName();
        String newName = (String) JOptionPane.showInputDialog(
                this,
                Constant.messages.getString("crimsonautorize.dialog.renameUser.prompt"),
                Constant.messages.getString("crimsonautorize.dialog.renameUser.title"),
                JOptionPane.PLAIN_MESSAGE,
                null, null, oldName);

        if (newName == null || newName.trim().isEmpty()) return;

        String trimmedName = newName.trim();

        // Update the credentials object
        creds.setUserName(trimmedName);

        // Update the table model to reflect the change immediately
        usersTableModel.fireTableRowsUpdated(idx, idx);

        // Update in the options persistence
        if (options != null) {
            options.removeUser(oldName);
            options.addUser(creds);
        }

        // Notify extension to rename user in existing results
        if (userRenameCallback != null) {
            userRenameCallback.renameUser(oldName, trimmedName);
        }

        notifyUsersChanged();
    }

    private void editUser() {
        int idx = usersTable.getSelectedRow();
        if (idx < 0) {
            JOptionPane.showMessageDialog(this,
                    Constant.messages.getString("crimsonautorize.users.error.noSelection"),
                    Constant.messages.getString("crimsonautorize.users.error.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        AuthCredentials originalCreds = usersTableModel.getUserAt(idx);
        if (originalCreds == null) return;

        EditUserDialog dialog = new EditUserDialog(this, originalCreds);
        dialog.setVisible(true);

        AuthCredentials updatedCreds = dialog.getCredentials();
        if (updatedCreds != null) {
            // Update the credentials
            originalCreds.setUserName(updatedCreds.getUserName());
            originalCreds.setEnabled(updatedCreds.isEnabled());
            originalCreds.getHeaders().clear();
            for (AuthCredentials.HeaderEntry header : updatedCreds.getHeaders()) {
                originalCreds.addHeader(header.getName(), header.getValue());
            }

            usersTableModel.fireTableRowsUpdated(idx, idx);
            notifyUsersChanged();
            warnIfDuplicateTokens();
        }
    }

    public List<AuthCredentials> getUsers() {
        return usersTableModel.getUsers();
    }

    public void setUsers(List<AuthCredentials> users) {
        usersTableModel.setUsers(users);
        updateButtonStates();
    }

    public void setUsersChangedCallback(Runnable callback) {
        this.usersChangedCallback = callback;
    }

    public void setUserRenameCallback(UserRenameCallback callback) {
        this.userRenameCallback = callback;
    }

    private void notifyUsersChanged() {
        if (usersChangedCallback != null) {
            usersChangedCallback.run();
        }
    }

    /**
     * Warns if any two different users share an identical non-empty header value for the same
     * header name. This catches copy/paste errors where a token was accidentally reused.
     */
    private void warnIfDuplicateTokens() {
        List<AuthCredentials> allUsers = usersTableModel.getUsers();

        // headerName → headerValue → list of user names that carry that exact value
        Map<String, Map<String, List<String>>> headerValueUsers = new LinkedHashMap<>();
        for (AuthCredentials user : allUsers) {
            for (AuthCredentials.HeaderEntry header : user.getHeaders()) {
                String value = header.getValue();
                if (value == null || value.trim().isEmpty()) {
                    continue;
                }
                headerValueUsers
                        .computeIfAbsent(header.getName(), k -> new LinkedHashMap<>())
                        .computeIfAbsent(value, k -> new ArrayList<>())
                        .add(user.getUserName());
            }
        }

        List<String> warnings = new ArrayList<>();
        for (Map.Entry<String, Map<String, List<String>>> headerEntry : headerValueUsers.entrySet()) {
            for (Map.Entry<String, List<String>> valueEntry : headerEntry.getValue().entrySet()) {
                List<String> userNames = valueEntry.getValue();
                if (userNames.size() > 1) {
                    warnings.add(Constant.messages.getString(
                            "crimsonautorize.warning.duplicateToken.item",
                            headerEntry.getKey(),
                            String.join(", ", userNames)));
                }
            }
        }

        if (warnings.isEmpty()) {
            return;
        }

        StringBuilder msg = new StringBuilder(
                Constant.messages.getString("crimsonautorize.warning.duplicateToken.header"));
        msg.append("\n\n");
        for (String w : warnings) {
            msg.append(w).append("\n");
        }
        msg.append("\n");
        msg.append(Constant.messages.getString("crimsonautorize.warning.duplicateToken.footer"));
        JOptionPane.showMessageDialog(
                this,
                msg.toString(),
                Constant.messages.getString("crimsonautorize.warning.duplicateToken.title"),
                JOptionPane.WARNING_MESSAGE);
    }

    /** Table model for the users list. */
    private static class UsersTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;
        private final transient List<AuthCredentials> users = new ArrayList<>();
        private transient Runnable onEnabledChanged;

        @Override
        public int getRowCount() {
            return users.size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return Constant.messages.getString("crimsonautorize.label.userName");
                case 1:
                    return Constant.messages.getString("crimsonautorize.users.column.enabled");
                case 2:
                    return Constant.messages.getString("crimsonautorize.users.column.headers");
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == 1 ? Boolean.class : String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            AuthCredentials creds = users.get(rowIndex);
            if (creds == null) return null;

            switch (columnIndex) {
                case 0:
                    return creds.getUserName();
                case 1:
                    return creds.isEnabled();
                case 2:
                    return formatHeaders(creds);
                default:
                    return null;
            }
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 1; // Only the enabled checkbox is editable
        }

        public void setOnEnabledChanged(Runnable callback) {
            this.onEnabledChanged = callback;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 1 && aValue instanceof Boolean) {
                AuthCredentials creds = users.get(rowIndex);
                if (creds != null) {
                    creds.setEnabled((Boolean) aValue);
                    fireTableRowsUpdated(rowIndex, rowIndex);
                    if (onEnabledChanged != null) {
                        onEnabledChanged.run();
                    }
                }
            }
        }

        private String formatHeaders(AuthCredentials creds) {
            List<AuthCredentials.HeaderEntry> headers = creds.getHeaders();
            if (headers.isEmpty()) {
                return "";
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < headers.size(); i++) {
                AuthCredentials.HeaderEntry header = headers.get(i);
                if (sb.length() > 0) {
                    sb.append("; ");
                }
                sb.append(header.getName()).append(": ");

                // Show full value without truncation
                String value = header.getValue();
                sb.append(value != null ? value : "");
            }
            return sb.toString();
        }

        public List<AuthCredentials> getUsers() {
            return new ArrayList<>(users);
        }

        public void setUsers(List<AuthCredentials> users) {
            this.users.clear();

            // Use a map to track unique user names and prevent duplicates
            Map<String, AuthCredentials> uniqueUsers = new java.util.LinkedHashMap<>();
            for (AuthCredentials user : users) {
                String userName = user.getUserName();
                if (userName != null && !uniqueUsers.containsKey(userName)) {
                    uniqueUsers.put(userName, user);
                }
            }

            this.users.addAll(uniqueUsers.values());
            fireTableDataChanged();
        }

        public boolean addUser(AuthCredentials user) {
            // Check for duplicate user names
            for (AuthCredentials existing : users) {
                if (existing.getUserName().equals(user.getUserName())) {
                    return false; // User already exists
                }
            }
            users.add(user);
            fireTableRowsInserted(users.size() - 1, users.size() - 1);
            return true;
        }

        public void removeUser(int index) {
            if (index >= 0 && index < users.size()) {
                users.remove(index);
                fireTableRowsDeleted(index, index);
            }
        }

        public AuthCredentials getUserAt(int index) {
            if (index >= 0 && index < users.size()) {
                return users.get(index);
            }
            return null;
        }
    }

    /** Dialog for adding a new user. */
    private static class AddUserDialog extends JDialog {

        private static final long serialVersionUID = 1L;
        private transient AuthCredentials resultCredentials = null;
        private final JTextField userNameField;
        private final JTextArea rawHeadersArea;
        private final DefaultTableModel headerTableModel;
        private final JCheckBox enabledCheckBox;

        public AddUserDialog(Component parent) {
            super(JOptionPane.getFrameForComponent(parent),
                    Constant.messages.getString("crimsonautorize.dialog.addUser.title"), true);
            setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
            setLocationRelativeTo(parent);

            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(4, 8, 4, 8);

            // Username field with enabled checkbox
            JPanel namePanel = new JPanel(new GridBagLayout());
            namePanel.setBorder(BorderFactory.createTitledBorder(
                    Constant.messages.getString("crimsonautorize.label.userName")));

            GridBagConstraints ngbc = new GridBagConstraints();
            ngbc.insets = new Insets(4, 4, 4, 4);
            ngbc.fill = GridBagConstraints.HORIZONTAL;
            ngbc.weightx = 1.0;

            ngbc.gridx = 0;
            ngbc.gridy = 0;
            userNameField = new JTextField();
            namePanel.add(userNameField, ngbc);

            ngbc.gridx = 1;
            ngbc.weightx = 0.0;
            enabledCheckBox = new JCheckBox(Constant.messages.getString("crimsonautorize.users.column.enabled"), true);
            namePanel.add(enabledCheckBox, ngbc);

            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.weightx = 1.0;
            add(namePanel, gbc);

            // Raw headers text area
            gbc.gridy = 1;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weighty = 0.3;
            JPanel rawPanel = new JPanel(new BorderLayout());
            rawPanel.setBorder(BorderFactory.createTitledBorder(
                    Constant.messages.getString("crimsonautorize.label.pasteHeaders")));
            rawHeadersArea = new JTextArea(5, 40);
            rawHeadersArea.setLineWrap(true);
            rawHeadersArea.setWrapStyleWord(true);
            JScrollPane rawScroll = new JScrollPane(rawHeadersArea);
            rawPanel.add(rawScroll, BorderLayout.CENTER);

            JButton parseButton = new JButton(Constant.messages.getString("crimsonautorize.dialog.addUser.parseHeaders"));
            parseButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.parseHeaders"));
            parseButton.addActionListener(e -> parseRawHeaders());
            rawPanel.add(parseButton, BorderLayout.SOUTH);

            add(rawPanel, gbc);

            // Headers table
            gbc.gridy = 2;
            gbc.weighty = 0.7;
            JPanel tablePanel = new JPanel(new BorderLayout());
            tablePanel.setBorder(BorderFactory.createTitledBorder(
                    Constant.messages.getString("crimsonautorize.label.parsedHeaders")));
            headerTableModel = new DefaultTableModel(
                    new Object[]{
                        Constant.messages.getString("crimsonautorize.label.headerName"),
                        Constant.messages.getString("crimsonautorize.label.headerValue")
                    }, 0);
            JTable headerTable = new JTable(headerTableModel);
            JScrollPane tableScroll = new JScrollPane(headerTable);
            tablePanel.add(tableScroll, BorderLayout.CENTER);

            JPanel tableButtonPanel = new JPanel();
            JButton addHeaderBtn = new JButton(
                    Constant.messages.getString("crimsonautorize.users.header.addHeader"));
            JButton removeHeaderBtn = new JButton(
                    Constant.messages.getString("crimsonautorize.users.header.removeHeader"));

            addHeaderBtn.addActionListener(e -> {
                headerTableModel.addRow(new Object[]{"", ""});
            });

            removeHeaderBtn.addActionListener(e -> {
                int row = headerTable.getSelectedRow();
                if (row >= 0) {
                    headerTableModel.removeRow(row);
                }
            });

            tableButtonPanel.add(addHeaderBtn);
            tableButtonPanel.add(removeHeaderBtn);
            tablePanel.add(tableButtonPanel, BorderLayout.SOUTH);

            add(tablePanel, gbc);

            // Bottom buttons
            gbc.gridy = 3;
            gbc.fill = GridBagConstraints.NONE;
            gbc.weighty = 0.0;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.insets = new Insets(8, 8, 8, 8);
            JPanel buttonPanel = new JPanel();
            JButton okButton = new JButton(Constant.messages.getString("crimsonautorize.dialog.ok"));
            JButton cancelButton = new JButton(Constant.messages.getString("crimsonautorize.dialog.cancel"));

            okButton.addActionListener(new OkListener());
            cancelButton.addActionListener(e -> dispose());

            buttonPanel.add(okButton);
            buttonPanel.add(cancelButton);
            add(buttonPanel, gbc);

            pack();
            setSize(550, Math.max(500, getHeight()));
        }

        private void parseRawHeaders() {
            String rawText = rawHeadersArea.getText().trim();
            if (rawText.isEmpty()) {
                return;
            }

            String[] lines = rawText.split("\\r?\\n");
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String name = line.substring(0, colonIdx).trim();
                    String value = line.substring(colonIdx + 1).trim();

                    boolean found = false;
                    for (int i = 0; i < headerTableModel.getRowCount(); i++) {
                        String existingName = (String) headerTableModel.getValueAt(i, 0);
                        if (existingName != null && existingName.equalsIgnoreCase(name)) {
                            headerTableModel.setValueAt(value, i, 1);
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        headerTableModel.addRow(new Object[]{name, value});
                    }
                }
            }

            rawHeadersArea.setText("");
        }

        public AuthCredentials getCredentials() {
            return resultCredentials;
        }

        private class OkListener implements ActionListener {
            @Override
            public void actionPerformed(ActionEvent e) {
                String userName = userNameField.getText().trim();
                if (userName.isEmpty()) {
                    JOptionPane.showMessageDialog(AddUserDialog.this,
                            Constant.messages.getString("crimsonautorize.dialog.addUser.error.missingName"),
                            Constant.messages.getString("crimsonautorize.dialog.addUser.error.validation"),
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                resultCredentials = new AuthCredentials(userName);
                resultCredentials.setEnabled(enabledCheckBox.isSelected());

                for (int i = 0; i < headerTableModel.getRowCount(); i++) {
                    String name = (String) headerTableModel.getValueAt(i, 0);
                    String value = (String) headerTableModel.getValueAt(i, 1);
                    if (name != null && !name.trim().isEmpty()) {
                        resultCredentials.addHeader(name.trim(), value != null ? value : "");
                    }
                }

                dispose();
            }
        }
    }

    /** Dialog for editing an existing user. */
    private static class EditUserDialog extends JDialog {

        private static final long serialVersionUID = 1L;
        private transient AuthCredentials resultCredentials = null;
        private final JTextField userNameField;
        private final JTextArea rawHeadersArea;
        private final DefaultTableModel headerTableModel;
        private final JCheckBox enabledCheckBox;

        public EditUserDialog(Component parent, AuthCredentials originalCreds) {
            super(JOptionPane.getFrameForComponent(parent),
                    Constant.messages.getString("crimsonautorize.dialog.addUser.title"), true);
            setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
            setLocationRelativeTo(parent);

            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(4, 8, 4, 8);

            // Username field with enabled checkbox
            JPanel namePanel = new JPanel(new GridBagLayout());
            namePanel.setBorder(BorderFactory.createTitledBorder(
                    Constant.messages.getString("crimsonautorize.label.userName")));

            GridBagConstraints ngbc = new GridBagConstraints();
            ngbc.insets = new Insets(4, 4, 4, 4);
            ngbc.fill = GridBagConstraints.HORIZONTAL;
            ngbc.weightx = 1.0;

            ngbc.gridx = 0;
            ngbc.gridy = 0;
            userNameField = new JTextField(originalCreds.getUserName());
            namePanel.add(userNameField, ngbc);

            ngbc.gridx = 1;
            ngbc.weightx = 0.0;
            enabledCheckBox = new JCheckBox(Constant.messages.getString("crimsonautorize.users.column.enabled"),
                    originalCreds.isEnabled());
            namePanel.add(enabledCheckBox, ngbc);

            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.weightx = 1.0;
            add(namePanel, gbc);

            // Raw headers text area
            gbc.gridy = 1;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weighty = 0.3;
            JPanel rawPanel = new JPanel(new BorderLayout());
            rawPanel.setBorder(BorderFactory.createTitledBorder(
                    Constant.messages.getString("crimsonautorize.label.pasteHeaders")));
            rawHeadersArea = new JTextArea(5, 40);
            rawHeadersArea.setLineWrap(true);
            rawHeadersArea.setWrapStyleWord(true);
            JScrollPane rawScroll = new JScrollPane(rawHeadersArea);
            rawPanel.add(rawScroll, BorderLayout.CENTER);

            JButton parseButton = new JButton(Constant.messages.getString("crimsonautorize.dialog.addUser.parseHeaders"));
            parseButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.parseHeaders"));
            parseButton.addActionListener(e -> parseRawHeaders());
            rawPanel.add(parseButton, BorderLayout.SOUTH);

            add(rawPanel, gbc);

            // Headers table - pre-populate with existing headers
            gbc.gridy = 2;
            gbc.weighty = 0.7;
            JPanel tablePanel = new JPanel(new BorderLayout());
            tablePanel.setBorder(BorderFactory.createTitledBorder(
                    Constant.messages.getString("crimsonautorize.label.parsedHeaders")));
            headerTableModel = new DefaultTableModel(
                    new Object[]{
                        Constant.messages.getString("crimsonautorize.label.headerName"),
                        Constant.messages.getString("crimsonautorize.label.headerValue")
                    }, 0);

            // Add existing headers to the table
            for (AuthCredentials.HeaderEntry header : originalCreds.getHeaders()) {
                headerTableModel.addRow(new Object[]{header.getName(), header.getValue()});
            }

            JTable headerTable = new JTable(headerTableModel);
            JScrollPane tableScroll = new JScrollPane(headerTable);
            tablePanel.add(tableScroll, BorderLayout.CENTER);

            JPanel tableButtonPanel = new JPanel();
            JButton addHeaderBtn = new JButton(
                    Constant.messages.getString("crimsonautorize.users.header.addHeader"));
            JButton removeHeaderBtn = new JButton(
                    Constant.messages.getString("crimsonautorize.users.header.removeHeader"));

            addHeaderBtn.addActionListener(e -> {
                headerTableModel.addRow(new Object[]{"", ""});
            });

            removeHeaderBtn.addActionListener(e -> {
                int row = headerTable.getSelectedRow();
                if (row >= 0) {
                    headerTableModel.removeRow(row);
                }
            });

            tableButtonPanel.add(addHeaderBtn);
            tableButtonPanel.add(removeHeaderBtn);
            tablePanel.add(tableButtonPanel, BorderLayout.SOUTH);

            add(tablePanel, gbc);

            // Bottom buttons
            gbc.gridy = 3;
            gbc.fill = GridBagConstraints.NONE;
            gbc.weighty = 0.0;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.insets = new Insets(8, 8, 8, 8);
            JPanel buttonPanel = new JPanel();
            JButton okButton = new JButton(Constant.messages.getString("crimsonautorize.dialog.ok"));
            JButton cancelButton = new JButton(Constant.messages.getString("crimsonautorize.dialog.cancel"));

            okButton.addActionListener(new OkListener());
            cancelButton.addActionListener(e -> dispose());

            buttonPanel.add(okButton);
            buttonPanel.add(cancelButton);
            add(buttonPanel, gbc);

            pack();
            setSize(550, Math.max(500, getHeight()));
        }

        private void parseRawHeaders() {
            String rawText = rawHeadersArea.getText().trim();
            if (rawText.isEmpty()) {
                return;
            }

            String[] lines = rawText.split("\\r?\\n");
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String name = line.substring(0, colonIdx).trim();
                    String value = line.substring(colonIdx + 1).trim();

                    boolean found = false;
                    for (int i = 0; i < headerTableModel.getRowCount(); i++) {
                        String existingName = (String) headerTableModel.getValueAt(i, 0);
                        if (existingName != null && existingName.equalsIgnoreCase(name)) {
                            headerTableModel.setValueAt(value, i, 1);
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        headerTableModel.addRow(new Object[]{name, value});
                    }
                }
            }

            rawHeadersArea.setText("");
        }

        public AuthCredentials getCredentials() {
            return resultCredentials;
        }

        private class OkListener implements ActionListener {
            @Override
            public void actionPerformed(ActionEvent e) {
                String userName = userNameField.getText().trim();
                if (userName.isEmpty()) {
                    JOptionPane.showMessageDialog(EditUserDialog.this,
                            Constant.messages.getString("crimsonautorize.dialog.addUser.error.missingName"),
                            Constant.messages.getString("crimsonautorize.dialog.addUser.error.validation"),
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                resultCredentials = new AuthCredentials(userName);
                resultCredentials.setEnabled(enabledCheckBox.isSelected());

                for (int i = 0; i < headerTableModel.getRowCount(); i++) {
                    String name = (String) headerTableModel.getValueAt(i, 0);
                    String value = (String) headerTableModel.getValueAt(i, 1);
                    if (name != null && !name.trim().isEmpty()) {
                        resultCredentials.addHeader(name.trim(), value != null ? value : "");
                    }
                }

                dispose();
            }
        }
    }

    /** Cell renderer for the headers column that shows a tooltip with all headers. */
    private static class HeadersCellRenderer extends javax.swing.table.DefaultTableCellRenderer {

        private static final long serialVersionUID = 1L;

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int column) {

            Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);

            if (c instanceof javax.swing.JLabel) {
                javax.swing.JLabel label = (javax.swing.JLabel) c;

                // Get the AuthCredentials for this row
                int modelRow = table.convertRowIndexToModel(row);
                if (table.getModel() instanceof UsersTableModel) {
                    UsersTableModel model = (UsersTableModel) table.getModel();
                    AuthCredentials creds = model.getUserAt(modelRow);
                    if (creds != null && !creds.getHeaders().isEmpty()) {
                        // Build tooltip text with all headers
                        StringBuilder tooltip = new StringBuilder("<html>");
                        for (AuthCredentials.HeaderEntry header : creds.getHeaders()) {
                            if (tooltip.length() > 6) { // Skip "<html>"
                                tooltip.append("<br>");
                            }
                            tooltip.append("<b>").append(header.getName()).append(":</b> ")
                                   .append(header.getValue());
                        }
                        tooltip.append("</html>");
                        label.setToolTipText(tooltip.toString());
                    } else {
                        label.setToolTipText(null);
                    }
                }
            }

            return c;
        }
    }
}
