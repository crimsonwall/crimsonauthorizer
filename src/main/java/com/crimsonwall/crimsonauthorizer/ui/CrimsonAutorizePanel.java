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
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.network.HttpMessage;
import com.crimsonwall.crimsonauthorizer.AuthCredentials;
import com.crimsonwall.crimsonauthorizer.AuthorizationResult;
import com.crimsonwall.crimsonauthorizer.ExtensionCrimsonAutorize;
import com.crimsonwall.crimsonauthorizer.ResultsExportService;

/** Main UI panel for Crimson Authorizer authorization test results. */
public final class CrimsonAutorizePanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(CrimsonAutorizePanel.class);

    private final transient ExtensionCrimsonAutorize extension;
    private ResultsTableModel tableModel;
    private JTable resultsTable;
    private JToggleButton startStopButton;
    private JButton clearButton;
    private JButton exportButton;
    private JLabel statusLabel;

    // Message viewer components
    private HttpMessageViewer originalViewer;
    private HttpMessageViewer unauthenticatedViewer;
    private final transient java.util.Map<String, HttpMessageViewer> userViewers = new java.util.LinkedHashMap<>();
    private JTabbedPane mainTabs;
    private DnDTabbedPane messageViewersTabs;
    private ConfigurationPanel configurationPanel;
    private JPopupMenu tablePopupMenu;

    // Store the current result for popup menu access
    private transient AuthorizationResult currentResult;

    // Auto-scroll state
    private boolean autoScrollEnabled = true;
    private boolean programmaticSelectionChange = false;

    public CrimsonAutorizePanel(ExtensionCrimsonAutorize extension) {
        this.extension = extension;
        initialize();
        setIcon(ExtensionCrimsonAutorize.getIcon());
    }

    private void initialize() {
        setLayout(new BorderLayout());
        setName(Constant.messages.getString("crimsonautorize.panel.title"));

        mainTabs = new JTabbedPane();

        // Results tab
        JPanel resultsTab = new JPanel(new BorderLayout());
        resultsTab.add(createToolbar(), BorderLayout.NORTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setDividerLocation(300);
        mainSplit.setResizeWeight(0.4);
        mainSplit.setTopComponent(createResultsPanel());
        mainSplit.setBottomComponent(createMessageViewers());
        resultsTab.add(mainSplit, BorderLayout.CENTER);

        // Initialize user tabs after message viewers are created
        rebuildUserTabs();

        resultsTab.add(createStatusBar(), BorderLayout.SOUTH);

        mainTabs.addTab("Results", resultsTab);

        configurationPanel = new ConfigurationPanel(extension.getOptions(), this::refreshTableColumns,
                extension::renameUser);
        mainTabs.addTab("Users", configurationPanel);

        add(mainTabs, BorderLayout.CENTER);
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 4));

        // Action buttons grouped in a JToolBar for native separator support
        JToolBar actionsBar = new JToolBar();
        actionsBar.setFloatable(false);

        startStopButton = new JToggleButton(Constant.messages.getString("crimsonautorize.button.start"));
        startStopButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.startTesting"));
        startStopButton.setMnemonic(KeyEvent.VK_S);
        startStopButton.addActionListener(new StartStopListener());
        actionsBar.add(startStopButton);
        updateStartButtonState();

        actionsBar.addSeparator();

        clearButton = new JButton(Constant.messages.getString("crimsonautorize.button.clear"));
        clearButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.clearResults"));
        clearButton.setMnemonic(KeyEvent.VK_C);
        clearButton.setEnabled(false);
        clearButton.addActionListener(e -> clearResults());
        actionsBar.add(clearButton);

        exportButton = new JButton(Constant.messages.getString("crimsonautorize.button.export"));
        exportButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.exportResults"));
        exportButton.setMnemonic(KeyEvent.VK_E);
        exportButton.setEnabled(false);
        exportButton.addActionListener(new ExportListener());
        actionsBar.add(exportButton);

        toolbar.add(actionsBar, BorderLayout.CENTER);

        return toolbar;
    }

    private JPanel createResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        tableModel = new ResultsTableModel();
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.setDefaultRenderer(Object.class, new ResultsTableCellRenderer(tableModel));
        resultsTable.setDefaultRenderer(Integer.class, new ResultsTableCellRenderer(tableModel));
        resultsTable.getSelectionModel()
                .addListSelectionListener(
                        e -> {
                            if (!e.getValueIsAdjusting()) {
                                handleSelectionChange();
                            }
                        });

        addTablePopupMenu();

        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(45);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(400);

        JScrollPane scrollPane = new JScrollPane(resultsTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private void addTablePopupMenu() {
        tablePopupMenu = new JPopupMenu();

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopupIfNeeded(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopupIfNeeded(e);
            }

            private void showPopupIfNeeded(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                showTablePopupMenu(e);
            }
        });
    }

    private JPanel createMessageViewers() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        messageViewersTabs = new DnDTabbedPane();

        // Enable tab dragging/reordering
        messageViewersTabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        // Original tab (always first)
        JPanel originalPanel = new JPanel(new BorderLayout());
        originalViewer = new HttpMessageViewer();
        originalPanel.add(originalViewer, BorderLayout.CENTER);

        // Add popup menu to original viewer
        originalViewer.addPopupMenu(
                Constant.messages.getString("crimsonautorize.menu.sendOriginal"),
                () -> currentResult != null ? currentResult.getOriginalMessage() : null,
                Constant.messages.getString("crimsonautorize.menu.copyUrl"),
                () -> getUrlFromMessage(currentResult != null ? currentResult.getOriginalMessage() : null));

        messageViewersTabs.addTab(
                Constant.messages.getString("crimsonautorize.label.original"),
                originalPanel);

        // Unauthenticated tab (second, only if enabled in options)
        if (extension.getOptions().isTestUnauthenticated()) {
            JPanel unauthenticatedPanel = new JPanel(new BorderLayout());
            unauthenticatedViewer = new HttpMessageViewer();
            unauthenticatedPanel.add(unauthenticatedViewer, BorderLayout.CENTER);

            // Add popup menu to unauthenticated viewer
            unauthenticatedViewer.addPopupMenu(
                    Constant.messages.getString("crimsonautorize.menu.sendUnauth"),
                    () -> currentResult != null ? currentResult.getUnauthenticatedMessage() : null,
                    Constant.messages.getString("crimsonautorize.menu.copyUrl"),
                    () -> getUrlFromMessage(currentResult != null ? currentResult.getUnauthenticatedMessage() : null));

            messageViewersTabs.addTab(
                    Constant.messages.getString("crimsonautorize.label.unauthenticated"),
                    unauthenticatedPanel);
        }

        panel.add(messageViewersTabs, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createStatusBar() {
        JPanel panel = new JPanel(new BorderLayout());
        statusLabel = new JLabel(Constant.messages.getString("crimsonautorize.status.ready"));
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        panel.add(statusLabel, BorderLayout.WEST);
        return panel;
    }

    /** Add a new result to the table. Called from the EDT. */
    public void addResult(AuthorizationResult result) {
        tableModel.addResult(result);
        updateStatus();
        clearButton.setEnabled(true);
        exportButton.setEnabled(true);

        if (autoScrollEnabled) {
            int lastRow = resultsTable.getRowCount() - 1;
            programmaticSelectionChange = true;
            resultsTable.setRowSelectionInterval(lastRow, lastRow);
            resultsTable.scrollRectToVisible(resultsTable.getCellRect(lastRow, 0, true));
            programmaticSelectionChange = false;
        }
    }

    /**
     * Handles table selection changes to manage auto-scroll behavior.
     * Auto-scroll is enabled when the last row is selected, disabled otherwise.
     * Programmatic selection changes (from addResult) don't affect auto-scroll state.
     */
    private void handleSelectionChange() {
        // Ignore programmatic selection changes from addResult
        if (programmaticSelectionChange) {
            updateMessageViewers();
            return;
        }

        int selectedRow = resultsTable.getSelectedRow();
        int rowCount = resultsTable.getRowCount();

        if (selectedRow >= 0 && rowCount > 0) {
            // Check if the selected row is the last row
            boolean isLastRow = (selectedRow == rowCount - 1);

            // Enable auto-scroll only when user selects the last row
            autoScrollEnabled = isLastRow;

            LOGGER.debug("Selection changed to row {} of {}. Auto-scroll: {}",
                    selectedRow, rowCount - 1, autoScrollEnabled);
        }

        updateMessageViewers();
    }

    /** Called by the Clear button — shows confirmation dialog, then clears if confirmed. */
    public void clearResults() {
        int confirm =
                JOptionPane.showConfirmDialog(
                        this,
                        Constant.messages.getString("crimsonautorize.confirm.clear"),
                        Constant.messages.getString("crimsonautorize.confirm.clear.title"),
                        JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            extension.clearResults();
        }
    }

    /** Clears the table and viewers without showing a dialog. Called by extension.clearResults(). */
    public void clearTable() {
        tableModel.clearResults();
        originalViewer.clear();
        autoScrollEnabled = true;
        if (unauthenticatedViewer != null) {
            unauthenticatedViewer.clear();
        }
        for (HttpMessageViewer viewer : userViewers.values()) {
            viewer.clear();
        }
        clearButton.setEnabled(false);
        exportButton.setEnabled(false);
        updateStatus();
    }

    /** Refresh table columns when users change. */
    public void refreshTableColumns() {
        tableModel.setUsers(extension.getUsers());
        tableModel.setTestUnauthenticated(extension.getOptions().isTestUnauthenticated());
        tableModel.setMaxResults(extension.getOptions().getMaxResults());
        rebuildUserTabs();
        updateStartButtonState();
    }

    /** Enables or disables the Start button based on whether there is something to test. */
    private void updateStartButtonState() {
        if (startStopButton.isSelected()) {
            return;
        }
        boolean hasUsers = !extension.getUsers().isEmpty();
        boolean testUnauth = extension.getOptions().isTestUnauthenticated();
        startStopButton.setEnabled(hasUsers || testUnauth);
    }

    /** Rebuilds the user tabs when the user list changes. */
    private void rebuildUserTabs() {
        if (messageViewersTabs == null) {
            return;
        }

        // Remember the currently selected tab
        int selectedIndex = messageViewersTabs.getSelectedIndex();

        // Remove all tabs except Original (index 0)
        while (messageViewersTabs.getTabCount() > 1) {
            messageViewersTabs.remove(1);
        }
        userViewers.clear();

        // Add Unauthenticated tab if enabled
        boolean testUnauth = extension.getOptions().isTestUnauthenticated();
        if (testUnauth) {
            JPanel unauthenticatedPanel = new JPanel(new BorderLayout());
            unauthenticatedViewer = new HttpMessageViewer();
            unauthenticatedPanel.add(unauthenticatedViewer, BorderLayout.CENTER);

            // Add popup menu to unauthenticated viewer
            unauthenticatedViewer.addPopupMenu(
                    Constant.messages.getString("crimsonautorize.menu.sendUnauth"),
                    () -> currentResult != null ? currentResult.getUnauthenticatedMessage() : null,
                    Constant.messages.getString("crimsonautorize.menu.copyUrl"),
                    () -> getUrlFromMessage(currentResult != null ? currentResult.getUnauthenticatedMessage() : null));

            messageViewersTabs.addTab(
                    Constant.messages.getString("crimsonautorize.label.unauthenticated"),
                    unauthenticatedPanel);
        }

        // Add a tab for each user
        List<AuthCredentials> users = extension.getUsers();
        if (users == null || users.isEmpty()) {
            return;
        }

        for (AuthCredentials user : users) {
            String userName = user.getUserName();
            if (userName == null || userName.trim().isEmpty()) {
                continue;
            }
            JPanel userPanel = new JPanel(new BorderLayout());
            HttpMessageViewer viewer = new HttpMessageViewer();
            userPanel.add(viewer, BorderLayout.CENTER);

            // Add popup menu to user viewer
            final String finalUserName = userName;
            viewer.addPopupMenu(
                    Constant.messages.getString("crimsonautorize.menu.sendModified", userName),
                    () -> getUserMessage(finalUserName),
                    Constant.messages.getString("crimsonautorize.menu.copyUrl"),
                    () -> getUrlFromMessage(getUserMessage(finalUserName)));

            userViewers.put(userName, viewer);
            messageViewersTabs.addTab(userName, userPanel);
        }

        // Restore selection if possible, otherwise select Original
        if (selectedIndex >= 0 && selectedIndex < messageViewersTabs.getTabCount()) {
            messageViewersTabs.setSelectedIndex(selectedIndex);
        } else {
            messageViewersTabs.setSelectedIndex(0);
        }
    }

    /** Gets the modified message for a specific user from the current result. */
    private HttpMessage getUserMessage(String userName) {
        if (currentResult == null) {
            return null;
        }
        AuthorizationResult.UserTestResult userResult = currentResult.getUserResults().get(userName);
        return userResult != null ? userResult.getModifiedMessage() : null;
    }

    /** Get the configuration panel. */
    public ConfigurationPanel getConfigurationPanel() {
        return configurationPanel;
    }

    private void updateMessageViewers() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) {
            originalViewer.clear();
            if (unauthenticatedViewer != null) {
                unauthenticatedViewer.clear();
            }
            for (HttpMessageViewer viewer : userViewers.values()) {
                viewer.clear();
            }
            currentResult = null;
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AuthorizationResult result = tableModel.getResultAt(modelRow);
        if (result == null) {
            currentResult = null;
            return;
        }

        // Store current result for popup menu access
        currentResult = result;

        // Populate original viewer (no diff base)
        originalViewer.setMessage(result.getOriginalMessage(), null);

        // Populate unauthenticated viewer (if it exists)
        if (unauthenticatedViewer != null) {
            HttpMessage unauthMsg = result.getUnauthenticatedMessage();
            if (unauthMsg != null) {
                // Pass the original message as the diff base so header changes are highlighted
                unauthenticatedViewer.setMessage(unauthMsg, result.getOriginalMessage());
            } else {
                unauthenticatedViewer.clear();
            }
        }

        // Populate each user's viewer
        for (java.util.Map.Entry<String, HttpMessageViewer> entry : userViewers.entrySet()) {
            String userName = entry.getKey();
            HttpMessageViewer viewer = entry.getValue();
            AuthorizationResult.UserTestResult userResult = result.getUserResults().get(userName);

            if (userResult != null && userResult.getModifiedMessage() != null) {
                // Pass the original message as the diff base so header changes are highlighted
                viewer.setMessage(userResult.getModifiedMessage(), result.getOriginalMessage());
            } else {
                viewer.clear();
            }
        }
    }

    private String getUrlFromMessage(HttpMessage msg) {
        if (msg == null || msg.getRequestHeader() == null) {
            return null;
        }
        try {
            return msg.getRequestHeader().getURI().toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void showTablePopupMenu(MouseEvent e) {
        int row = resultsTable.rowAtPoint(e.getPoint());
        if (row < 0) return;

        resultsTable.setRowSelectionInterval(row, row);

        int modelRow = resultsTable.convertRowIndexToModel(row);
        AuthorizationResult result = tableModel.getResultAt(modelRow);
        if (result == null) return;

        // Resolve the model column under the pointer (accounts for column reordering).
        int viewCol = resultsTable.columnAtPoint(e.getPoint());
        int modelCol = viewCol >= 0 ? resultsTable.convertColumnIndexToModel(viewCol) : -1;
        String userNameAtColumn = modelCol >= 0 ? tableModel.getUserNameForColumn(modelCol) : null;

        // If the pointer is over a named-user column and that user has a modified message,
        // send the modified request; otherwise send the original.
        final HttpMessage messageToSend;
        if (userNameAtColumn != null) {
            AuthorizationResult.UserTestResult userResult =
                    result.getUserResults().get(userNameAtColumn);
            HttpMessage modified = userResult != null ? userResult.getModifiedMessage() : null;
            messageToSend = modified != null ? modified : result.getOriginalMessage();
        } else {
            messageToSend = result.getOriginalMessage();
        }

        // Clear and rebuild the popup menu contents
        tablePopupMenu.removeAll();

        JMenuItem sendToRequests = new JMenuItem(
                Constant.messages.getString("crimsonautorize.menu.sendToRequests"));
        sendToRequests.addActionListener(ev -> sendToRequestTab(messageToSend));
        tablePopupMenu.add(sendToRequests);

        JMenuItem copyUrlItem = new JMenuItem(
                Constant.messages.getString("crimsonautorize.menu.copyUrl"));
        copyUrlItem.addActionListener(ev -> copyUrlToClipboard(result.getOriginalMessage()));
        tablePopupMenu.add(copyUrlItem);

        tablePopupMenu.addSeparator();

        JMenuItem sendOriginal = new JMenuItem(
                Constant.messages.getString("crimsonautorize.menu.sendOriginal"));
        sendOriginal.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.sendOriginal"));
        sendOriginal.addActionListener(ev -> sendToRequestTab(result.getOriginalMessage()));
        tablePopupMenu.add(sendOriginal);

        if (result.getUnauthenticatedMessage() != null) {
            JMenuItem sendUnauth = new JMenuItem(
                    Constant.messages.getString("crimsonautorize.menu.sendUnauth"));
            sendUnauth.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.sendUnauth"));
            sendUnauth.addActionListener(ev -> sendToRequestTab(result.getUnauthenticatedMessage()));
            tablePopupMenu.add(sendUnauth);
        }

        for (Map.Entry<String, AuthorizationResult.UserTestResult> entry :
                result.getUserResults().entrySet()) {
            final HttpMessage modifiedMsg = entry.getValue().getModifiedMessage();
            if (modifiedMsg != null) {
                final String userName = entry.getKey();
                JMenuItem sendUser = new JMenuItem(
                        Constant.messages.getString("crimsonautorize.menu.sendModified", userName));
                sendUser.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.sendModified"));
                sendUser.addActionListener(ev -> sendToRequestTab(modifiedMsg));
                tablePopupMenu.add(sendUser);
            }
        }

        tablePopupMenu.show(resultsTable, e.getX(), e.getY());
    }

    private void sendToRequestTab(HttpMessage msg) {
        if (msg == null) return;
        try {
            // Try ExtensionRequester first (opens in the Requester tab)
            org.parosproxy.paros.control.Control control =
                    org.parosproxy.paros.control.Control.getSingleton();
            if (control != null) {
                Object requester =
                        control.getExtensionLoader().getExtension("ExtensionRequester");
                if (requester != null) {
                    try {
                        java.lang.reflect.Method method =
                                requester.getClass().getMethod("newRequesterPane", HttpMessage.class);
                        method.invoke(requester, msg);
                        return;
                    } catch (NoSuchMethodException ex) {
                        LOGGER.debug("newRequesterPane not found, trying displayMessage");
                        try {
                            java.lang.reflect.Method method =
                                    requester.getClass().getMethod("displayMessage",
                                            org.zaproxy.zap.extension.httppanel.Message.class);
                            method.invoke(requester, msg);
                            return;
                        } catch (Exception ex2) {
                            LOGGER.debug("displayMessage failed", ex2);
                        }
                    }
                }
            }

            // Fallback: show in main request panel
            org.parosproxy.paros.view.View.getSingleton().getRequestPanel().setMessage(msg);
        } catch (Exception ex) {
            LOGGER.error("Failed to send message to Request tab", ex);
        }
    }

    private void copyUrlToClipboard(HttpMessage msg) {
        String url = getUrlFromMessage(msg);
        if (url != null) {
            try {
                java.awt.datatransfer.StringSelection selection =
                        new java.awt.datatransfer.StringSelection(url);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(selection, selection);
            } catch (Exception ex) {
                LOGGER.error("Failed to copy URL to clipboard", ex);
            }
        }
    }

    private void updateStatus() {
        statusLabel.setText(Constant.messages.getString(
                "crimsonautorize.status.summary",
                String.valueOf(tableModel.getRowCount()),
                String.valueOf(tableModel.getEnforcedCount()),
                String.valueOf(tableModel.getBypassedCount()),
                String.valueOf(tableModel.getUndeterminedCount())));
    }

    public ResultsTableModel getTableModel() {
        return tableModel;
    }

    /** Start/Stop button listener. */
    private class StartStopListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (startStopButton.isSelected()) {
                extension.startTesting();
                startStopButton.setText(Constant.messages.getString("crimsonautorize.button.stop"));
                refreshTableColumns();
            } else {
                extension.stopTesting();
                startStopButton.setText(Constant.messages.getString("crimsonautorize.button.start"));
                updateStartButtonState();
            }
        }
    }

    /** Export button listener. */
    private class ExportListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            List<AuthorizationResult> allResults = tableModel.getAllResults();
            if (allResults.isEmpty()) {
                JOptionPane.showMessageDialog(
                        CrimsonAutorizePanel.this,
                        Constant.messages.getString("crimsonautorize.dialog.export.error.noResults"),
                        Constant.messages.getString("crimsonautorize.dialog.export.title"),
                        JOptionPane.WARNING_MESSAGE);
                return;
            }

            String[] options = {
                Constant.messages.getString("crimsonautorize.export.csv"),
                Constant.messages.getString("crimsonautorize.export.html")
            };
            int choice =
                    JOptionPane.showOptionDialog(
                            CrimsonAutorizePanel.this,
                            Constant.messages.getString("crimsonautorize.dialog.export.prompt"),
                            Constant.messages.getString("crimsonautorize.dialog.export.title"),
                            JOptionPane.DEFAULT_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            options,
                            options[0]);

            if (choice == 0) {
                exportCsv(allResults);
            } else if (choice == 1) {
                exportHtml(allResults);
            }
        }

        private void exportCsv(List<AuthorizationResult> results) {
            javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
            chooser.setSelectedFile(new java.io.File("crimsonautorize_results.csv"));
            if (chooser.showSaveDialog(CrimsonAutorizePanel.this) == javax.swing.JFileChooser.APPROVE_OPTION) {
                try {
                    ResultsExportService.exportToCsv(results, chooser.getSelectedFile());
                    JOptionPane.showMessageDialog(
                            CrimsonAutorizePanel.this,
                            Constant.messages.getString("crimsonautorize.dialog.export.success",
                                    chooser.getSelectedFile().getName()),
                            Constant.messages.getString("crimsonautorize.dialog.export.title"),
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                            CrimsonAutorizePanel.this,
                            Constant.messages.getString("crimsonautorize.dialog.export.error.failed",
                                    ex.getMessage()),
                            Constant.messages.getString("crimsonautorize.dialog.export.title"),
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }

        private void exportHtml(List<AuthorizationResult> results) {
            javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
            chooser.setSelectedFile(new java.io.File("crimsonautorize_results.html"));
            if (chooser.showSaveDialog(CrimsonAutorizePanel.this) == javax.swing.JFileChooser.APPROVE_OPTION) {
                try {
                    ResultsExportService.exportToHtml(results, chooser.getSelectedFile());
                    JOptionPane.showMessageDialog(
                            CrimsonAutorizePanel.this,
                            Constant.messages.getString("crimsonautorize.dialog.export.success",
                                    chooser.getSelectedFile().getName()),
                            Constant.messages.getString("crimsonautorize.dialog.export.title"),
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                            CrimsonAutorizePanel.this,
                            Constant.messages.getString("crimsonautorize.dialog.export.error.failed",
                                    ex.getMessage()),
                            Constant.messages.getString("crimsonautorize.dialog.export.title"),
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }
}
