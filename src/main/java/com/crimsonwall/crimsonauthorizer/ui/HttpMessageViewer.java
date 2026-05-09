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
import java.awt.Color;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * A panel that displays an HTTP message with Request and Response tabs,
 * using colour-based pretty printing. Headers modified compared to an original message
 * are highlighted. Supports toggle between horizontal and vertical layout.
 */
public final class HttpMessageViewer extends JPanel {

    private static final long serialVersionUID = 1L;

    // Maximum message size to render (prevents UI freeze on huge responses)
    private static final int MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB
    private static final int MAX_STATUS_URI_LENGTH = 500;

    // One Dark colour scheme
    private static final Color COLOR_BG = new Color(40, 44, 52);
    private static final Color COLOR_KEY = new Color(224, 108, 117);       // soft red
    private static final Color COLOR_STRING = new Color(152, 195, 127);    // green
    private static final Color COLOR_NUMBER = new Color(209, 154, 102);    // orange
    private static final Color COLOR_BOOL_NULL = new Color(198, 120, 221); // purple
    private static final Color COLOR_PUNCT = new Color(171, 178, 191);    // light gray
    private static final Color COLOR_STATUS_2XX = COLOR_STRING;
    private static final Color COLOR_STATUS_3XX = COLOR_NUMBER;
    private static final Color COLOR_STATUS_4XX = COLOR_KEY;
    private static final Color COLOR_OFFSET = new Color(92, 99, 112);   // dim gray

    // Highlight colours for modified/added headers
    private static final Color COLOR_MODIFIED_BG = new Color(80, 70, 20);  // dark yellow
    private static final Color COLOR_MODIFIED_FG = new Color(255, 200, 100); // orange
    private static final Color COLOR_ADDED_BG = new Color(20, 80, 20);     // dark green
    private static final Color COLOR_ADDED_FG = new Color(100, 255, 100); // green
    private static final Color COLOR_REMOVED_FG = new Color(255, 100, 100); // red

    private static final Font MONO_FONT = new Font("Monospaced", Font.PLAIN, 12);

    // Layout preference keys
    private static final String CONFIG_DIR = "crimsonautorize";
    private static final String CONFIG_FILE = "layout.xml";
    private static final String KEY_HORIZONTAL = "layout.horizontal";
    private static final String KEY_DIVIDER_RATIO = "layout.dividerRatio";

    private final JTextPane requestPane;
    private final JTextPane responsePane;
    private final transient StyledDocument requestDoc;
    private final transient StyledDocument responseDoc;

    // UI components for layout toggle
    private JSplitPane splitPane;
    private JPanel requestPanel;
    private JPanel responsePanel;
    private JButton toggleButton;
    private boolean horizontal;
    private Timer dividerSaveTimer;

    private static volatile ZapXmlConfiguration cachedConfig;

    // Colour attributes
    private final SimpleAttributeSet attrMethod;
    private final SimpleAttributeSet attrUrl;
    private final SimpleAttributeSet attrHeaderName;
    private final SimpleAttributeSet attrHeaderValue;
    private final SimpleAttributeSet attrBody;
    private final SimpleAttributeSet attrStatusCode;
    private final SimpleAttributeSet attrStatusText;
    private final SimpleAttributeSet attrPunct;
    private final SimpleAttributeSet attrModifiedBg;
    private final SimpleAttributeSet attrModifiedFg;
    private final SimpleAttributeSet attrAddedBg;
    private final SimpleAttributeSet attrAddedFg;

    public HttpMessageViewer() {
        horizontal = loadHorizontal();

        // Initialize colour attributes
        attrMethod = createStyle(COLOR_NUMBER);
        attrUrl = createStyle(COLOR_STRING);
        attrHeaderName = createStyle(COLOR_KEY);
        attrHeaderValue = createStyle(COLOR_STRING);
        attrBody = createStyle(new Color(180, 180, 180));
        attrStatusCode = createStyle(COLOR_KEY);
        attrStatusText = createStyle(new Color(100, 100, 100));
        attrPunct = createStyle(COLOR_PUNCT);
        attrModifiedBg = createStyle(COLOR_MODIFIED_FG, COLOR_MODIFIED_BG);
        attrModifiedFg = createStyle(COLOR_MODIFIED_FG, COLOR_MODIFIED_BG);
        attrAddedBg = createStyle(COLOR_ADDED_FG, COLOR_ADDED_BG);
        attrAddedFg = createStyle(COLOR_ADDED_FG, COLOR_ADDED_BG);

        // Create text panes
        requestPane = createTextPane();
        responsePane = createTextPane();
        requestDoc = requestPane.getStyledDocument();
        responseDoc = responsePane.getStyledDocument();

        initialize();
    }

    private void initialize() {
        setLayout(new BorderLayout());

        // Add toolbar with toggle button
        add(createToolbar(), BorderLayout.NORTH);

        // Create request and response panels
        requestPanel = createHalfPanel(true);
        responsePanel = createHalfPanel(false);

        // Build split pane
        splitPane = buildSplitPane();
        add(splitPane, BorderLayout.CENTER);

        updateToggleIcon();

        // Restore saved divider position once component has been laid out
        splitPane.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                applyDividerRatio();
                splitPane.removeAncestorListener(this);
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {}

            @Override
            public void ancestorMoved(AncestorEvent event) {}
        });
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JPanel buttons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));

        toggleButton = new JButton();
        toggleButton.setToolTipText("Toggle between horizontal and vertical layout");
        toggleButton.addActionListener(e -> toggleLayout());
        buttons.add(toggleButton);

        toolbar.add(buttons, BorderLayout.EAST);
        return toolbar;
    }

    private JPanel createHalfPanel(boolean isRequest) {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel label = new JLabel(isRequest ? "Request" : "Response");
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12.0f));
        label.setForeground(new Color(220, 20, 60));
        label.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        panel.add(label, BorderLayout.NORTH);

        JTextPane pane = isRequest ? requestPane : responsePane;
        panel.add(new JScrollPane(pane), BorderLayout.CENTER);

        return panel;
    }

    private JSplitPane buildSplitPane() {
        JSplitPane pane = new JSplitPane(
                horizontal ? JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT);
        pane.setResizeWeight(0.5);
        pane.setTopComponent(requestPanel);
        pane.setBottomComponent(responsePanel);

        dividerSaveTimer = new Timer(500, e -> {
            int divisor = horizontal ? splitPane.getWidth() : splitPane.getHeight();
            if (divisor > 0) {
                double ratio = (double) splitPane.getDividerLocation() / divisor;
                saveDividerRatio(ratio);
            }
        });
        dividerSaveTimer.setRepeats(false);
        pane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, evt -> dividerSaveTimer.restart());

        return pane;
    }

    private void applyDividerRatio() {
        double saved = loadDividerRatio();
        if (saved > 0.0 && saved < 1.0) {
            int size = horizontal ? splitPane.getWidth() : splitPane.getHeight();
            if (size > 0) {
                splitPane.setDividerLocation((int) (size * saved));
            }
        } else {
            splitPane.setDividerLocation(0.5);
        }
    }

    private void toggleLayout() {
        horizontal = !horizontal;
        saveHorizontal(horizontal);

        // Remember current divider position ratio
        int divisor = horizontal ? splitPane.getWidth() : splitPane.getHeight();
        double currentRatio = divisor > 0 ? (double) splitPane.getDividerLocation() / divisor : 0.5;

        remove(splitPane);
        splitPane = buildSplitPane();
        add(splitPane, BorderLayout.CENTER);
        updateToggleIcon();
        revalidate();
        repaint();

        SwingUtilities.invokeLater(() -> {
            int newSize = horizontal ? splitPane.getWidth() : splitPane.getHeight();
            if (newSize > 0) {
                splitPane.setDividerLocation((int) (newSize * currentRatio));
            }
        });
    }

    private void updateToggleIcon() {
        ImageIcon icon = horizontal ? getVerticalIcon() : getHorizontalIcon();
        if (icon != null) {
            toggleButton.setIcon(icon);
            toggleButton.setText(null);
        } else {
            toggleButton.setIcon(null);
            toggleButton.setText(horizontal ? "≡" : "∴");
        }
    }

    private static ImageIcon getVerticalIcon() {
        java.net.URL url = HttpMessageViewer.class.getResource("/icons/crimsonautorize-toggle-v.png");
        return url != null ? new ImageIcon(url) : null;
    }

    private static ImageIcon getHorizontalIcon() {
        java.net.URL url = HttpMessageViewer.class.getResource("/icons/crimsonautorize-toggle-h.png");
        return url != null ? new ImageIcon(url) : null;
    }

    /**
     * Displays an HTTP message with optional diff highlighting against an original.
     *
     * @param msg The message to display.
     * @param original The original message to diff against (null to skip diff).
     */
    public void setMessage(HttpMessage msg, HttpMessage original) {
        clear();
        if (msg == null) return;

        renderRequest(msg, original);
        renderResponse(msg, original);

        // Scroll both panes to top after rendering
        requestPane.setCaretPosition(0);
        responsePane.setCaretPosition(0);
    }

    /** Clears both panes. */
    public void clear() {
        try {
            requestDoc.remove(0, requestDoc.getLength());
            responseDoc.remove(0, responseDoc.getLength());
        } catch (Exception ignored) {
        }
    }

    /**
     * Adds a popup menu to the request and response panes.
     *
     * @param sendToRequesterText The text to display for the "Send to Requester" menu item
     * @param messageSupplier A supplier that provides the HttpMessage to send when the menu item is clicked
     * @param copyUrlText The text to display for the "Copy URL" menu item
     * @param urlSupplier A supplier that provides the URL to copy when the menu item is clicked
     */
    public void addPopupMenu(String sendToRequesterText, Supplier<HttpMessage> messageSupplier,
                             String copyUrlText, Supplier<String> urlSupplier) {
        addContextMenuToPane(requestPane, sendToRequesterText, messageSupplier, copyUrlText, urlSupplier);
        addContextMenuToPane(responsePane, sendToRequesterText, messageSupplier, copyUrlText, urlSupplier);
    }

    private void addContextMenuToPane(JTextPane pane, String sendToRequesterText,
            Supplier<HttpMessage> messageSupplier, String copyUrlText, Supplier<String> urlSupplier) {
        final JPopupMenu popup = new JPopupMenu();

        JMenuItem sendMenuItem = new JMenuItem(sendToRequesterText);
        sendMenuItem.addActionListener(e -> {
            HttpMessage msg = messageSupplier.get();
            if (msg != null) {
                sendToRequestTab(msg);
            }
        });
        popup.add(sendMenuItem);

        JMenuItem copyUrlItem = new JMenuItem(copyUrlText);
        copyUrlItem.addActionListener(e -> {
            String url = urlSupplier.get();
            if (url != null) {
                copyToClipboard(url);
            }
        });
        popup.add(copyUrlItem);

        pane.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopupIfNeeded(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopupIfNeeded(e);
            }

            private void showPopupIfNeeded(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    HttpMessage msg = messageSupplier.get();
                    String url = urlSupplier.get();
                    sendMenuItem.setEnabled(msg != null);
                    copyUrlItem.setEnabled(url != null);
                    popup.show(pane, e.getX(), e.getY());
                }
            }
        });
    }

    private void copyToClipboard(String text) {
        try {
            java.awt.datatransfer.StringSelection selection =
                    new java.awt.datatransfer.StringSelection(text);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(selection, selection);
        } catch (Exception ex) {
            // Ignore clipboard errors
        }
    }

    private void sendToRequestTab(HttpMessage msg) {
        try {
            org.parosproxy.paros.control.Control control =
                    org.parosproxy.paros.control.Control.getSingleton();
            if (control != null) {
                Object requester =
                        control.getExtensionLoader().getExtension("ExtensionRequester");
                if (requester != null) {
                    try {
                        java.lang.reflect.Method method =
                                requester.getClass().getMethod("displayMessage",
                                        org.zaproxy.zap.extension.httppanel.Message.class);
                        method.invoke(requester, msg);
                        return;
                    } catch (Exception ex) {
                        // Fall through to fallback
                    }
                }
            }
        } catch (Exception ex) {
            // Ignore errors
        }
    }

    // ---- Request rendering ----

    private void renderRequest(HttpMessage msg, HttpMessage original) {
        try {
            // Check total message size to prevent UI freeze
            int requestSize = msg.getRequestHeader().toString().length();
            if (msg.getRequestBody() != null) {
                requestSize += msg.getRequestBody().length();
            }
            if (requestSize > MAX_MESSAGE_SIZE) {
                append(requestDoc, "[Request too large to display: " + formatSize(requestSize) + "]\n", attrPunct);
                append(requestDoc, "Showing headers only:\n\n", attrBody);
                // Show just headers for large messages
                append(requestDoc, msg.getRequestHeader().toString(), attrHeaderValue);
                return;
            }

            // Request line: METHOD URI HTTP/version
            String method = msg.getRequestHeader().getMethod();
            String uri = msg.getRequestHeader().getURI().toString();
            String version = msg.getRequestHeader().getVersion();

            // Ensure version has HTTP/ prefix
            String requestVersion = version.toUpperCase().startsWith("HTTP/")
                    ? version : "HTTP/" + version;
            append(requestDoc, (method != null ? method : "GET"), attrMethod);
            append(requestDoc, " ", attrPunct);
            append(requestDoc, (uri != null ? truncate(uri, MAX_STATUS_URI_LENGTH) : "/"), attrUrl);
            append(requestDoc, " ", attrPunct);
            append(requestDoc, requestVersion + "\n", attrPunct);

            // Headers with diff
            Set<String> diffNames = original != null
                    ? collectHeaderDiff(msg.getRequestHeader(), original.getRequestHeader())
                    : new HashSet<>();

            String headersStr = msg.getRequestHeader().getHeadersAsString();

            // Parse headers and separate pragma/cache-control for display at bottom
            List<String[]> regularHeaders = new ArrayList<>();
            List<String[]> deferredHeaders = new ArrayList<>();

            for (String line : headersStr.split("\r\n")) {
                if (line.trim().isEmpty()) continue;
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String name = line.substring(0, colonIdx).trim();
                    String value = line.substring(colonIdx + 1);

                    // Defer pragma and cache-control headers to the end for easier comparison
                    if (name.equalsIgnoreCase("pragma") || name.equalsIgnoreCase("cache-control")) {
                        deferredHeaders.add(new String[]{name, value, line});
                    } else {
                        regularHeaders.add(new String[]{name, value, line});
                    }
                }
            }

            // Render regular headers first
            for (String[] header : regularHeaders) {
                renderHeader(header[0], header[1], header[2], diffNames, original, requestDoc, true);
            }

            // Then render deferred headers (pragma, cache-control) at the bottom
            for (String[] header : deferredHeaders) {
                renderHeader(header[0], header[1], header[2], diffNames, original, requestDoc, true);
            }

            // Blank line before body
            append(requestDoc, "\n", attrPunct);

            // Body
            if (msg.getRequestBody() != null && msg.getRequestBody().length() > 0) {
                append(requestDoc, msg.getRequestBody().toString(), attrBody);
            }
        } catch (Exception e) {
            append(requestDoc, "[Error rendering request: " + e.getMessage() + "]", attrPunct);
        }
    }

    /** Helper method to render a single header with diff highlighting. */
    private void renderHeader(String name, String value, String originalLine,
            Set<String> diffNames, HttpMessage original, StyledDocument doc, boolean isRequest) {
        boolean isModified = diffNames.contains(name);
        boolean wasInOriginal = original != null
                && (isRequest
                    ? original.getRequestHeader().getHeader(name) != null
                    : original.getResponseHeader().getHeader(name) != null);

        SimpleAttributeSet nameStyle;
        SimpleAttributeSet valueStyle;

        if (isModified) {
            if (wasInOriginal) {
                nameStyle = attrModifiedFg;
                valueStyle = attrModifiedFg;
            } else {
                nameStyle = attrAddedFg;
                valueStyle = attrAddedFg;
            }
        } else {
            nameStyle = attrHeaderName;
            valueStyle = attrHeaderValue;
        }

        append(doc, name + ":", nameStyle);
        append(doc, value + "\n", valueStyle);
    }

    // ---- Response rendering ----

    private void renderResponse(HttpMessage msg, HttpMessage original) {
        try {
            if (msg.getResponseHeader() == null
                    || msg.getResponseHeader().getStatusCode() <= 0) {
                append(responseDoc, "(No response)", attrBody);
                return;
            }

            // Check response size to prevent UI freeze
            int responseSize = msg.getResponseHeader().toString().length();
            if (msg.getResponseBody() != null) {
                responseSize += msg.getResponseBody().length();
            }
            if (responseSize > MAX_MESSAGE_SIZE) {
                append(responseDoc, "[Response too large to display: " + formatSize(responseSize) + "]\n", attrPunct);
                append(responseDoc, "Showing headers and status only:\n\n", attrBody);
                // Show just headers for large responses
                append(responseDoc, msg.getResponseHeader().toString(), attrHeaderValue);
                append(responseDoc, "\n[Body truncated: " + formatSize(msg.getResponseBody().length()) + "]\n", attrBody);
                return;
            }

            // Status line: HTTP/version statusCode reason
            String version = msg.getResponseHeader().getVersion();
            int statusCode = msg.getResponseHeader().getStatusCode();
            String reason = msg.getResponseHeader().getReasonPhrase();

            String responseVersion = version.toUpperCase().startsWith("HTTP/")
                    ? version : "HTTP/" + version;
            append(responseDoc, responseVersion + " ", attrPunct);
            append(responseDoc, String.valueOf(statusCode) + " ", getStatusAttr(statusCode));
            append(responseDoc, (reason != null ? reason : "") + "\n", attrStatusText);

            // Headers with diff
            Set<String> diffNames = original != null
                    ? collectHeaderDiff(msg.getResponseHeader(), original.getResponseHeader())
                    : new HashSet<>();

            String headersStr = msg.getResponseHeader().getHeadersAsString();
            List<String[]> regularHeaders = new ArrayList<>();
            List<String[]> deferredHeaders = new ArrayList<>();

            for (String line : headersStr.split("\r\n")) {
                if (line.trim().isEmpty()) continue;
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    String name = line.substring(0, colonIdx).trim();
                    String value = line.substring(colonIdx + 1);

                    // Defer pragma and cache-control headers to the end for easier comparison
                    if (name.equalsIgnoreCase("pragma") || name.equalsIgnoreCase("cache-control")) {
                        deferredHeaders.add(new String[]{name, value, line});
                    } else {
                        regularHeaders.add(new String[]{name, value, line});
                    }
                }
            }

            // Render regular headers first
            for (String[] header : regularHeaders) {
                renderHeader(header[0], header[1], header[2], diffNames, original, responseDoc, false);
            }

            // Then render deferred headers (pragma, cache-control) at the bottom
            for (String[] header : deferredHeaders) {
                renderHeader(header[0], header[1], header[2], diffNames, original, responseDoc, false);
            }

            // Blank line before body
            append(responseDoc, "\n", attrPunct);

            // Body
            if (msg.getResponseBody() != null && msg.getResponseBody().length() > 0) {
                append(responseDoc, msg.getResponseBody().toString(), attrBody);
            }
        } catch (Exception e) {
            append(responseDoc, "[Error rendering response: " + e.getMessage() + "]", attrPunct);
        }
    }

    // ---- Diff helpers ----

    /**
     * Collects header names that are new or have a different value compared to
     * the original.
     */
    private static Set<String> collectHeaderDiff(org.parosproxy.paros.network.HttpHeader current,
            org.parosproxy.paros.network.HttpHeader original) {
        Set<String> diff = new HashSet<>();
        String currentHeaders = current.getHeadersAsString();
        for (String line : currentHeaders.split("\r\n")) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String currentValue = line.substring(colonIdx + 1).trim();
                String originalValue = original.getHeader(name);
                if (originalValue == null || !originalValue.trim().equals(currentValue)) {
                    diff.add(name);
                }
            }
        }

        // Also check for headers removed in the modified message
        String originalHeaders = original.getHeadersAsString();
        for (String line : originalHeaders.split("\r\n")) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                if (current.getHeader(name) == null) {
                    diff.add(name);
                }
            }
        }

        return diff;
    }

    // ---- Style helpers ----

    private SimpleAttributeSet createStyle(Color fg) {
        SimpleAttributeSet s = new SimpleAttributeSet();
        StyleConstants.setFontFamily(s, "Monospaced");
        StyleConstants.setFontSize(s, 12);
        StyleConstants.setForeground(s, fg);
        return s;
    }

    private SimpleAttributeSet createStyle(Color fg, Color bg) {
        SimpleAttributeSet s = new SimpleAttributeSet();
        StyleConstants.setFontFamily(s, "Monospaced");
        StyleConstants.setFontSize(s, 12);
        StyleConstants.setForeground(s, fg);
        StyleConstants.setBackground(s, bg);
        return s;
    }

    private SimpleAttributeSet getStatusAttr(int statusCode) {
        if (statusCode >= 200 && statusCode < 300) {
            return attrStatus_2XX;
        }
        if (statusCode >= 300 && statusCode < 400) {
            return attrStatus_3XX;
        }
        return attrStatus_4XX;
    }

    // Helper attributes
    private final SimpleAttributeSet attrStatus_2XX = createStyle(COLOR_STATUS_2XX);
    private final SimpleAttributeSet attrStatus_3XX = createStyle(COLOR_STATUS_3XX);
    private final SimpleAttributeSet attrStatus_4XX = createStyle(COLOR_STATUS_4XX);

    private static void append(StyledDocument doc, String text, SimpleAttributeSet attr) {
        if (text == null || text.isEmpty()) {
            return;
        }
        try {
            doc.insertString(doc.getLength(), text, attr);
        } catch (Exception ignored) {
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return null;
        }
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }

    private static String formatSize(int bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }

    private JTextPane createTextPane() {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setBackground(COLOR_BG);
        pane.setCaretColor(Color.WHITE);
        return pane;
    }

    // ---- Layout preferences persistence ----

    private static boolean loadHorizontal() {
        ZapXmlConfiguration config = getConfig();
        if (config == null) {
            return true;
        }
        return config.getBoolean(KEY_HORIZONTAL, true);
    }

    private static void saveHorizontal(boolean horizontal) {
        ZapXmlConfiguration config = getConfig();
        if (config != null) {
            config.setProperty(KEY_HORIZONTAL, Boolean.valueOf(horizontal));
            saveConfig(config);
        }
    }

    private static double loadDividerRatio() {
        ZapXmlConfiguration config = getConfig();
        if (config == null) {
            return -1.0;
        }
        return config.getDouble(KEY_DIVIDER_RATIO, -1.0);
    }

    private static void saveDividerRatio(double ratio) {
        ZapXmlConfiguration config = getConfig();
        if (config != null) {
            config.setProperty(KEY_DIVIDER_RATIO, Double.valueOf(ratio));
            saveConfig(config);
        }
    }

    private static ZapXmlConfiguration getConfig() {
        if (cachedConfig != null) return cachedConfig;
        synchronized (HttpMessageViewer.class) {
            if (cachedConfig != null) return cachedConfig;
            try {
                File configFile = new File(
                        new File(org.parosproxy.paros.Constant.getZapHome(), CONFIG_DIR),
                        CONFIG_FILE);
                configFile.getParentFile().mkdirs();
                cachedConfig = configFile.exists()
                        ? new ZapXmlConfiguration(configFile)
                        : new ZapXmlConfiguration();
            } catch (Exception e) {
                // ignore
            }
            return cachedConfig;
        }
    }

    private static void saveConfig(ZapXmlConfiguration config) {
        try {
            config.save();
        } catch (Exception e) {
            // Ignore save errors
        }
    }
}
