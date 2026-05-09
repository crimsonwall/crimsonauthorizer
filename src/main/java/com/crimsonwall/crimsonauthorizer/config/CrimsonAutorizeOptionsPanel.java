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
package com.crimsonwall.crimsonauthorizer.config;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;

/** Options panel for Crimson Authorizer global settings. */
public final class CrimsonAutorizeOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final transient CrimsonAutorizeOptions options;

    private JCheckBox ignore304Checkbox;
    private JCheckBox testUnauthenticatedCheckbox;
    private JCheckBox testRequesterCheckbox;
    private JTextArea excludeExtensionsTextArea;
    private JTextField maxMessageSizeField;
    private JTextField maxResultsField;

    private transient Runnable onOptionsSaved;

    public CrimsonAutorizeOptionsPanel(CrimsonAutorizeOptions options) {
        this.options = options;
        initialize();
    }

    private void initialize() {
        setName(Constant.messages.getString("crimsonautorize.options.title"));
        setLayout(new BorderLayout());

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        // --- Behaviour checkboxes ---
        ignore304Checkbox =
                new JCheckBox(Constant.messages.getString("crimsonautorize.options.ignore304"));
        panel.add(ignore304Checkbox, gbc);

        gbc.gridy++;
        testUnauthenticatedCheckbox =
                new JCheckBox(Constant.messages.getString("crimsonautorize.options.testUnauthenticated"));
        panel.add(testUnauthenticatedCheckbox, gbc);

        gbc.gridy++;
        testRequesterCheckbox =
                new JCheckBox(Constant.messages.getString("crimsonautorize.options.testRequester"));
        testRequesterCheckbox.setToolTipText(
                Constant.messages.getString("crimsonautorize.options.tooltip.testRequester"));
        panel.add(testRequesterCheckbox, gbc);

        // --- Limits ---
        gbc.gridy++;
        gbc.insets = new Insets(15, 5, 2, 5);
        panel.add(new JLabel(
                Constant.messages.getString("crimsonautorize.options.limits")), gbc);

        gbc.gridy++;
        gbc.insets = new Insets(2, 5, 2, 5);
        JPanel limitsPanel = new JPanel(new GridBagLayout());
        limitsPanel.setBorder(BorderFactory.createTitledBorder(
                Constant.messages.getString("crimsonautorize.options.limits.desc")));
        GridBagConstraints lgbc = new GridBagConstraints();
        lgbc.insets = new Insets(2, 5, 2, 5);
        lgbc.anchor = GridBagConstraints.WEST;

        lgbc.gridx = 0;
        lgbc.gridy = 0;
        limitsPanel.add(new JLabel(
                Constant.messages.getString("crimsonautorize.options.maxMessageSize")), lgbc);

        lgbc.gridx = 1;
        lgbc.weightx = 1.0;
        lgbc.fill = GridBagConstraints.HORIZONTAL;
        maxMessageSizeField = new JTextField(10);
        maxMessageSizeField.setToolTipText(
                Constant.messages.getString("crimsonautorize.options.tooltip.maxMessageSize"));
        limitsPanel.add(maxMessageSizeField, lgbc);

        lgbc.gridx = 0;
        lgbc.gridy = 1;
        lgbc.weightx = 0.0;
        limitsPanel.add(new JLabel(
                Constant.messages.getString("crimsonautorize.options.maxResults")), lgbc);

        lgbc.gridx = 1;
        lgbc.weightx = 1.0;
        maxResultsField = new JTextField(10);
        maxResultsField.setToolTipText(
                Constant.messages.getString("crimsonautorize.options.tooltip.maxResults"));
        limitsPanel.add(maxResultsField, lgbc);

        panel.add(limitsPanel, gbc);

        // --- File extension exclusions ---
        gbc.gridy++;
        gbc.insets = new Insets(15, 5, 2, 5);
        panel.add(new JLabel(
                Constant.messages.getString("crimsonautorize.options.excludeExtensions")), gbc);

        gbc.gridy++;
        gbc.insets = new Insets(2, 5, 2, 5);
        JPanel extensionsPanel = new JPanel(new BorderLayout());
        extensionsPanel.setBorder(BorderFactory.createTitledBorder(
                Constant.messages.getString("crimsonautorize.options.excludeExtensions.desc")));
        excludeExtensionsTextArea = new JTextArea(4, 30);
        excludeExtensionsTextArea.setToolTipText(
                Constant.messages.getString("crimsonautorize.options.excludeExtensions.tooltip"));
        extensionsPanel.add(new JScrollPane(excludeExtensionsTextArea), BorderLayout.CENTER);
        panel.add(extensionsPanel, gbc);

        // Push everything to the top
        gbc.gridy++;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(new JPanel(), gbc);

        add(panel, BorderLayout.CENTER);
    }

    @Override
    public void initParam(Object obj) {
        ignore304Checkbox.setSelected(options.isIgnore304());
        testUnauthenticatedCheckbox.setSelected(options.isTestUnauthenticated());
        testRequesterCheckbox.setSelected(options.isTestRequester());
        excludeExtensionsTextArea.setText(String.join("\n", options.getExcludeExtensions()));
        maxMessageSizeField.setText(String.valueOf(options.getMaxMessageSizeMb()));
        maxResultsField.setText(String.valueOf(options.getMaxResults()));
    }

    @Override
    public void validateParam(Object obj) throws Exception {
        try {
            String maxSizeText = maxMessageSizeField.getText().trim();
            if (!maxSizeText.isEmpty()) {
                int maxSizeMb = Integer.parseInt(maxSizeText);
                if (maxSizeMb < 1 || maxSizeMb > 100) {
                    throw new IllegalArgumentException("Max message size must be between 1 and 100 MB");
                }
            }

            String maxResText = maxResultsField.getText().trim();
            if (!maxResText.isEmpty()) {
                int maxRes = Integer.parseInt(maxResText);
                if (maxRes < 100 || maxRes > 100000) {
                    throw new IllegalArgumentException("Max results must be between 100 and 100000");
                }
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid number format for limits", e);
        }
    }

    /** Sets a callback invoked after options are saved successfully. */
    public void setOnOptionsSaved(Runnable callback) {
        this.onOptionsSaved = callback;
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        options.setIgnore304(ignore304Checkbox.isSelected());
        options.setTestUnauthenticated(testUnauthenticatedCheckbox.isSelected());
        options.setTestRequester(testRequesterCheckbox.isSelected());

        List<String> extensions = new ArrayList<>();
        for (String line : excludeExtensionsTextArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                extensions.add(trimmed);
            }
        }
        options.setExcludeExtensions(extensions);

        try {
            int maxSizeMb = Integer.parseInt(maxMessageSizeField.getText().trim());
            if (maxSizeMb < 1 || maxSizeMb > 100) {
                throw new IllegalArgumentException("Max message size must be between 1 and 100 MB");
            }
            options.setMaxMessageSizeMb(maxSizeMb);

            int maxRes = Integer.parseInt(maxResultsField.getText().trim());
            if (maxRes < 100 || maxRes > 100000) {
                throw new IllegalArgumentException("Max results must be between 100 and 100000");
            }
            options.setMaxResults(maxRes);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid number format for limits", e);
        }

        if (onOptionsSaved != null) {
            onOptionsSaved.run();
        }
    }

    @Override
    public String getHelpIndex() {
        // Help not implemented yet - return null to avoid loading issues
        return null;
    }
}
