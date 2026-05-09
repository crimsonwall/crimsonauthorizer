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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.parosproxy.paros.Constant;
import com.crimsonwall.crimsonauthorizer.MatchReplaceRule;
import com.crimsonwall.crimsonauthorizer.MatchReplaceRule.ApplyTarget;

/** UI panel for managing match/replace rules. */
public final class MatchReplacePanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final DefaultListModel<MatchReplaceRule> listModel = new DefaultListModel<>();
    private final JList<MatchReplaceRule> ruleList = new JList<>(listModel);
    private final JComboBox<ApplyTarget> targetCombo = new JComboBox<>(ApplyTarget.values());
    private final JTextField matchField = new JTextField(20);
    private final JTextField replaceField = new JTextField(20);
    private final JButton addButton;
    private final JButton removeButton;

    public MatchReplacePanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder(
                Constant.messages.getString("crimsonautorize.matchreplace.title")));

        // Input panel
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 3, 3, 3);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(new JLabel(Constant.messages.getString("crimsonautorize.matchreplace.target")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        inputPanel.add(targetCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        inputPanel.add(new JLabel(Constant.messages.getString("crimsonautorize.matchreplace.match")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        inputPanel.add(matchField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0;
        inputPanel.add(new JLabel(Constant.messages.getString("crimsonautorize.matchreplace.replace")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        inputPanel.add(replaceField, gbc);

        // Buttons
        JPanel buttonPanel = new JPanel();
        addButton = new JButton(Constant.messages.getString("crimsonautorize.matchreplace.add"));
        addButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.addRule"));
        removeButton = new JButton(Constant.messages.getString("crimsonautorize.matchreplace.remove"));
        removeButton.setToolTipText(Constant.messages.getString("crimsonautorize.tooltip.removeRule"));

        addButton.addActionListener(e -> addRule());
        removeButton.addActionListener(e -> removeRule());

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        inputPanel.add(buttonPanel, gbc);

        add(inputPanel, BorderLayout.NORTH);

        // Rule list
        ruleList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ruleList.addListSelectionListener(new RuleSelectionListener());
        JScrollPane listScroll = new JScrollPane(ruleList);
        add(listScroll, BorderLayout.CENTER);
    }

    private void addRule() {
        ApplyTarget target = (ApplyTarget) targetCombo.getSelectedItem();
        String match = matchField.getText().trim();
        String replace = replaceField.getText().trim();
        if (match.isEmpty()) return;
        listModel.addElement(new MatchReplaceRule(target, match, replace, true));
        matchField.setText("");
        replaceField.setText("");
    }

    private void removeRule() {
        int idx = ruleList.getSelectedIndex();
        if (idx >= 0) {
            listModel.remove(idx);
        }
    }

    private class RuleSelectionListener implements ListSelectionListener {
        @Override
        public void valueChanged(ListSelectionEvent e) {
            int idx = ruleList.getSelectedIndex();
            if (idx >= 0) {
                MatchReplaceRule rule = listModel.getElementAt(idx);
                targetCombo.setSelectedItem(rule.getTarget());
                matchField.setText(rule.getMatchPattern());
                replaceField.setText(rule.getReplacePattern());
            }
        }
    }

    public List<MatchReplaceRule> getRules() {
        List<MatchReplaceRule> rules = new ArrayList<>();
        for (int i = 0; i < listModel.size(); i++) {
            rules.add(listModel.getElementAt(i));
        }
        return rules;
    }

    public void setRules(List<MatchReplaceRule> rules) {
        listModel.clear();
        for (MatchReplaceRule rule : rules) {
            listModel.addElement(rule);
        }
    }

    public void clear() {
        listModel.clear();
        matchField.setText("");
        replaceField.setText("");
    }
}
