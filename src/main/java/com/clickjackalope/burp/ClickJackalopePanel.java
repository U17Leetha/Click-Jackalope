package com.clickjackalope.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.ExecutorService;

final class ClickJackalopePanel extends JPanel
{
    private final MontoyaApi api;
    private final ExecutorService executorService;

    private final JTextField urlField;
    private final JTextField fileField;
    private final JCheckBox sandboxCheckBox;
    private final JTextArea previewArea;
    private final JLabel statusLabel;

    ClickJackalopePanel(MontoyaApi api, ExecutorService executorService)
    {
        super(new BorderLayout(12, 12));
        this.api = api;
        this.executorService = executorService;

        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));

        this.urlField = new JTextField();
        this.fileField = new JTextField("clickjack_test.html");
        this.sandboxCheckBox = new JCheckBox("Add iframe sandbox attribute");

        controls.add(labeledField("Target URL", urlField));
        controls.add(Box.createRigidArea(new Dimension(0, 8)));
        controls.add(labeledField("Output filename", fileField));
        controls.add(Box.createRigidArea(new Dimension(0, 8)));
        controls.add(sandboxCheckBox);
        controls.add(Box.createRigidArea(new Dimension(0, 12)));
        controls.add(buttonRow());

        this.previewArea = new JTextArea(18, 120);
        previewArea.setEditable(false);
        previewArea.setLineWrap(false);
        previewArea.setText(ClickJackalopeHtmlGenerator.build("https://target.example", false));

        this.statusLabel = new JLabel("Ready", SwingConstants.LEFT);

        content.add(controls, BorderLayout.NORTH);
        content.add(new JScrollPane(previewArea), BorderLayout.CENTER);
        content.add(statusLabel, BorderLayout.SOUTH);

        api.userInterface().applyThemeToComponent(content);
        add(content, BorderLayout.CENTER);
    }

    void populateFromRequestResponse(HttpRequestResponse requestResponse, boolean promptForSave)
    {
        String url;
        try
        {
            url = requestResponse.request().url();
        }
        catch (Exception exception)
        {
            showError("Could not derive a URL from the selected request.", exception);
            return;
        }

        urlField.setText(url);
        fileField.setText(defaultFilename(url));
        updatePreview();

        if (promptForSave)
        {
            save(false);
        }
    }

    private JPanel labeledField(String label, JTextField field)
    {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.add(new JLabel(label), BorderLayout.NORTH);
        panel.add(field, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buttonRow()
    {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

        JButton previewButton = new JButton("Preview");
        previewButton.addActionListener(ignore -> updatePreview());

        JButton saveButton = new JButton("Save As...");
        saveButton.addActionListener(ignore -> save(false));

        JButton saveAndOpenButton = new JButton("Save & Open");
        saveAndOpenButton.addActionListener(ignore -> save(true));

        panel.add(previewButton);
        panel.add(Box.createRigidArea(new Dimension(8, 0)));
        panel.add(saveButton);
        panel.add(Box.createRigidArea(new Dimension(8, 0)));
        panel.add(saveAndOpenButton);
        panel.add(Box.createHorizontalGlue());

        return panel;
    }

    private void updatePreview()
    {
        String normalizedUrl = normalizedUrl();
        String html = ClickJackalopeHtmlGenerator.build(normalizedUrl, sandboxCheckBox.isSelected());
        previewArea.setText(html);
        previewArea.setCaretPosition(0);
        statusLabel.setText("Preview ready for " + normalizedUrl);
    }

    private void save(boolean openAfterSave)
    {
        String normalizedUrl;
        try
        {
            normalizedUrl = normalizedUrl();
        }
        catch (IllegalArgumentException exception)
        {
            showError(exception.getMessage(), exception);
            return;
        }

        updatePreview();

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Click-Jackalope POC");
        chooser.setSelectedFile(Path.of(fileField.getText().trim()).toFile());

        int result = chooser.showSaveDialog(parentComponent());
        if (result != JFileChooser.APPROVE_OPTION)
        {
            statusLabel.setText("Save cancelled");
            return;
        }

        Path outputPath = chooser.getSelectedFile().toPath().toAbsolutePath().normalize();
        String html = ClickJackalopeHtmlGenerator.build(normalizedUrl, sandboxCheckBox.isSelected());

        try
        {
            Files.writeString(outputPath, html, StandardCharsets.UTF_8);
            fileField.setText(outputPath.getFileName().toString());
            statusLabel.setText("Saved " + outputPath);
            api.logging().logToOutput("Click-Jackalope wrote " + outputPath);
        }
        catch (IOException exception)
        {
            showError("Could not save the generated POC.", exception);
            return;
        }

        if (openAfterSave)
        {
            executorService.submit(() -> openInBrowser(outputPath));
        }
    }

    private String normalizedUrl()
    {
        String raw = urlField.getText().trim();
        if (raw.isEmpty())
        {
            throw new IllegalArgumentException("Please enter a target URL first.");
        }

        String normalized = raw;
        if (!normalized.regionMatches(true, 0, "http://", 0, 7) &&
            !normalized.regionMatches(true, 0, "https://", 0, 8))
        {
            normalized = "https://" + normalized;
        }

        try
        {
            URI uri = new URI(normalized);
            if (uri.getScheme() == null || uri.getHost() == null)
            {
                throw new IllegalArgumentException("Please enter a full HTTP or HTTPS URL.");
            }
        }
        catch (URISyntaxException exception)
        {
            throw new IllegalArgumentException("The target URL is not valid.", exception);
        }

        return normalized;
    }

    private void openInBrowser(Path outputPath)
    {
        try
        {
            Desktop.getDesktop().browse(outputPath.toUri());
            api.logging().logToOutput("Click-Jackalope opened " + outputPath);
        }
        catch (IOException exception)
        {
            api.logging().logToError("Click-Jackalope could not open " + outputPath + ": " + exception.getMessage());
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                parentComponent(),
                "Saved the POC, but could not open it automatically:\n" + outputPath,
                "Click-Jackalope",
                JOptionPane.WARNING_MESSAGE
            ));
        }
    }

    private Component parentComponent()
    {
        return api.userInterface().swingUtils().windowForComponent(this);
    }

    private void showError(String message, Exception exception)
    {
        api.logging().logToError("Click-Jackalope: " + message + " " + exception.getMessage());
        statusLabel.setText(message);
        JOptionPane.showMessageDialog(
            parentComponent(),
            message,
            "Click-Jackalope",
            JOptionPane.ERROR_MESSAGE
        );
    }

    private static String defaultFilename(String url)
    {
        try
        {
            String host = new URI(url).getHost();
            if (host == null || host.isBlank())
            {
                return "clickjack_test.html";
            }

            return "clickjack_" + host.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9.-]", "_") + ".html";
        }
        catch (URISyntaxException exception)
        {
            return "clickjack_test.html";
        }
    }
}
