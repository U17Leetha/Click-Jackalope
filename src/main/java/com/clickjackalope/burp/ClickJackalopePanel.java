package com.clickjackalope.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
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
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
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
    private final ServedPocServer servedPocServer;

    private final JTextField urlField;
    private final JTextField fileField;
    private final JTextField servePortField;
    private final JCheckBox sandboxCheckBox;
    private final JComboBox<ClickJackalopeTemplate> templateComboBox;
    private final JTextArea previewArea;
    private final JTextArea analysisArea;
    private final JLabel statusLabel;

    private ClickJackalopeFrameAnalysis currentAnalysis;

    ClickJackalopePanel(MontoyaApi api, ExecutorService executorService)
    {
        super(new BorderLayout(12, 12));
        this.api = api;
        this.executorService = executorService;
        this.servedPocServer = new ServedPocServer();
        this.currentAnalysis = ClickJackalopeFrameAnalysis.analyze(null);

        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));

        this.urlField = new JTextField();
        this.fileField = new JTextField("clickjack_test.html");
        this.servePortField = new JTextField("9011");
        this.sandboxCheckBox = new JCheckBox("Add iframe sandbox attribute");
        this.templateComboBox = new JComboBox<>(ClickJackalopeTemplate.values());

        controls.add(labeledField("Target URL", urlField));
        controls.add(Box.createRigidArea(new Dimension(0, 8)));
        controls.add(labeledField("Output filename", fileField));
        controls.add(Box.createRigidArea(new Dimension(0, 8)));
        controls.add(labeledField("Serve port", servePortField));
        controls.add(Box.createRigidArea(new Dimension(0, 8)));
        controls.add(labeledComponent("Template", templateComboBox));
        controls.add(Box.createRigidArea(new Dimension(0, 8)));
        controls.add(sandboxCheckBox);
        controls.add(Box.createRigidArea(new Dimension(0, 12)));
        controls.add(buttonRow());

        this.analysisArea = new JTextArea(7, 120);
        analysisArea.setEditable(false);
        analysisArea.setLineWrap(true);
        analysisArea.setWrapStyleWord(true);
        analysisArea.setText(defaultAnalysisText());

        this.previewArea = new JTextArea(18, 120);
        previewArea.setEditable(false);
        previewArea.setLineWrap(false);
        previewArea.setText(ClickJackalopeHtmlGenerator.build("https://target.example", false, ClickJackalopeTemplate.STANDARD));

        JPanel centerPanel = new JPanel(new BorderLayout(0, 12));
        centerPanel.add(section("Frame Defense Analysis", new JScrollPane(analysisArea)), BorderLayout.NORTH);
        centerPanel.add(section("Generated PoC Preview", new JScrollPane(previewArea)), BorderLayout.CENTER);

        this.statusLabel = new JLabel("Ready", SwingConstants.LEFT);

        content.add(controls, BorderLayout.NORTH);
        content.add(centerPanel, BorderLayout.CENTER);
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
        applyAnalysis(ClickJackalopeFrameAnalysis.analyze(requestResponse));
        updatePreview();

        if (promptForSave)
        {
            save(false);
        }
    }

    void shutdown()
    {
        servedPocServer.stop();
    }

    private JPanel labeledField(String label, JTextField field)
    {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.add(new JLabel(label), BorderLayout.NORTH);
        panel.add(field, BorderLayout.CENTER);
        return panel;
    }

    private JPanel labeledComponent(String label, Component component)
    {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.add(new JLabel(label), BorderLayout.NORTH);
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    private JPanel section(String title, Component component)
    {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(new JLabel(title), BorderLayout.NORTH);
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buttonRow()
    {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

        JButton previewButton = new JButton("Preview");
        previewButton.addActionListener(ignore -> updatePreviewSafely());

        JButton copyNotesButton = new JButton("Copy Report Notes");
        copyNotesButton.addActionListener(ignore -> copyReportNotes());

        JButton saveButton = new JButton("Save As...");
        saveButton.addActionListener(ignore -> save(false));

        JButton saveAndOpenButton = new JButton("Save & Open");
        saveAndOpenButton.addActionListener(ignore -> save(true));

        JButton serveAndOpenButton = new JButton("Serve & Open");
        serveAndOpenButton.addActionListener(ignore -> serveAndOpen());

        panel.add(previewButton);
        panel.add(Box.createRigidArea(new Dimension(8, 0)));
        panel.add(copyNotesButton);
        panel.add(Box.createRigidArea(new Dimension(8, 0)));
        panel.add(saveButton);
        panel.add(Box.createRigidArea(new Dimension(8, 0)));
        panel.add(saveAndOpenButton);
        panel.add(Box.createRigidArea(new Dimension(8, 0)));
        panel.add(serveAndOpenButton);
        panel.add(Box.createHorizontalGlue());

        return panel;
    }

    private void updatePreviewSafely()
    {
        try
        {
            updatePreview();
        }
        catch (IllegalArgumentException exception)
        {
            showError(exception.getMessage(), exception);
        }
    }

    private void updatePreview()
    {
        String normalizedUrl = normalizedUrl();
        String html = ClickJackalopeHtmlGenerator.build(normalizedUrl, sandboxCheckBox.isSelected(), selectedTemplate());
        previewArea.setText(html);
        previewArea.setCaretPosition(0);
        statusLabel.setText("Preview ready for " + normalizedUrl);
    }

    private void copyReportNotes()
    {
        String url = urlField.getText().trim().isEmpty() ? "(not set)" : urlField.getText().trim();
        String notes = ClickJackalopeReportNotes.build(url, currentAnalysis);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(notes), null);
        statusLabel.setText("Copied report notes to clipboard");
        api.logging().logToOutput("Click-Jackalope copied report notes for " + url);
    }

    private void save(boolean openAfterSave)
    {
        final String normalizedUrl;
        try
        {
            normalizedUrl = normalizedUrl();
        }
        catch (IllegalArgumentException exception)
        {
            showError(exception.getMessage(), exception);
            return;
        }

        previewArea.setText(ClickJackalopeHtmlGenerator.build(normalizedUrl, sandboxCheckBox.isSelected(), selectedTemplate()));
        previewArea.setCaretPosition(0);

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
        String html = ClickJackalopeHtmlGenerator.build(normalizedUrl, sandboxCheckBox.isSelected(), selectedTemplate());

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
            executorService.submit(() -> openInBrowser(outputPath.toUri(), "Click-Jackalope opened " + outputPath));
        }
    }

    private void serveAndOpen()
    {
        final String normalizedUrl;
        try
        {
            normalizedUrl = normalizedUrl();
        }
        catch (IllegalArgumentException exception)
        {
            showError(exception.getMessage(), exception);
            return;
        }

        final int port;
        try
        {
            port = Integer.parseInt(servePortField.getText().trim());
        }
        catch (NumberFormatException exception)
        {
            showError("Serve port must be a valid number.", exception);
            return;
        }

        if (port < 1 || port > 65535)
        {
            showError("Serve port must be between 1 and 65535.", new IllegalArgumentException("invalid port"));
            return;
        }

        String html = ClickJackalopeHtmlGenerator.build(normalizedUrl, sandboxCheckBox.isSelected(), selectedTemplate());
        previewArea.setText(html);
        previewArea.setCaretPosition(0);

        try
        {
            URI uri = servedPocServer.startOrUpdate(html, port);
            statusLabel.setText("Serving PoC at " + uri);
            api.logging().logToOutput("Click-Jackalope serving PoC at " + uri);
            executorService.submit(() -> openInBrowser(uri, "Click-Jackalope opened served PoC " + uri));
        }
        catch (IOException exception)
        {
            showError("Could not start the local PoC server.", exception);
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

    private void openInBrowser(URI uri, String successMessage)
    {
        try
        {
            Desktop.getDesktop().browse(uri);
            api.logging().logToOutput(successMessage);
        }
        catch (IOException exception)
        {
            api.logging().logToError("Click-Jackalope could not open " + uri + ": " + exception.getMessage());
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                parentComponent(),
                "Generated the PoC, but could not open it automatically:\n" + uri,
                "Click-Jackalope",
                JOptionPane.WARNING_MESSAGE
            ));
        }
    }

    private ClickJackalopeTemplate selectedTemplate()
    {
        return (ClickJackalopeTemplate) templateComboBox.getSelectedItem();
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

    private void applyAnalysis(ClickJackalopeFrameAnalysis analysis)
    {
        currentAnalysis = analysis;
        analysisArea.setText(
            "Summary: " + analysis.summary() + "\n\n" +
            "Guidance: " + analysis.guidance() + "\n\n" +
            "X-Frame-Options: " + analysis.xFrameOptions() + "\n" +
            "CSP frame-ancestors: " + analysis.frameAncestors()
        );
        analysisArea.setCaretPosition(0);
    }

    private static String defaultAnalysisText()
    {
        return "Summary: No response selected\n\n" +
            "Guidance: Select a request with a response in Burp to inspect frame-defense headers before generating the PoC.\n\n" +
            "X-Frame-Options: Not observed\n" +
            "CSP frame-ancestors: Not observed";
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
