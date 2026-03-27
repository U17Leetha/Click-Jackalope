package com.clickjackalope.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class ClickJackalopeContextMenuItemsProvider implements ContextMenuItemsProvider
{
    private final MontoyaApi api;
    private final ClickJackalopePanel panel;

    ClickJackalopeContextMenuItemsProvider(MontoyaApi api, ClickJackalopePanel panel)
    {
        this.api = api;
        this.panel = panel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (!event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.REPEATER, ToolType.LOGGER))
        {
            return null;
        }

        HttpRequestResponse requestResponse = selectedRequestResponse(event);
        if (requestResponse == null)
        {
            return null;
        }

        List<Component> items = new ArrayList<>();

        JMenuItem generate = new JMenuItem("Create Click-Jackalope POC");
        generate.addActionListener(ignore -> SwingUtilities.invokeLater(() -> panel.populateFromRequestResponse(requestResponse, true)));
        items.add(generate);

        JMenuItem preview = new JMenuItem("Preview Click-Jackalope POC");
        preview.addActionListener(ignore -> SwingUtilities.invokeLater(() -> panel.populateFromRequestResponse(requestResponse, false)));
        items.add(preview);

        return items;
    }

    private HttpRequestResponse selectedRequestResponse(ContextMenuEvent event)
    {
        Optional<HttpRequestResponse> editorSelection = event.messageEditorRequestResponse()
            .map(editor -> editor.requestResponse());
        if (editorSelection.isPresent())
        {
            return editorSelection.get();
        }

        List<HttpRequestResponse> selectedRequestResponses = event.selectedRequestResponses();
        if (selectedRequestResponses == null || selectedRequestResponses.isEmpty())
        {
            api.logging().logToError("Click-Jackalope context menu invoked without a request selection.");
            return null;
        }

        return selectedRequestResponses.get(0);
    }
}
