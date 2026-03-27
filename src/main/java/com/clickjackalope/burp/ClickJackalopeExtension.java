package com.clickjackalope.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ClickJackalopeExtension implements BurpExtension, ExtensionUnloadingHandler
{
    private ExecutorService executorService;
    private Registration suiteTabRegistration;
    private Registration contextMenuRegistration;
    private ClickJackalopePanel panel;
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        this.executorService = Executors.newSingleThreadExecutor(runnable ->
        {
            Thread thread = new Thread(runnable, "click-jackalope-open");
            thread.setDaemon(true);
            return thread;
        });

        api.extension().setName("Click-Jackalope");

        this.panel = new ClickJackalopePanel(api, executorService);
        this.suiteTabRegistration = api.userInterface().registerSuiteTab("Click-Jackalope", panel);
        this.contextMenuRegistration = api.userInterface().registerContextMenuItemsProvider(
            new ClickJackalopeContextMenuItemsProvider(api, panel)
        );
        api.extension().registerUnloadingHandler(this);

        api.logging().logToOutput("Click-Jackalope loaded from " + api.extension().filename());
    }

    @Override
    public void extensionUnloaded()
    {
        safelyDeregister(contextMenuRegistration);
        safelyDeregister(suiteTabRegistration);

        if (panel != null)
        {
            panel.shutdown();
        }

        if (executorService != null)
        {
            executorService.shutdownNow();
        }

        if (api != null)
        {
            api.logging().logToOutput("Click-Jackalope unloaded.");
        }
    }

    private static void safelyDeregister(Registration registration)
    {
        if (registration == null || !registration.isRegistered())
        {
            return;
        }

        try
        {
            registration.deregister();
        }
        catch (IllegalStateException ignored)
        {
            // Burp may already be tearing the registration down during unload.
        }
    }
}
