package com.clickjackalope.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.lang.reflect.*;
import java.util.List;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.*;

class ClickJackalopePanelTest
{
    @Test
    void editingTargetImmediatelyClearsResponseEvidence() throws Exception
    {
        var previousFactory = ObjectFactoryLocator.FACTORY;
        var executor = Executors.newSingleThreadExecutor();
        try
        {
            // Burp supplies this factory at runtime. Editors do not need actual byte arrays here.
            ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (p, m, a) -> null);
            SwingUtilities.invokeAndWait(() -> {
                var panel = new ClickJackalopePanel(stub(MontoyaApi.class), executor);
                try
                {
                    var header = proxy(HttpHeader.class, (p, m, a) -> m.getName().equals("name") ? "X-Frame-Options" : "DENY");
                    var response = proxy(HttpResponse.class, (p, m, a) -> m.getName().equals("headers") ? List.of(header) : null);
                    var request = proxy(HttpRequest.class, (p, m, a) -> "https://first.test/open?q=\"><script>alert(1)</script>");
                    var rr = proxy(HttpRequestResponse.class, (p, m, a) -> switch (m.getName()) {
                        case "request" -> request;
                        case "response" -> response;
                        case "hasResponse" -> true;
                        default -> null;
                    });
                    panel.populateFromRequestResponse(rr, false);
                    assertEquals("Framing should be blocked by X-Frame-Options", analysis(panel).summary());
                    Field url = ClickJackalopePanel.class.getDeclaredField("urlField");
                    url.setAccessible(true);
                    ((JTextField) url.get(panel)).setText("https://second.test/");
                    var analysis = analysis(panel);
                    String notes = ClickJackalopeReportNotes.build("https://second.test/", analysis);
                    assertEquals("No response selected", analysis.summary());
                    assertFalse(notes.contains("DENY"));
                }
                catch (ReflectiveOperationException error) { throw new AssertionError(error); }
                finally { panel.shutdown(); }
            });
        }
        finally { ObjectFactoryLocator.FACTORY = previousFactory; executor.shutdownNow(); }
    }

    private static ClickJackalopeFrameAnalysis analysis(ClickJackalopePanel panel) throws ReflectiveOperationException
    {
        Field field = ClickJackalopePanel.class.getDeclaredField("currentAnalysis");
        field.setAccessible(true);
        return (ClickJackalopeFrameAnalysis) field.get(panel);
    }

    private static <T> T stub(Class<T> type)
    {
        return proxy(type, (p, method, args) -> {
            if (method.getName().equals("uiComponent")) return new JPanel();
            if (method.getReturnType().isInterface()) return stub(method.getReturnType());
            return null;
        });
    }

    private static <T> T proxy(Class<T> type, InvocationHandler handler)
    {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
    }
}
