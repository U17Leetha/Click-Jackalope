package com.clickjackalope.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClickJackalopeFrameAnalysisTest
{
    @Test
    void reportsNoResponseWhenNoneIsPresent()
    {
        ClickJackalopeFrameAnalysis analysis = ClickJackalopeFrameAnalysis.analyze(requestResponse(null));

        assertEquals("No response selected", analysis.summary());
        assertEquals("Not observed", analysis.xFrameOptions());
    }

    @Test
    void reportsXFrameOptionsDeny()
    {
        ClickJackalopeFrameAnalysis analysis = ClickJackalopeFrameAnalysis.analyze(
            requestResponse(response(Map.of("X-Frame-Options", "DENY")))
        );

        assertEquals("Framing should be blocked by X-Frame-Options", analysis.summary());
        assertTrue(analysis.guidance().contains("DENY"));
    }

    @Test
    void prefersFrameAncestorsAnalysisOverXfo()
    {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Frame-Options", "SAMEORIGIN");
        headers.put("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");

        ClickJackalopeFrameAnalysis analysis = ClickJackalopeFrameAnalysis.analyze(requestResponse(response(headers)));

        assertEquals("Framing should be blocked by CSP", analysis.summary());
        assertEquals("'none'", analysis.frameAncestors());
        assertEquals("SAMEORIGIN", analysis.xFrameOptions());
    }

    @Test
    void reportsSameOriginRestrictions()
    {
        ClickJackalopeFrameAnalysis analysis = ClickJackalopeFrameAnalysis.analyze(
            requestResponse(response(Map.of("Content-Security-Policy", "frame-ancestors 'self' https://portal.example")))
        );

        assertEquals("Framing is restricted to same-origin ancestors", analysis.summary());
        assertTrue(analysis.guidance().contains("same origin"));
    }

    private static HttpRequestResponse requestResponse(HttpResponse response)
    {
        return (HttpRequestResponse) Proxy.newProxyInstance(
            ClickJackalopeFrameAnalysisTest.class.getClassLoader(),
            new Class<?>[]{HttpRequestResponse.class},
            (proxy, method, args) -> switch (method.getName())
            {
                case "hasResponse" -> response != null;
                case "response" -> response;
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static HttpResponse response(Map<String, String> headers)
    {
        return (HttpResponse) Proxy.newProxyInstance(
            ClickJackalopeFrameAnalysisTest.class.getClassLoader(),
            new Class<?>[]{HttpResponse.class},
            (proxy, method, args) -> switch (method.getName())
            {
                case "headerValue" -> headers.get((String) args[0]);
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static Object defaultValue(Class<?> type)
    {
        if (!type.isPrimitive())
        {
            return null;
        }
        if (type == boolean.class)
        {
            return false;
        }
        if (type == byte.class)
        {
            return (byte) 0;
        }
        if (type == short.class)
        {
            return (short) 0;
        }
        if (type == int.class)
        {
            return 0;
        }
        if (type == long.class)
        {
            return 0L;
        }
        if (type == float.class)
        {
            return 0f;
        }
        if (type == double.class)
        {
            return 0d;
        }
        if (type == char.class)
        {
            return '\0';
        }
        return null;
    }
}
