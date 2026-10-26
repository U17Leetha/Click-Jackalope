package com.clickjackalope.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import burp.api.montoya.http.message.HttpHeader;

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

        assertEquals("Other websites may frame the page under CSP", analysis.summary());
    }

    @Test
    void emptyAncestorsBlocksAllFraming()
    {
        assertEquals("Framing should be blocked by CSP", analyze("Content-Security-Policy", "frame-ancestors").summary());
    }

    @Test
    void readsSecondCspHeaderAndCombinedPolicies()
    {
        for (HttpResponse response : List.of(
            response(List.of(header("Content-Security-Policy", "default-src 'self'"), header("content-security-policy", "frame-ancestors 'none'"))),
            response(Map.of("Content-Security-Policy", "default-src 'self', frame-ancestors 'none'"))))
            assertEquals("Framing should be blocked by CSP", ClickJackalopeFrameAnalysis.analyze(requestResponse(response)).summary());
    }

    @Test
    void conflictingXfoBlocksAndPreservesBothValues()
    {
        var analysis = ClickJackalopeFrameAnalysis.analyze(requestResponse(response(List.of(
            header("X-Frame-Options", "SAMEORIGIN"), header("X-Frame-Options", "DENY")))));
        assertEquals("Framing should be blocked by X-Frame-Options", analysis.summary());
        assertEquals("SAMEORIGIN, DENY", analysis.xFrameOptions());
    }

    @Test
    void wildcardPermitsOtherWebsitesAndOverridesXfo()
    {
        var analysis = ClickJackalopeFrameAnalysis.analyze(requestResponse(response(Map.of(
            "Content-Security-Policy", "frame-ancestors *", "X-Frame-Options", "DENY"))));
        assertEquals("Any website may frame the page", analysis.summary());
    }

    @Test
    void policiesIntersectRatherThanUnion()
    {
        assertEquals("Framing is restricted to same-origin ancestors", analyze("Content-Security-Policy",
            "frame-ancestors *, frame-ancestors 'self'").summary());
        assertEquals("Framing depends on the intersection of CSP policies", analyze("Content-Security-Policy",
            "frame-ancestors https://a.test, frame-ancestors https://b.test").summary());
    }

    @Test
    void parsesExactDirectiveAndUsesFirstDuplicateWithinPolicy()
    {
        assertEquals("No frame-defense header observed", analyze("Content-Security-Policy", "frame-ancestors-extra 'none'").summary());
        assertEquals("Any website may frame the page", analyze("Content-Security-Policy", "frame-ancestors *; frame-ancestors 'none'").summary());
        assertEquals("No frame-defense header observed", analyze("Content-Security-Policy-Report-Only", "frame-ancestors 'none'").summary());
    }

    @Test
    void noneAlongsideOtherSourcesDoesNotBlockEverything()
    {
        assertEquals("Other websites may frame the page under CSP", analyze("Content-Security-Policy", "frame-ancestors 'none' https://a.test").summary());
        assertEquals("Framing behavior depends on X-Frame-Options handling", analyze("X-Frame-Options", "NOT-DENY").summary());
    }

    @Test
    void unsupportedSourcesNeverClaimOtherWebsitesCanFrame()
    {
        assertEquals("CSP framing requires browser validation", analyze("Content-Security-Policy", "frame-ancestors 'unsafe-inline'").summary());
        assertEquals("CSP framing requires browser validation", analyze("Content-Security-Policy", "frame-ancestors not-a-valid-source:???").summary());
    }

    private static ClickJackalopeFrameAnalysis analyze(String name, String value)
    {
        return ClickJackalopeFrameAnalysis.analyze(requestResponse(response(Map.of(name, value))));
    }

    private static HttpHeader header(String name, String value)
    {
        return (HttpHeader) Proxy.newProxyInstance(ClickJackalopeFrameAnalysisTest.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class}, (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                default -> defaultValue(method.getReturnType());
            });
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
        return response(headers.entrySet().stream().map(entry -> header(entry.getKey(), entry.getValue())).toList());
    }

    private static HttpResponse response(List<HttpHeader> headers)
    {
        return (HttpResponse) Proxy.newProxyInstance(
            ClickJackalopeFrameAnalysisTest.class.getClassLoader(),
            new Class<?>[]{HttpResponse.class},
            (proxy, method, args) -> switch (method.getName())
            {
                case "headers" -> headers;
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
