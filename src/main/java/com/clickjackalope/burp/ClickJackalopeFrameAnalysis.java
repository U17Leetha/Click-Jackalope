package com.clickjackalope.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

final class ClickJackalopeFrameAnalysis
{
    private final String summary;
    private final String guidance;
    private final String xFrameOptions;
    private final String frameAncestors;

    private ClickJackalopeFrameAnalysis(String summary, String guidance, String xFrameOptions, String frameAncestors)
    {
        this.summary = summary;
        this.guidance = guidance;
        this.xFrameOptions = xFrameOptions;
        this.frameAncestors = frameAncestors;
    }

    static ClickJackalopeFrameAnalysis analyze(HttpRequestResponse requestResponse)
    {
        if (requestResponse == null || !requestResponse.hasResponse() || requestResponse.response() == null)
        {
            return new ClickJackalopeFrameAnalysis(
                "No response selected",
                "Select a request with a server response to inspect frame-defense headers before generating the PoC.",
                "Not observed",
                "Not observed"
            );
        }

        HttpResponse response = requestResponse.response();
        String xfo = headerValue(response, "X-Frame-Options");
        String csp = headerValue(response, "Content-Security-Policy");
        String frameAncestors = extractFrameAncestors(csp);

        if (frameAncestors != null)
        {
            String lower = frameAncestors.toLowerCase();
            if (lower.contains("'none'"))
            {
                return new ClickJackalopeFrameAnalysis(
                    "Framing should be blocked by CSP",
                    "Expected browser behavior: the page should refuse to load in an iframe because `frame-ancestors 'none'` forbids all framing.",
                    valueOrFallback(xfo),
                    frameAncestors
                );
            }
            if (lower.contains("'self'"))
            {
                return new ClickJackalopeFrameAnalysis(
                    "Framing is restricted to same-origin ancestors",
                    "Expected browser behavior: local-file PoCs and foreign-origin PoCs should fail. A PoC served from the same origin may still work.",
                    valueOrFallback(xfo),
                    frameAncestors
                );
            }

            return new ClickJackalopeFrameAnalysis(
                "Framing is controlled by CSP allowlist",
                "Expected browser behavior depends on whether the PoC origin matches the `frame-ancestors` sources in the response CSP.",
                valueOrFallback(xfo),
                frameAncestors
            );
        }

        if (xfo != null)
        {
            String normalizedXfo = xfo.trim().toUpperCase();
            if (normalizedXfo.contains("DENY"))
            {
                return new ClickJackalopeFrameAnalysis(
                    "Framing should be blocked by X-Frame-Options",
                    "Expected browser behavior: the page should refuse to load in an iframe because the response sends `X-Frame-Options: DENY`.",
                    xfo,
                    "Not observed"
                );
            }
            if (normalizedXfo.contains("SAMEORIGIN"))
            {
                return new ClickJackalopeFrameAnalysis(
                    "Framing is restricted to same-origin ancestors",
                    "Expected browser behavior: local-file PoCs and foreign-origin PoCs should fail. A PoC served from the same origin may still work.",
                    xfo,
                    "Not observed"
                );
            }

            return new ClickJackalopeFrameAnalysis(
                "Framing behavior depends on X-Frame-Options handling",
                "The response sends an `X-Frame-Options` value that should be reviewed manually in the browser and response headers.",
                xfo,
                "Not observed"
            );
        }

        return new ClickJackalopeFrameAnalysis(
            "No frame-defense header observed",
            "Expected browser behavior: the page may be frameable unless other controls or browser behavior prevent it.",
            "Not observed",
            "Not observed"
        );
    }

    String summary()
    {
        return summary;
    }

    String guidance()
    {
        return guidance;
    }

    String xFrameOptions()
    {
        return xFrameOptions;
    }

    String frameAncestors()
    {
        return frameAncestors;
    }

    private static String headerValue(HttpResponse response, String name)
    {
        String value = response.headerValue(name);
        if (value == null || value.isBlank())
        {
            return null;
        }
        return value;
    }

    private static String extractFrameAncestors(String csp)
    {
        if (csp == null || csp.isBlank())
        {
            return null;
        }

        for (String directive : csp.split(";"))
        {
            String trimmed = directive.trim();
            if (trimmed.regionMatches(true, 0, "frame-ancestors", 0, "frame-ancestors".length()))
            {
                String value = trimmed.substring("frame-ancestors".length()).trim();
                return value.isEmpty() ? "present but empty" : value;
            }
        }

        return null;
    }

    private static String valueOrFallback(String value)
    {
        return value == null ? "Not observed" : value;
    }
}
