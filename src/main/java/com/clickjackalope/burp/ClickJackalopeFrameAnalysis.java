package com.clickjackalope.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

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
        String xfo = String.join(", ", headerValues(response, "X-Frame-Options"));
        List<String> policies = new ArrayList<>();
        for (String header : headerValues(response, "Content-Security-Policy"))
        {
            for (String policy : header.split(",", -1))
            {
                String sources = extractFrameAncestors(policy);
                if (sources != null) policies.add(sources);
            }
        }
        String ancestors = policies.stream().map(value -> value.isEmpty() ? "(empty)" : value)
            .collect(Collectors.joining(" | "));
        if (!policies.isEmpty())
        {
            List<List<String>> sources = policies.stream()
                .map(value -> value.isEmpty() ? List.<String>of() : Arrays.asList(value.split("\\s+")))
                .toList();
            if (sources.stream().anyMatch(tokens -> tokens.isEmpty() ||
                tokens.stream().allMatch(token -> token.equalsIgnoreCase("'none'"))))
                return result("Framing should be blocked by CSP",
                    "An enforced frame-ancestors policy has an empty source list or only 'none', forbidding all framing.", xfo, ancestors);
            if (sources.stream().anyMatch(tokens -> tokens.stream().allMatch(token ->
                token.equalsIgnoreCase("'self'") || token.equalsIgnoreCase("'none'"))))
                return result("Framing is restricted to same-origin ancestors",
                    "At least one enforced policy permits only the same origin; every policy must allow every ancestor. Verify in the browser.", xfo, ancestors);
            if (sources.stream().allMatch(tokens -> tokens.contains("*")))
                return result("Any website may frame the page",
                    "All frame-ancestors policies permit wildcard network origins. This is not clickjacking protection for HTTP(S) websites; verify the PoC in the browser.", xfo, ancestors);
            if (policies.size() > 1)
                return result("Framing depends on the intersection of CSP policies",
                    "Every ancestor must match every enforced policy. These policies may have no common permitted origin; verify the complete ancestor chain in the browser.", xfo, ancestors);
            if (sources.get(0).stream().anyMatch(token ->
                !token.equalsIgnoreCase("'self'") && !token.equalsIgnoreCase("'none'") &&
                !token.matches("(?i)(https?://)?(\\*\\.)?[a-z0-9-]+(\\.[a-z0-9-]+)+(:[0-9]+)?(/[^\\s]*)?")))
                return result("CSP framing requires browser validation",
                    "The source list contains expressions this analyzer cannot safely classify. Verify browser source matching before reporting framing protection or exposure.", xfo, ancestors);
            if (requestResponse.request() != null) {
                try {
                    java.net.URL target = new java.net.URL(requestResponse.request().url());
                    String origin = target.getProtocol() + "://" + target.getAuthority();
                    if (sources.get(0).stream().allMatch(token -> token.equals("'self'") || token.equals(origin)))
                        return result("Framing is restricted to same-origin ancestors", "The policy permits only this response origin. Verify in the browser.", xfo, ancestors);
                } catch (java.net.MalformedURLException ignored) { }
            }
            return result("Other websites may frame the page under CSP",
                "The source list includes origins beyond 'self'. Any matching website may frame the page; verify source matching and the complete ancestor chain in the browser.", xfo, ancestors);
        }
        Set<String> options = Arrays.stream(xfo.split(","))
            .map(String::trim).map(value -> value.toUpperCase(Locale.ROOT))
            .filter(value -> !value.isEmpty()).collect(Collectors.toSet());
        if (options.contains("DENY") || (options.size() > 1 && options.contains("SAMEORIGIN")))
            return result("Framing should be blocked by X-Frame-Options",
                "DENY or conflicting X-Frame-Options values block framing in modern browsers. Verify the response in the browser.", xfo, ancestors);
        if (options.equals(Set.of("SAMEORIGIN")))
            return result("Framing is restricted to same-origin ancestors",
                "X-Frame-Options permits only same-origin ancestors. Foreign-origin PoCs should fail.", xfo, ancestors);
        if (!options.isEmpty())
            return result("Framing behavior depends on X-Frame-Options handling",
                "Unrecognized X-Frame-Options values may be ignored. Verify in the browser before reporting protection.", xfo, ancestors);
        return result("No frame-defense header observed",
            "The page may be frameable unless other controls or browser behavior prevent it. Verify the PoC in the browser.", xfo, ancestors);
    }

    private static ClickJackalopeFrameAnalysis result(String summary, String guidance, String xfo, String ancestors)
    {
        return new ClickJackalopeFrameAnalysis(summary, guidance,
            xfo.isEmpty() ? "Not observed" : xfo, ancestors.isEmpty() ? "Not observed" : ancestors);
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

    private static List<String> headerValues(HttpResponse response, String name)
    {
        return response.headers().stream().filter(header -> header.name().equalsIgnoreCase(name))
            .map(header -> header.value()).toList();
    }

    private static String extractFrameAncestors(String csp)
    {
        for (String directive : csp.split(";"))
        {
            String[] parts = directive.trim().split("\\s+", 2);
            if (parts[0].equalsIgnoreCase("frame-ancestors"))
                return parts.length == 1 ? "" : parts[1].trim();
        }
        return null;
    }
}
