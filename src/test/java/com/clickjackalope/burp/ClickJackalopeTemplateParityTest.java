package com.clickjackalope.burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-implementation parity contract with click-jackalope.sh. The shell CLI renders its own
 * copies of these three templates (render_html), so the two implementations can drift silently.
 * tests/test_cli.py::TemplateParityTests mirrors PARITY_URL / PARITY_ESCAPED and the expected
 * iframe markup below verbatim: for identical inputs, both implementations must emit byte-identical
 * iframe elements (same escaping, same sandbox attribute). Change an escaping or sandbox change on
 * one side requires updating both sides together — that is the point of this test.
 */
class ClickJackalopeTemplateParityTest
{
    static final String PARITY_URL = "https://example.test/\" onload=globalThis.sentinel=1 x=\"<>&";
    static final String PARITY_ESCAPED =
        "https://example.test/&quot; onload=globalThis.sentinel=1 x=&quot;&lt;&gt;&amp;";

    private static String expectedIframe(boolean sandbox)
    {
        return "<iframe src=\"" + PARITY_ESCAPED + "\" title=\"click-jackalope-test\""
            + (sandbox ? " sandbox=\"\"" : "") + "></iframe>";
    }

    @Test
    void everyTemplateEmitsTheSharedIframeContract()
    {
        for (ClickJackalopeTemplate template : ClickJackalopeTemplate.values())
        {
            for (boolean sandbox : new boolean[] {false, true})
            {
                String html = ClickJackalopeHtmlGenerator.build(PARITY_URL, sandbox, template);
                assertTrue(html.contains(expectedIframe(sandbox)),
                    "iframe markup drifted from the shell CLI contract for " + template + " sandbox=" + sandbox);
            }
        }
    }
}
