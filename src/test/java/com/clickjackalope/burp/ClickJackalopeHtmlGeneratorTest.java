package com.clickjackalope.burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClickJackalopeHtmlGeneratorTest
{
    @Test
    void escapesHtmlInTargetUrl()
    {
        String html = ClickJackalopeHtmlGenerator.build("https://target.example/?q=<tag>&x=1", false, ClickJackalopeTemplate.STANDARD);

        assertTrue(html.contains("&lt;tag&gt;"));
        assertTrue(html.contains("&amp;x=1"));
        assertFalse(html.contains("<tag>"));
    }

    @Test
    void includesSandboxAttributeOnlyWhenRequested()
    {
        String sandboxed = ClickJackalopeHtmlGenerator.build("https://target.example", true, ClickJackalopeTemplate.STANDARD);
        String unsandboxed = ClickJackalopeHtmlGenerator.build("https://target.example", false, ClickJackalopeTemplate.STANDARD);

        assertTrue(sandboxed.contains("sandbox=\"\""));
        assertFalse(unsandboxed.contains("sandbox=\"\""));
    }

    @Test
    void rendersDistinctTemplates()
    {
        String decoy = ClickJackalopeHtmlGenerator.build("https://target.example", false, ClickJackalopeTemplate.DECOY_LOGIN);
        String banner = ClickJackalopeHtmlGenerator.build("https://target.example", false, ClickJackalopeTemplate.BANNER_LURE);

        assertTrue(decoy.contains("Continue Session"));
        assertTrue(banner.contains("Action required: verify your session to continue"));
    }
}
