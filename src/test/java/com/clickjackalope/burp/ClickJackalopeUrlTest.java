package com.clickjackalope.burp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ClickJackalopeUrlTest
{
    @Test
    void preservesSecurityTestingPayloadsAndExistingEscapes()
    {
        String url = "https://target.test/open?q=\"><script>alert(1)</script>&encoded=%22";
        assertEquals(url, ClickJackalopePanel.normalizedUrl(url));
        String html = ClickJackalopeHtmlGenerator.build(url, false, ClickJackalopeTemplate.STANDARD);
        assertFalse(html.contains("<script>"));
        assertTrue(html.contains("&quot;&gt;&lt;script&gt;"));
        assertTrue(html.contains("%22"));
    }

    @Test
    void validatesAuthorityAndRejectsControlCharacters()
    {
        assertEquals("https://target.test/path", ClickJackalopePanel.normalizedUrl("target.test/path"));
        assertThrows(IllegalArgumentException.class, () -> ClickJackalopePanel.normalizedUrl(""));
        assertThrows(IllegalArgumentException.class, () -> ClickJackalopePanel.normalizedUrl("https:///path"));
        assertThrows(IllegalArgumentException.class, () -> ClickJackalopePanel.normalizedUrl("https://a.test/\r\ninjected"));
    }
}
