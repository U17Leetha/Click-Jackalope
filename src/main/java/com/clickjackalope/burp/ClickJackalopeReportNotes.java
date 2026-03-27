package com.clickjackalope.burp;

final class ClickJackalopeReportNotes
{
    private ClickJackalopeReportNotes()
    {
    }

    static String build(String url, ClickJackalopeFrameAnalysis analysis)
    {
        return "Click-Jackalope observation\n" +
            "Target URL: " + url + "\n" +
            "Summary: " + analysis.summary() + "\n" +
            "X-Frame-Options: " + analysis.xFrameOptions() + "\n" +
            "CSP frame-ancestors: " + analysis.frameAncestors() + "\n" +
            "Guidance: " + analysis.guidance();
    }
}
