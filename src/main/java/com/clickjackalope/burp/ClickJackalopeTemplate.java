package com.clickjackalope.burp;

enum ClickJackalopeTemplate
{
    STANDARD("Standard"),
    DECOY_LOGIN("Decoy Login"),
    BANNER_LURE("Banner Lure");

    private final String label;
    ClickJackalopeTemplate(String label) { this.label = label; }
    @Override public String toString() { return label; }
}
