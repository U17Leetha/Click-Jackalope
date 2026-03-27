package com.clickjackalope.burp;

enum ClickJackalopeTemplate
{
    STANDARD("standard", "Standard"),
    DECOY_LOGIN("decoy-login", "Decoy Login"),
    BANNER_LURE("banner-lure", "Banner Lure");

    private final String id;
    private final String label;

    ClickJackalopeTemplate(String id, String label)
    {
        this.id = id;
        this.label = label;
    }

    String id()
    {
        return id;
    }

    static ClickJackalopeTemplate fromId(String value)
    {
        for (ClickJackalopeTemplate template : values())
        {
            if (template.id.equalsIgnoreCase(value))
            {
                return template;
            }
        }

        throw new IllegalArgumentException("Unknown template: " + value);
    }

    @Override
    public String toString()
    {
        return label;
    }
}
