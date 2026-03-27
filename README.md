# Click-Jackalope
Click-Jackalope is a compact toolkit for generating clickjacking proof-of-concept pages during authorized security testing.

## Purpose
The extension helps testers answer a narrow workflow question quickly: can this target page be framed, and if so, what does a minimal proof-of-concept look like? It is intended for validating `X-Frame-Options` and CSP `frame-ancestors` behavior and for producing reproducible evidence for reports.

## Why This Exists
Clickjacking verification is usually simple, but it is repetitive. Testers often need to:

- extract a URL from Burp traffic
- build a local HTML page that embeds it in an iframe
- save the file and open it in a browser
- document whether framing succeeds or is blocked

Click-Jackalope reduces that sequence to a short Burp-native workflow.

## Burp Extension
The Burp Suite extension now targets PortSwigger's current Java-based Montoya API instead of the legacy Jython Extender API. This makes it easier to load, test, package, and submit through the BApp review process.

## Key Features
- Adds a dedicated `Click-Jackalope` Burp suite tab.
- Generates a local clickjacking test page from a target URL.
- Adds context menu items in Burp to pre-populate the target from selected requests.
- Provides an in-extension HTML preview before saving.
- Saves the generated HTML locally and can open it in the default browser.
- Escapes untrusted URL content before rendering it into HTML.
- Makes iframe sandboxing optional instead of forcing it on every test.

## Build

```bash
gradle clean jar
```

Build artifact:

```text
build/libs/click-jackalope-burp-1.0.0.jar
```

## Using In Burp
1. Open `Extensions > Installed` in Burp Suite.
2. Click `Add`.
3. Set the extension type to `Java`.
4. Select [click-jackalope-burp-1.0.0.jar](/Users/matt/Development/Click-Jackalope/build/libs/click-jackalope-burp-1.0.0.jar) after building it.
5. Load the extension and open the `Click-Jackalope` tab.

Typical workflow:

- Paste a target URL into the tab and preview or save the generated PoC.
- Or right-click a request in Proxy, Target, Repeater, or Logger and choose `Create Click-Jackalope POC`.
- Save the HTML locally and open it in a browser to verify framing behavior.

## BApp Submission Notes
- The supported Burp implementation is the Java/Montoya source under [ClickJackalopeExtension.java](/Users/matt/Development/Click-Jackalope/src/main/java/com/clickjackalope/burp/ClickJackalopeExtension.java).
- The extension builds into a normal JAR and no longer requires Jython.
- The repository intentionally ignores local Burp project files, build outputs, generated HTML, and the legacy Jython prototype so the submission tree stays clean.
- The extension performs only local UI, file-generation, and browser-opening actions. It does not transmit generated data to external services.

## Reviewer Notes
- Primary entry point: [ClickJackalopeExtension.java](/Users/matt/Development/Click-Jackalope/src/main/java/com/clickjackalope/burp/ClickJackalopeExtension.java)
- Main UI: [ClickJackalopePanel.java](/Users/matt/Development/Click-Jackalope/src/main/java/com/clickjackalope/burp/ClickJackalopePanel.java)
- HTML generation: [ClickJackalopeHtmlGenerator.java](/Users/matt/Development/Click-Jackalope/src/main/java/com/clickjackalope/burp/ClickJackalopeHtmlGenerator.java)
- Context menu integration: [ClickJackalopeContextMenuItemsProvider.java](/Users/matt/Development/Click-Jackalope/src/main/java/com/clickjackalope/burp/ClickJackalopeContextMenuItemsProvider.java)

## CLI Helper
The standalone shell helper is still included for simple local generation:

```bash
./click-jackalope.sh -u "https://target.example" [-e] [-f out.html]
```

## Repository Notes
- The supported Burp implementation is the Java source under [ClickJackalopeExtension.java](/Users/matt/Development/Click-Jackalope/src/main/java/com/clickjackalope/burp/ClickJackalopeExtension.java).
- The shell helper remains available for quick standalone PoC generation outside Burp.
