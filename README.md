# Click-Jackalope

[![CI](https://github.com/U17Leetha/Click-Jackalope/actions/workflows/ci.yml/badge.svg)](https://github.com/U17Leetha/Click-Jackalope/actions/workflows/ci.yml)
[![Release](https://github.com/U17Leetha/Click-Jackalope/actions/workflows/release.yml/badge.svg)](https://github.com/U17Leetha/Click-Jackalope/actions/workflows/release.yml)

Click-Jackalope is a compact toolkit for generating clickjacking proof-of-concept pages during authorized security testing.

## At A Glance

- Burp Suite extension built on PortSwigger's Montoya API
- Standalone CLI helper for quick PoC generation
- Local localhost serving mode for HTTP-based testing
- Response-header inspection for `X-Frame-Options` and CSP `frame-ancestors`
- Built-in local lab with known-good framing scenarios
- Multiple PoC templates for demonstrations and reporting

## Purpose

The extension helps testers answer a narrow workflow question quickly: can this target page be framed, and if so, what does a minimal proof-of-concept look like? It is intended for validating `X-Frame-Options` and CSP `frame-ancestors` behavior and for producing reproducible evidence for reports.

## Why This Exists

Clickjacking verification is usually simple, but it is repetitive. Testers often need to:

- extract a URL from Burp traffic
- build a local HTML page that embeds it in an iframe
- save the file and open it in a browser
- document whether framing succeeds or is blocked

Click-Jackalope reduces that sequence to a short Burp-native workflow.

## Key Features

- Adds a dedicated `Click-Jackalope` Burp suite tab.
- Generates a local clickjacking test page from a target URL.
- Adds context menu items in Burp to pre-populate the target from selected requests.
- Inspects `X-Frame-Options` and CSP `frame-ancestors` headers from selected responses and explains the expected framing outcome.
- Provides an in-extension HTML preview before saving.
- Can copy concise report-ready notes for the current target and observed frame-defense headers.
- Saves the generated HTML locally and can open it in the default browser.
- Can serve the generated PoC over localhost for HTTP-based testing instead of only local-file testing.
- Escapes untrusted URL content before rendering it into HTML.
- Makes iframe sandboxing optional instead of forcing it on every test.
- Supports multiple PoC templates: `standard`, `decoy-login`, and `banner-lure`.

## Quick Start

Build with the Gradle wrapper:

```bash
./gradlew clean jar
```

Run tests and build together:

```bash
./gradlew test jar
```

Primary load target for Burp:

```text
click-jackalope-burp.jar
```

## Using In Burp

1. Open `Extensions > Installed` in Burp Suite.
2. Click `Add`.
3. Set the extension type to `Java`.
4. Select `click-jackalope-burp.jar` after building it.
5. Load the extension and open the `Click-Jackalope` tab.

Typical workflow:

- Paste a target URL into the tab, choose a template, and preview, save, or serve the generated PoC.
- Or right-click a request in Proxy, Target, Repeater, or Logger and choose `Create Click-Jackalope POC` to pre-populate the target and inspect frame-defense headers from the selected response.
- Save the HTML locally and open it in a browser to verify framing behavior.

## Screenshots

Add screenshots here before publishing broadly or linking the repo in release notes.

Suggested captures:

- Burp tab with header analysis and template selection
- Context-menu flow from a selected Burp request
- Local lab landing page
- One example of a generated PoC template in the browser

## Build Output

Versioned build artifact:

```text
build/libs/click-jackalope-burp-1.0.0.jar
```

Convenience copy in the repository root after building:

```text
click-jackalope-burp.jar
```

## BApp Submission Notes

- The supported Burp implementation is the Java/Montoya source under `src/main/java/com/clickjackalope/burp/ClickJackalopeExtension.java`.
- The extension builds into a normal JAR and no longer requires Jython.
- The repository intentionally ignores local Burp project files, build outputs, generated HTML, and the legacy Jython prototype so the submission tree stays clean.
- The extension performs only local UI, file-generation, and browser-opening actions. It does not transmit generated data to external services.

## Reviewer Notes

- Primary entry point: `src/main/java/com/clickjackalope/burp/ClickJackalopeExtension.java`
- Main UI: `src/main/java/com/clickjackalope/burp/ClickJackalopePanel.java`
- HTML generation: `src/main/java/com/clickjackalope/burp/ClickJackalopeHtmlGenerator.java`
- Context menu integration: `src/main/java/com/clickjackalope/burp/ClickJackalopeContextMenuItemsProvider.java`

## Automation

GitHub Actions workflows are included for CI and release automation:

- `.github/workflows/ci.yml` runs `./gradlew test jar` on pushes and pull requests and uploads the built JAR as an artifact.
- `.github/workflows/release.yml` runs on version tags like `v1.0.0`, rebuilds the project, and attaches the JAR files to the GitHub release.

## CLI Helper

The standalone shell helper is still included for simple local generation:

```bash
./click-jackalope.sh -u "https://target.example" [-e] [-s] [-t template] [-S port] [-f out.html]
```

CLI notes:

- `-e` opens the generated file after writing it.
- `-s` adds iframe sandboxing to the generated test page.
- `-t template` selects `standard`, `decoy-login`, or `banner-lure`.
- `-S port` serves the generated PoC over `http://127.0.0.1:port/` and keeps the server running until interrupted.
- The CLI now uses the same escaped HTML output and default non-sandboxed behavior as the Burp extension.

## Local Lab

The repository includes a self-contained local web lab with login-style pages that exercise distinct frame-defense setups.

Run it with:

```bash
python3 lab/server.py
```

Lab entry point:

```text
http://127.0.0.1:8765/lab
```

The lab includes:

- a deliberately frameable login page with no frame protections
- a login page blocked by `X-Frame-Options: DENY`
- a login page restricted by `X-Frame-Options: SAMEORIGIN`
- a login page blocked by `Content-Security-Policy: frame-ancestors 'none'`
- a login page restricted by `Content-Security-Policy: frame-ancestors 'self'`

These routes give users known-good expected outcomes when trying the Burp extension or CLI for the first time.

## Repository Notes

- The supported Burp implementation is the Java source under `src/main/java/com/clickjackalope/burp/ClickJackalopeExtension.java`.
- The shell helper remains available for quick standalone PoC generation outside Burp.
