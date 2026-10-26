# Fix tracker

## 2026-10-26 — Reviewer feedback and related URL/server handling

- Fixed empty frame-ancestors, duplicate/combined CSP policies, conflicting X-Frame-Options, mixed self/external sources, and wildcard verdicts. Exact directive/token matching replaces substring checks. CSP policies are intersected; complex combinations require browser verification.
- Editing the Target URL immediately discards selected-response analysis, preventing stale report evidence. A fresh Burp response is required to analyze the edited target.
- Security-testing characters in request paths/queries survive URL validation and remain HTML escaped in generated PoCs. Context-menu preview errors are caught on the Swing thread.
- Replacement server ports bind before the old server stops. Failed binds close the candidate socket, preserve the previous HTML and listener, and display the exception cause.
- Fixed Gradle root-JAR synchronization inputs so rebuilding refreshes the extension artifact after source changes.
- Verification: ./gradlew check jar; 18 Java tests, including Swing document changes and real localhost occupied-port recovery. Manual Burp/Chrome verification remains outstanding.

Policy interpretation follows [CSP Level 3](https://www.w3.org/TR/CSP/) and the [HTML X-Frame-Options algorithm](https://html.spec.whatwg.org/multipage/document-lifecycle.html#the-x-frame-options-header). Header predictions describe the selected response, not a fresh response fetched by Preview.
