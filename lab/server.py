#!/usr/bin/env python3
"""Local Click-Jackalope lab with routes that exercise frame defenses."""

from __future__ import annotations

import argparse
import html
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class Scenario:
    path: str
    title: str
    subtitle: str
    outcome: str
    x_frame_options: Optional[str] = None
    csp: Optional[str] = None


SCENARIOS: Dict[str, Scenario] = {
    "/lab/open-login": Scenario(
        path="/lab/open-login",
        title="Open Login",
        subtitle="No frame protections. This page should be frameable.",
        outcome="Expected result: your generated Click-Jackalope PoC should load this login page inside an iframe.",
    ),
    "/lab/xfo-deny-login": Scenario(
        path="/lab/xfo-deny-login",
        title="X-Frame-Options DENY",
        subtitle="Classic non-clickjackable login page.",
        outcome="Expected result: browsers should refuse to frame this page because it sends X-Frame-Options: DENY.",
        x_frame_options="DENY",
    ),
    "/lab/xfo-sameorigin-login": Scenario(
        path="/lab/xfo-sameorigin-login",
        title="X-Frame-Options SAMEORIGIN",
        subtitle="Frameable only by pages from the same origin.",
        outcome="Expected result: a local file or foreign-origin PoC should be blocked. A PoC served from this same lab origin could frame it.",
        x_frame_options="SAMEORIGIN",
    ),
    "/lab/csp-none-login": Scenario(
        path="/lab/csp-none-login",
        title="CSP frame-ancestors 'none'",
        subtitle="Modern explicit frame denial.",
        outcome="Expected result: browsers should refuse to frame this page because CSP forbids all framing.",
        csp="frame-ancestors 'none'; default-src 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; form-action 'self'; base-uri 'self'",
    ),
    "/lab/csp-self-login": Scenario(
        path="/lab/csp-self-login",
        title="CSP frame-ancestors 'self'",
        subtitle="Frameable only by pages served from this exact origin.",
        outcome="Expected result: a local file or foreign-origin PoC should be blocked. A same-origin PoC can frame it.",
        csp="frame-ancestors 'self'; default-src 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; form-action 'self'; base-uri 'self'",
    ),
}


def html_page(title: str, body: str) -> bytes:
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{html.escape(title)}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    :root {{
      --bg: #f4f6f8;
      --panel: #ffffff;
      --ink: #15202b;
      --muted: #556372;
      --line: #d6dde5;
      --accent: #0f766e;
      --danger: #9f1239;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Arial, sans-serif; background: linear-gradient(180deg, #eef2f5 0%, #f8fafb 100%); color: var(--ink); }}
    main {{ max-width: 1040px; margin: 0 auto; padding: 32px 20px 48px; }}
    .hero {{ margin-bottom: 24px; }}
    .hero h1 {{ margin: 0 0 8px; font-size: 32px; }}
    .hero p {{ margin: 0; color: var(--muted); font-size: 16px; line-height: 1.5; }}
    .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 18px;
      box-shadow: 0 10px 24px rgba(21, 32, 43, 0.06);
    }}
    .card h2, .card h3 {{ margin-top: 0; }}
    .card p {{ color: var(--muted); line-height: 1.5; }}
    .pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      background: #e2f7f2;
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.02em;
      text-transform: uppercase;
    }}
    .pill.block {{ background: #fde8ef; color: var(--danger); }}
    .login {{
      max-width: 420px;
      margin: 48px auto 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 18px 32px rgba(21, 32, 43, 0.08);
    }}
    label {{ display: block; margin: 12px 0 6px; font-size: 14px; font-weight: 700; }}
    input {{
      width: 100%;
      padding: 12px 14px;
      border: 1px solid #c6d0da;
      border-radius: 10px;
      background: #fbfcfd;
    }}
    button {{
      width: 100%;
      margin-top: 18px;
      padding: 12px 14px;
      border: 0;
      border-radius: 10px;
      background: #0f172a;
      color: white;
      font-weight: 700;
    }}
    code {{
      font-family: Menlo, Monaco, monospace;
      font-size: 13px;
      background: #eff3f7;
      padding: 2px 6px;
      border-radius: 6px;
    }}
    ul {{ color: var(--muted); line-height: 1.6; }}
    a {{ color: #0f766e; text-decoration: none; }}
  </style>
</head>
<body>
  <main>
    {body}
  </main>
</body>
</html>
"""
    return document.encode("utf-8")


def landing_page(host: str) -> bytes:
    cards = []
    for scenario in SCENARIOS.values():
        protected = scenario.x_frame_options or scenario.csp
        badge = (
            '<span class="pill">Frameable</span>'
            if not protected
            else '<span class="pill block">Protected</span>'
        )
        headers = []
        if scenario.x_frame_options:
            headers.append(f"X-Frame-Options: {html.escape(scenario.x_frame_options)}")
        if scenario.csp:
            headers.append(f"Content-Security-Policy: {html.escape(scenario.csp)}")
        header_html = "<br />".join(headers) if headers else "No frame-defense headers"
        cards.append(
            f"""
            <section class="card">
              {badge}
              <h2>{html.escape(scenario.title)}</h2>
              <p>{html.escape(scenario.subtitle)}</p>
              <p><code>http://{html.escape(host)}{html.escape(scenario.path)}</code></p>
              <p>{header_html}</p>
              <p>{html.escape(scenario.outcome)}</p>
              <p><a href="{html.escape(scenario.path)}">Open scenario</a></p>
            </section>
            """
        )

    body = f"""
    <section class="hero">
      <h1>Click-Jackalope Local Lab</h1>
      <p>
        This lab provides login-style targets with intentionally different framing policies so you can test the
        Burp extension and CLI against known-good outcomes.
      </p>
    </section>
    <section class="card">
      <h3>Suggested use</h3>
      <ul>
        <li>Start this lab server locally.</li>
        <li>Feed one of the URLs below into Click-Jackalope.</li>
        <li>Open the generated PoC in your browser.</li>
        <li>Compare the observed framing result with the expected result shown here.</li>
      </ul>
    </section>
    <section class="grid">
      {"".join(cards)}
    </section>
    """
    return html_page("Click-Jackalope Local Lab", body)


def scenario_page(scenario: Scenario, host: str) -> bytes:
    header_bits = []
    if scenario.x_frame_options:
        header_bits.append(
            f"<code>X-Frame-Options: {html.escape(scenario.x_frame_options)}</code>"
        )
    if scenario.csp:
        header_bits.append(
            f"<code>Content-Security-Policy: {html.escape(scenario.csp)}</code>"
        )
    if not header_bits:
        header_bits.append("<code>No frame protections</code>")

    badge = (
        '<span class="pill">Frameable</span>'
        if not (scenario.x_frame_options or scenario.csp)
        else '<span class="pill block">Protected</span>'
    )
    body = f"""
    <a href="/lab">Back to lab index</a>
    <section class="login">
      {badge}
      <h1>{html.escape(scenario.title)}</h1>
      <p>{html.escape(scenario.subtitle)}</p>
      <p>{" ".join(header_bits)}</p>
      <p>{html.escape(scenario.outcome)}</p>
      <label for="email">Email</label>
      <input id="email" type="email" placeholder="analyst@example.test" />
      <label for="password">Password</label>
      <input id="password" type="password" placeholder="password" />
      <button type="button">Sign in</button>
      <p style="margin-top: 16px; color: #556372;">
        Test URL: <code>http://{html.escape(host)}{html.escape(scenario.path)}</code>
      </p>
    </section>
    """
    return html_page(scenario.title, body)


class LabHandler(BaseHTTPRequestHandler):
    server_version = "ClickJackalopeLab/1.0"

    def do_GET(self) -> None:
        self._serve(include_body=True)

    def do_HEAD(self) -> None:
        self._serve(include_body=False)

    def _serve(self, include_body: bool) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        host = self.headers.get("Host", f"127.0.0.1:{self.server.server_port}")

        if path in {"/", "/lab"}:
            self._send_page(200, landing_page(host), include_body=include_body)
            return

        scenario = SCENARIOS.get(path)
        if scenario is None:
            self._send_page(
                404,
                html_page(
                    "Not Found",
                    "<section class='card'><h1>Not Found</h1><p>Use <a href='/lab'>/lab</a> to view the local test routes.</p></section>",
                ),
                include_body=include_body,
            )
            return

        headers = {}
        if scenario.x_frame_options:
            headers["X-Frame-Options"] = scenario.x_frame_options
        if scenario.csp:
            headers["Content-Security-Policy"] = scenario.csp
        self._send_page(
            200,
            scenario_page(scenario, host),
            extra_headers=headers,
            include_body=include_body,
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_page(
        self,
        status: int,
        body: bytes,
        extra_headers: Optional[Dict[str, str]] = None,
        include_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local Click-Jackalope lab server."
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host interface to bind. Default: 127.0.0.1"
    )
    parser.add_argument(
        "--port", type=int, default=8765, help="Port to listen on. Default: 8765"
    )
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    print(f"Click-Jackalope lab listening on http://{args.host}:{args.port}/lab")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
