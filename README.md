# Click-Jackalope
A compact toolkit for generating clickjacking proofs-of-concept and testing frame defenses.

# Description
clickjacking POC generator for authorized security testing. Drop in a target URL and create a clean iframe test page (with options to auto-open and proxy through local tooling). Built for pentesters who want a fast, reproducible way to verify X-Frame-Options/CSP frame-ancestors protections and to document attack/success cases for reports.

# Usage
click-jackalope -u <url> [-e] [-f <filename>] [-h]

Options:
  -u URL        Target URL to embed in the iframe (required)
  -e            Open the generated HTML with the system default browser (optional)
  -f FILENAME   Output filename (default: clickjack_test.html)
  -h            Show this help / usage

# Examples
# Create a POC file (clickjack_test.html) for the target
click-jackalope -u "https://website.com/"

# Create and open the POC in your default browser
click-jackalope -u "https://website.com" -e

# Create with a custom filename
click-jackalope -u "https://website.com" -f c2poc.html -e

# Installation One-liner
    sudo sh -c 'curl -fsSL https://raw.githubusercontent.com/<GITHUB_USER>/Click-Jackalope/main/click-jackalope -o /usr/local/bin/click-jackalope && chmod +x /usr/local/bin/click-jackalope'
