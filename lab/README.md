# Click-Jackalope Lab

This lab provides local login-style pages with different frame-defense policies so users can verify Click-Jackalope against known expected outcomes.

## Run

```bash
python3 lab/server.py
```

Default address:

```text
http://127.0.0.1:8765/lab
```

## Included Scenarios

- `open-login`: no frame protections, expected to be frameable
- `xfo-deny-login`: `X-Frame-Options: DENY`, expected to be blocked
- `xfo-sameorigin-login`: `X-Frame-Options: SAMEORIGIN`, expected to be blocked by a local-file PoC
- `csp-none-login`: `Content-Security-Policy: frame-ancestors 'none'`, expected to be blocked
- `csp-self-login`: `Content-Security-Policy: frame-ancestors 'self'`, expected to be blocked by a local-file PoC

## Notes

- The Burp extension and CLI both generate local HTML files by default.
- For that reason, `SAMEORIGIN` and `frame-ancestors 'self'` scenarios should fail when tested with the generated PoC unless you deliberately serve the PoC from the same origin as the lab.
