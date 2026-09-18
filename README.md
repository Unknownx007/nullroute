<div align="center">

<img width="721" height="424" alt="1" src="https://github.com/user-attachments/assets/75609ddf-247d-49fd-9a87-f2c671c0d02d" />

**built by DEDSEC · "The browser sees everything. So do we."**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-00d4ff?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-00d4ff?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-000000?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-active-00ff9c?style=flat-square)]()

</div>

---

## ⚠ Legal Notice

> **NULLROUTE performs passive reconnaissance against web applications.**
>
> It fetches the HTML and JavaScript your browser is served, extracts API endpoints, hardcoded secrets, internal hostnames, and analyses source maps.
>
> **Use ONLY on:**
> - Web applications you own.
> - Authorized bug bounty targets (in-scope domains only).
> - Engagements with **written authorization**.
>
> Reconnaissance against systems you do not own or lack explicit authorization for may violate computer-misuse statutes, terms of service, and bug bounty program rules.
>
> **You are solely responsible for your use of this tool. DEDSEC assumes no liability for misuse.**

---

## What is NULLROUTE?

Modern web apps ship everything to the browser. API endpoints, feature flags, hardcoded API keys, JWT secrets, internal hostnames, source maps — all of it arrives in the JavaScript bundles your browser downloads.

NULLROUTE downloads every JS file a site serves and pulls out what developers forgot to remove.

**One command. Full frontend recon. Zero configuration.**

---

## Features

| Analyzer | Extracts |
|---|---|
| **SECRETS** | AWS keys · Google/Firebase · Stripe · GitHub tokens · Slack/Discord/Telegram webhooks · Twilio · SendGrid · Mailgun · Mailchimp · npm/PyPI/NuGet tokens · JWT · RSA/EC/OpenSSH/PGP private keys · MongoDB/PostgreSQL/MySQL/Redis URIs · generic API keys · suspicious hardcoded strings |
| **ENDPOINTS** | Absolute URLs · API paths (`/api/`, `/admin/`, `/internal/`, `/graphql`, `/actuator`) · `fetch()` calls · `axios` calls · jQuery `$.ajax` · XHR `.open()` · GraphQL operations |
| **HOSTS** | Private IPs (RFC1918) · internal TLDs (`.local`, `.internal`, `.corp`, `.lan`, `.intranet`) · cloud infrastructure (S3, CloudFront, Azure Blob, GCP, Firebase) · leaked hostnames |
| **SOURCE MAPS** | Detects `sourceMappingURL` comments · verifies reachability · reports exposed `.map` files that leak original source |

**Severity tagging:** every finding is `HIGH` / `MEDIUM` / `LOW` / `INFO`. High-severity internal endpoints (e.g. `/api/internal/debug`) are auto-escalated.

**Multiple output formats:** colored CLI tables · JSON report · Markdown report. Files are also saved locally for offline inspection.

---

## Requirements

### System

Just Python 3.10+. Nothing else. NULLROUTE is a pure Python tool — no external binaries, no `aircrack-ng`, no scapy.

### Python dependencies

Declared in `pyproject.toml`:

```
requests>=2.31.0
beautifulsoup4>=4.12.0
rich>=13.7.0
```

---

## Install

```bash
git clone https://github.com/Unknownx007/nullroute
cd nullroute

python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

pip install -e .
```

Verify:

```bash
python -m nullroute --version
# NULLROUTE 1.0.0 (DEDSEC)
```

---

## Usage

```bash
python -m nullroute <target>
```

Or if installed as an entry point:

```bash
nullroute <target>
```

The tool first prints an animated banner, then a legal notice, then asks for authorization confirmation. Type `y` to proceed.

### Examples

```bash
# Basic — scan a site
python -m nullroute https://example.com

# Custom output directory
python -m nullroute https://example.com -o ./loot

# Skip inline scripts, skip source maps
python -m nullroute https://example.com --no-inline --no-maps

# Quiet mode — no banner, no animations
python -m nullroute https://example.com --quiet

# Write a specific JSON report
python -m nullroute https://example.com --json out.json

# Write a specific Markdown report
python -m nullroute https://example.com --md report.md

# Longer timeout for slow sites
python -m nullroute https://example.com --timeout 60
```

### Options

```
target                  URL to analyze (required)
-o, --output DIR        Output directory    (default: ./nullroute_output)
--timeout N             HTTP timeout in seconds (default: 20)
--no-inline             Skip inline <script> blocks
--no-maps               Skip source map detection
--json PATH             Write JSON report to PATH
--md PATH               Write Markdown report to PATH
--quiet, -q             Minimal output
--no-anim               Skip banner animations
--version               Print version
```

---

## Typical workflow

```bash
# 1. Scan a target
python -m nullroute https://target.com

# 2. Review the CLI output — secrets are highlighted in red

# 3. Open the Markdown report for the full breakdown
cat nullroute_output/report.md

# 4. Open the JSON report if you want to pipe into other tools
cat nullroute_output/report_*.json | jq '.secrets'

# 5. Inspect the raw JS that was downloaded
ls nullroute_output/js/
```

Every JS file is saved to `nullroute_output/js/` with a content-hash prefix, so you can grep locally:

```bash
grep -rn "api_key" nullroute_output/js/
grep -rn "internal" nullroute_output/js/
```

---

## Output layout

```
nullroute_output/
├── js/                            ← every downloaded JS file
│   ├── a1b2c3d4_main.js
│   ├── e5f6a7b8_app.js
│   └── ...
├── report.md                      ← human-readable Markdown report
└── report_1789666659.json         ← full JSON report
```

The JSON report schema:

```json
{
  "tool":      "NULLROUTE",
  "version":   "1.0.0",
  "target":    "https://example.com/",
  "generated": "2026-09-17T22:37:39",
  "stats": {
    "elapsed":   1.3,
    "js_count":  4,
    "js_bytes":  184320,
    "secrets":   3,
    "endpoints": 47,
    "hosts":     8,
    "maps":      1
  },
  "secrets":      [ { "kind": "...", "severity": "...", "value": "...", "source": "...", "url": "..." } ],
  "endpoints":    [ ... ],
  "hosts":        [ ... ],
  "source_maps":  [ ... ],
  "findings":     [ ... ],
  "log":          [ ... ]
}
```

---

## Recommended test targets

**NULLROUTE is a passive recon tool.** It only reads files your browser is already served. Still — only point it at sites where you have authorization.

---

## How it works

```
1. Fetch root HTML
   ↓
2. Extract <script src="..."> and inline <script> blocks
   ↓
3. Download every JS file (parallel-safe, retries on 5xx)
   ↓
4. Run four analyzers over the JS source:
      • SECRETS    — 40+ regex patterns
      • ENDPOINTS  — URL/path/fetch/axios/XHR/GraphQL extraction
      • HOSTS      — private IPs, internal TLDs, cloud infra
      • MAPS       — sourceMappingURL detection + reachability check
   ↓
5. Rank findings by severity
   ↓
6. Print colored CLI tables + save JSON + save Markdown
```

All requests use `verify=False` (sites with self-signed certs are common in pentest) and are rate-limited by the retry adapter. NULLROUTE never sends a request the browser wouldn't.

---

## Troubleshooting

### "no findings" on a site that clearly has JS

Some sites serve JS **inline** via frameworks that inject scripts at runtime (SPA with a `<div id="root">` and no `<script src>`). In that case:

```bash
python -m nullroute https://target.com --no-inline  # verify baseline
```

Then check the saved HTML: the initial `<script>` might load a single app bundle. That bundle is where everything lives.

### HTTP 403 / bot detection

Large sites (Cloudflare-protected) sometimes block unfamiliar user agents. Try a custom UA — edit `nullroute/core/http.py`, `DEFAULT_UA`.

### Unicode / emoji mangled in output

Your terminal's font doesn't render them. Use a monospace font with Unicode support — JetBrains Mono, Cascadia Code, or Nerd Fonts.

### Animated banner takes too long

Disable with:

```bash
python -m nullroute <target> --no-anim
```

### Report shows paths like `/api/internal/debug` as HIGH severity

That's intentional. Endpoints containing `/admin`, `/internal`, `/debug`, `/private`, `/dev`, `/staging`, `/actuator` are auto-escalated from MEDIUM to HIGH — they're the ones bug hunters chase first.

---

## Roadmap

- [x] HTML parsing — script extraction (BS4 + regex fallback)
- [x] Inline `<script>` capture
- [x] Multi-analyzer pipeline (secrets / endpoints / hosts / maps)
- [x] Rich CLI with colored tables + animated banner
- [x] JSON + Markdown reports
- [x] Local JS archive (grep-friendly)
- [ ] AST-based JS analysis (catch secrets in expression form)
- [ ] `--feed-from-dir` mode — analyze a local `reconforge_output/` mirror
- [ ] Webpack chunk graph reconstruction
- [ ] Subdomain cross-referencing from all downloaded JS
- [ ] Secret validation (test if a leaked key actually works)
- [ ] Diff mode — compare two scans of the same site to find new leaks
- [ ] CI integration — run as a GitHub Action on every deploy

---

## Directory layout

```
nullroute/
├── nullroute/
│   ├── __init__.py
│   ├── __main__.py             entry point + orchestration
│   ├── banner.py               animated wordmark + 2D logo
│   ├── theme.py                color tokens
│   ├── core/
│   │   ├── errors.py
│   │   ├── logger.py           structured logger
│   │   ├── http.py             HTTP client with retries
│   │   └── ui.py               rich panels / tables / progress
│   ├── recon/
│   │   ├── html_parser.py      extract <script> refs + inline blocks
│   │   ├── js_fetcher.py       download + save JS files
│   │   └── source_maps.py      detect + fetch .map files
│   ├── analyzers/
│   │   ├── secrets.py          40+ regex patterns
│   │   ├── endpoints.py        URL / fetch / axios / XHR / GraphQL
│   │   └── hosts.py            IPs / internal TLDs / cloud infra
│   ├── report/
│   │   ├── findings.py         merge + dedupe + rank
│   │   └── export.py           JSON + Markdown
│   └── data/
│       └── secrets_patterns.py compiled regex rules
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Credits

**Built by DEDSEC.**

Inspired by the excellent work of:

- **LinkFinder** — endpoint extraction from JS (Python 2, now discontinued)
- **SecretFinder** — regex-based secret detection
- **trufflehog** / **gitleaks** — secret detection in git repos (different threat model)
- **Nuclei** — templated scanning and severity ranking
- **Packer Fuzzer** / **JSFScan** — bundler-specific analysis

NULLROUTE combines their ideas in a single, modern, Python 3.10+ package with a proper multi-analyzer pipeline and native structured reports.

---

## License

MIT License

Copyright (c) 2026 DEDSEC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

<div align="center">

*"We don't break the app. We read its diary."*

</div>
