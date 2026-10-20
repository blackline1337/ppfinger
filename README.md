# ppfngr

A WAF/CDN fingerprinter and sqlmap tamper-script advisor, with a built-in
PHP/ASP(X) form finder. Point it at a target and it tells you **what's
protecting it** and **which sqlmap `--tamper` scripts to try first**, then
crawls for forms and hands you ready-to-run `curl` commands for the ones
worth testing.

> For authorized security testing / pentesting / CTF use only.

## What it does

1. **WAF/CDN fingerprinting** — sends a baseline request, then one probe
   per attack category (SQLi, XSS, path traversal, command injection), and
   matches the responses against a hand-written signature set covering
   Cloudflare, Akamai, AWS WAF, Imperva Incapsula, F5 BIG-IP ASM,
   ModSecurity/OWASP CRS, Sucuri, Barracuda, FortiWeb, Citrix NetScaler,
   Wordfence, Azure Front Door, and more.
2. **sqlmap's own WAF/IPS heuristic, reimplemented verbatim** — the same
   "kitchen sink" SQLi+XSS+traversal+RCE payload sqlmap's
   `checkWaf()` sends, diffed against the baseline by similarity ratio.
   Flags interception even when no vendor signature matches.
3. **sqlmap tamper script recommendations** — maps whatever was detected
   to a ranked list of `--tamper` scripts with a one-line reason each,
   plus a ready-to-paste `sqlmap --tamper=...` flag.
4. **TLS certificate check** — flags a self-signed / hostname-mismatched /
   expired cert as an informational warning (who it's actually issued to,
   who signed it, when it expires) without ever blocking the scan.
5. **PHP/ASP(X) form finder** — crawls the target (same-domain, shallow,
   rate-limited), fingerprints each form's backend language from the
   action extension, response headers, cookies, and framework-specific
   body markers (Laravel/Livewire, ThinkPHP, exposed `composer.json`),
   keeps only PHP and ASP/ASP.NET forms (Java/JSP and JSON/REST API
   endpoints are skipped), and writes each one out as a ready-to-run
   `curl` command.
6. **Optional extras** — a bounded rate-limit probe to catch edge/CDN
   throttling, routing through Tor, and a random browser User-Agent.

## Install

```bash
git clone git@github.com:blackline1337/ppfinger.git
cd ppfinger
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # Linux/macOS
pip install -r requirements.txt
```

## Usage

```
python ppfinger.py <target> [options]
```

Basic scan (WAF fingerprint + tamper suggestions + form crawl):

```bash
python ppfinger.py https://target.example.com
```

WAF/tamper check only, skip the form crawl:

```bash
python ppfinger.py https://target.example.com --no-crawl
```

Deeper crawl, slower pace, custom output directory:

```bash
python ppfinger.py https://target.example.com --max-pages 25 --delay 1.0 --out-dir ./results
```

Also check for rate-limit-based protection:

```bash
python ppfinger.py https://target.example.com --rate-probe --rate-probe-count 15
```

Route everything through Tor (requires a running Tor client):

```bash
python ppfinger.py https://target.example.com --tor
```

Use a random browser User-Agent instead of ppfngr's own:

```bash
python ppfinger.py https://target.example.com --random-agent
```

### Options

| Flag | Default | Description |
|---|---|---|
| `target` | — | Target base URL. Scheme defaults to `https://` if omitted. |
| `--max-pages N` | `10` | Max pages to crawl for forms. |
| `--delay N` | `0.5` | Delay (seconds) between requests. |
| `--out-dir DIR` | `.` | Directory to write `form_results-<target>.txt` into. |
| `--no-crawl` | off | Skip form crawling; only run WAF fingerprinting + tamper suggestions. |
| `--rate-probe` | off | Fire a small burst of back-to-back requests to check for rate-limit-based protection (e.g. Cloudflare 429s). |
| `--rate-probe-count N` | `10` | Number of requests to send for `--rate-probe`. |
| `--tor` | off | Route all traffic through a local Tor SOCKS proxy. Aborts immediately if Tor isn't reachable (no silent fallback to a direct connection). |
| `--tor-port N` | `9050` | Local Tor SOCKS port to use with `--tor`. |
| `--random-agent` | off | Use a random, common browser User-Agent instead of ppfngr's own. |
| `--no-color` | off | Disable colored output and the startup banner. |

### Output

Forms kept by the crawler are written to `form_results-<target>.txt`,
e.g.:

```
# ppfinger form results for https://target.example.com
# Generated: 2026-10-20 14:21:03
# 2 form(s) kept (PHP / ASP / ASP.NET). Java/API forms excluded.

# Found on: https://target.example.com/login.php
# Method:   POST  Tech: PHP
curl "https://target.example.com/login.php" --data "username=testuser&password=Password123%21&csrf_token=abc123"

# Found on: https://target.example.com/search.php
# Method:   GET  Tech: PHP
curl "https://target.example.com/search.php?q=test&category=all"
```

## Disclaimer

This tool sends intentionally attack-shaped requests (SQLi/XSS/traversal/
command-injection-looking payloads) to fingerprint WAF behavior, and
crawls/submits discovered forms. Only run it against systems you own or
are explicitly authorized to test.

## Acknowledgments

Approach informed by [wafw00f](https://github.com/EnableSecurity/wafw00f),
[whatwaf](https://github.com/Ekultek/WhatWaf), and
[sqlmap](https://github.com/sqlmapproject/sqlmap) (its `checkWaf()`
heuristic is reimplemented here with the same payload/ratio sqlmap itself
uses), plus PHP-detection signatures cross-checked against
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).
