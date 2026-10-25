#!/usr/bin/env python3
"""
ppfinger.py - WAF fingerprinter + sqlmap tamper-script recommender + PHP/ASP(X) form finder.

For authorized security testing / pentesting / CTF use only.

What it does:
  1. Sends a baseline request, then one probe per attack category (SQLi,
     XSS, path traversal, command injection) -- the same "try several
     payload shapes" idea wafw00f/whatwaf use, since a WAF may only have a
     rule for one category. Matches the responses against a set of known
     WAF signatures (vendor-specific headers, cookies, block-page text,
     status code behavior changes).
  2. Also runs sqlmap's own generic WAF/IPS heuristic verbatim (see
     lib/controller/checks.py:checkWaf() / IPS_WAF_CHECK_PAYLOAD in
     sqlmap's settings.py): one "kitchen sink" SQLi+XSS+traversal+RCE
     payload, diffed against the baseline page by similarity ratio. This
     flags interception even when no vendor signature matches.
  3. Optionally (--rate-probe, off by default) fires a small bounded burst
     of requests to check for rate-limit-based edge protection (429s,
     Retry-After) -- a signal the single-shot probes above can't surface.
  4. Maps any detected WAF(s) to a recommended list of sqlmap --tamper
     scripts (same idea as whatwaf's tamper-suggestion table), with a short
     rationale for each. With --verify-tampers, actually tests them.
  5. Crawls the target (same-domain only, shallow, rate-limited) looking for
     HTML <form> elements, in the spirit of sqlmap's --forms. For each form
     found, it fingerprints the backend language from the form action
     extension, response headers, cookies, body markers (Laravel/Livewire,
     ThinkPHP, framework default pages) and exposed composer.json/.lock.
     Only forms that look like PHP or ASP/ASP.NET are kept (Java/JSP/.do and
     anything that looks like a JSON/REST API endpoint are skipped). Each
     kept form is written out as a ready-to-run curl command to
     form_results-<target>.txt.
  6. Runs entirely on asyncio + aiohttp. In multi-target (stdin) mode,
     several targets are scanned concurrently -- how many is sized from
     available system RAM by default (~25% of it), with a live memory
     watcher that pauses starting *new* target scans (without touching
     ones already in flight) if system memory climbs past a ceiling, so a
     long subdomain-list run doesn't snowball into an OOM.

Usage:
    python ppfinger.py https://target.example.com
    python ppfinger.py https://target.example.com --max-pages 15 --delay 1.0
    python ppfinger.py https://target.example.com --out-dir ./results
    python ppfinger.py https://target.example.com --rate-probe --rate-probe-count 15
    cat subdomains.txt | python ppfinger.py --concurrency 8 --json
"""

import argparse
import asyncio
import contextvars
import difflib
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.parse as urlparse
from collections import deque

import aiohttp
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
from cryptography import x509
from cryptography.hazmat.backends import default_backend

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

colorama_init()  # makes ANSI colors work on Windows terminals too

# The "ansi_shadow" figlet font (used for the startup banner) is built from
# Unicode box-drawing/full-block characters. Some Windows consoles still
# default stdout to a legacy codepage (cp1252) that can't encode them and
# would crash with UnicodeEncodeError on the very first print. Force UTF-8
# with lossy fallback instead of a hard crash -- worst case on an exotic
# terminal is a few replacement characters in the banner, never a traceback.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


# --------------------------------------------------------------------------
# 0. Color output + per-target output buffering
#
# In multi-target mode several targets are scanned *concurrently*, but
# their terminal output must stay readable -- one target's block printed
# whole, never interleaved line-by-line with another's. Each per-target
# asyncio task gets its own private output buffer and error-dedupe table
# via contextvars (asyncio.create_task() snapshots a fresh copy of the
# current context for each task, so .set() inside one task's coroutine
# never touches another task's copy -- that's what makes this safe without
# a lock). The buffer is flushed as one atomic print() when that target's
# scan finishes.
# --------------------------------------------------------------------------

def c_info(msg):
    return f"{Fore.CYAN}{msg}{Style.RESET_ALL}"


def c_ok(msg):
    return f"{Fore.GREEN}{msg}{Style.RESET_ALL}"


def c_warn(msg):
    return f"{Fore.YELLOW}{msg}{Style.RESET_ALL}"


def c_bad(msg):
    return f"{Fore.RED}{msg}{Style.RESET_ALL}"


def c_bold(msg):
    return f"{Style.BRIGHT}{msg}{Style.RESET_ALL}"


def c_dim(msg):
    return f"{Style.DIM}{msg}{Style.RESET_ALL}"


def c_mag(msg):
    return f"{Fore.MAGENTA}{msg}{Style.RESET_ALL}"


_OUTPUT_BUF = contextvars.ContextVar("ppfngr_output_buf", default=None)
_SEEN_ERRORS_VAR = contextvars.ContextVar("ppfngr_seen_errors", default=None)


def _emit(line=""):
    """Writes one line to the current task's output buffer if one has been
    set (inside run_target()), otherwise prints immediately (banner, Tor
    setup, the final batch summary -- everything that runs outside a
    per-target task)."""
    buf = _OUTPUT_BUF.get()
    if buf is not None:
        buf.append(line)
    else:
        print(line)


def _seen_errors():
    d = _SEEN_ERRORS_VAR.get()
    if d is None:
        d = {}
        _SEEN_ERRORS_VAR.set(d)
    return d


# Severity -> color, loosely matching nuclei's own convention (info=cyan,
# low=green, medium=yellow, high=red, critical=bold red).
_SEVERITY_COLOR = {
    "info": c_info,
    "low": c_ok,
    "medium": c_warn,
    "high": c_bad,
    "critical": lambda s: c_bold(c_bad(s)),
}


def finding(fid, protocol, severity, target, detail=""):
    """Prints one result in nuclei's own compact line format:
    `[template-id] [protocol] [severity] matched-at  extra-info`, each
    bracketed field colored on its own (id bold, protocol dim, severity by
    level). This is the main unit of output -- one line per check, nothing
    to scroll past, the way `nuclei` itself reads."""
    sev_color = _SEVERITY_COLOR.get(severity, c_dim)
    line = f"{c_bold('[' + fid + ']')} {c_dim('[' + protocol + ']')} {sev_color('[' + severity + ']')} {target}"
    if detail:
        line += f" {c_dim(detail)}"
    _emit(line)


def sub(line):
    """A dim, indented continuation line under the finding above it (extra
    context -- probe statuses, tamper script breakdown -- that belongs to
    that result but would clutter the single-line format itself)."""
    _emit(c_dim(f"      {line}"))


# Plain-ASCII fallback wordmark, used only if pyfiglet isn't installed for
# some reason (it's a hard requirement in requirements.txt, so this is just
# a belt-and-suspenders path -- never crash over a missing banner).
BANNER = r"""
  ___  ___  _____ _
  | _ \| _ \| __(_)_ _  __ _ ___ _ _
  |  _/|  _/| _|| | ' \/ _` / -_) '_|
  |_|  |_|  |_| |_|_||_\__, \___|_|
                        |___/   WAF fingerprint + sqlmap tamper advisor
"""


def _gradient_lines(text_block, start_rgb, end_rgb):
    """Colors each line of a multi-line block of text with a true-color
    (24-bit) ANSI gradient interpolated from start_rgb to end_rgb, top to
    bottom. colorama's Fore only has the 16 legacy ANSI colors, so this
    writes raw \\x1b[38;2;r;g;bm escapes directly -- colorama's output
    wrapper still intercepts and converts/passes these through correctly on
    Windows. Returns the block unmodified if there's nothing to color."""
    lines = text_block.rstrip("\n").split("\n")
    n = max(1, len(lines) - 1)
    out = []
    for i, line in enumerate(lines):
        if not line.strip():
            out.append(line)
            continue
        t = i / n
        r = round(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * t)
        g = round(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * t)
        b = round(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * t)
        out.append(f"\x1b[38;2;{r};{g};{b}m{line}{Style.RESET_ALL}")
    return "\n".join(out)


# Short flavor line inside the banner box -- a handful of real WAF vendor
# names and the kind of header/cookie strings this tool actually fingerprints
# on, purely for look/feel. Kept to one short line on purpose (nothing to
# scroll past) -- see WAF_SIGNATURES and detect_tech() for the real logic.
_BANNER_FLAVOR = "Cl0udfl4re \u00b7 Ak4mai \u00b7 M0dSecur1ty"


def _pad_center(text, width):
    extra = max(0, width - len(text))
    left = extra // 2
    return " " * left + text + " " * (extra - left)


def print_banner():
    """Prints the startup banner: the "ppfngr" wordmark rendered with
    pyfiglet's 'ansi_shadow' font (big, solid block letters -- the style
    used by a lot of modern CLI tools), colored with a dark-to-neon green
    top-to-bottom gradient, boxed, with a one-line strip of WAF names and
    fingerprint-y header/cookie strings for flavor. Falls back to a
    plain-ASCII wordmark (no box) if pyfiglet is missing."""
    try:
        import pyfiglet
        art_lines = pyfiglet.figlet_format("ppfngr", font="ansi_shadow").rstrip("\n").split("\n")
    except Exception:
        print(c_bold(c_mag(BANNER)))
        print(c_bold(c_mag("  WAF fingerprint + sqlmap tamper advisor")))
        print(c_dim("  for authorized security testing / pentesting / CTF use only\n"))
        return

    subtitle = "WAF fingerprint + sqlmap tamper advisor"
    footer = "authorized security testing / pentesting / CTF use only"
    content_w = max(len(l) for l in art_lines + [subtitle, _BANNER_FLAVOR, footer])

    def border(s):
        return c_bold(c_mag(s))

    side = border(chr(0x2502))  # box-drawing vertical bar
    print(border(chr(0x250c) + chr(0x2500) * (content_w + 2) + chr(0x2510)))  # top-left corner + top rule + top-right corner

    padded_art = "\n".join(line.ljust(content_w) for line in art_lines)
    for line in _gradient_lines(padded_art, (10, 60, 10), (57, 255, 20)).split("\n"):
        print(f"{side} {line} {side}")

    print(f"{side} {c_bold(_pad_center(subtitle, content_w))} {side}")
    print(f"{side} {c_dim(_pad_center(_BANNER_FLAVOR, content_w))} {side}")
    print(f"{side} {c_dim(_pad_center(footer, content_w))} {side}")
    print(border(chr(0x2514) + chr(0x2500) * (content_w + 2) + chr(0x2518)))  # bottom-left + bottom rule + bottom-right
    print()


DEFAULT_TIMEOUT = 10
DEFAULT_TOR_TIMEOUT = 15  # Tor circuits add real latency -- a 10s timeout would false-positive as "unreachable" often
DEFAULT_UA = "ppfinger/1.0 (+authorized security testing)"

# A small pool of common, real-world browser UAs for --random-agent. Not
# trying to be exhaustive (sqlmap ships hundreds) -- just enough spread
# across OS/browser to not look like a single hardcoded scanner string.
# Some WAF rules specifically allow/penalize by UA, so a fixed scanner UA
# (the default above) is itself sometimes a detection vector.
RANDOM_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0",
]


# --------------------------------------------------------------------------
# 1. WAF SIGNATURES
#
# Each signature is checked against both the baseline response and a probe
# response (probe = baseline URL with a `?ppfinger=<sqli-ish payload>` query
# appended). A WAF is "matched" if any of its header/cookie/body patterns
# hit on either response, or if the probe response status differs from the
# baseline in a way that signature expects (e.g. probe blocked with 406/403
# while baseline was 200).
#
# This is a hand-written signature set based on publicly documented,
# well-known WAF fingerprints (vendor header names, cookie names, default
# block-page wording) -- not a copy of wafw00f's signature file. Extend this
# dict as you confirm new signatures in your own testing.
# --------------------------------------------------------------------------

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": [("Server", r"cloudflare"), ("CF-RAY", r".+"), ("cf-mitigated", r".+")],
        "cookies": [r"__cfduid", r"__cf_bm", r"cf_clearance"],
        "body": [r"Attention Required! \| Cloudflare", r"cloudflare[- ]nginx", r"Ray ID:"],
        "block_status": [403, 503],
    },
    "AWS WAF": {
        "headers": [("X-Amzn-RequestId", r".+"), ("X-Amz-Cf-Id", r".+")],
        "cookies": [r"AWSALB", r"AWSALBCORS"],
        "body": [r"Request blocked\.", r"ERROR The request could not be satisfied"],
        "block_status": [403],
    },
    "Akamai": {
        "headers": [("Server", r"AkamaiGHost"), ("X-Akamai-Transformed", r".+")],
        "cookies": [r"ak_bmsc", r"bm_sv"],
        "body": [r"Access Denied</title>\s*</head>\s*<body>\s*You don't have permission",
                 # Akamai's own reference ID has 3+ dot-separated segments
                 # (e.g. "Reference #18.xxxxxxxx.1234567.abcdef"); a bare
                 # "Reference #<num>.<num>" is too generic and collides with
                 # other vendors' (e.g. ModSecurity's) error pages.
                 r"Reference #\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+"],
        "block_status": [403],
    },
    "Imperva Incapsula": {
        "headers": [("X-CDN", r"Incapsula"), ("X-Iinfo", r".+")],
        "cookies": [r"incap_ses_", r"visid_incap_"],
        "body": [r"Incapsula incident ID", r"_Incapsula_Resource"],
        "block_status": [403],
    },
    "F5 BIG-IP ASM": {
        "headers": [("Server", r"BigIP"), ("X-WA-Info", r".+")],
        "cookies": [r"TS[0-9a-fA-F]{8,}", r"BIGipServer"],
        "body": [r"The requested URL was rejected", r"support ID is"],
        "block_status": [403],
    },
    "ModSecurity / OWASP CRS": {
        "headers": [("Server", r"Mod_Security|ModSecurity")],
        "cookies": [],
        "body": [r"This error was generated by Mod_Security", r"NOYB", r"Reference #\d+\.\d+",
                 r"ModSecurity Action"],
        "block_status": [403, 406, 501],
    },
    "Sucuri": {
        "headers": [("Server", r"Sucuri/Cloudproxy"), ("X-Sucuri-ID", r".+"), ("X-Sucuri-Cache", r".+")],
        "cookies": [r"sucuri-cloudproxy-uuid"],
        "body": [r"Access Denied - Sucuri Website Firewall", r"sucuri_cloudproxy"],
        "block_status": [403],
    },
    "Barracuda": {
        "headers": [],
        "cookies": [r"barra_counter_session", r"BNI__BARRACUDA_LB_COOKIE"],
        "body": [r"You have been blocked", r"Barracuda"],
        "block_status": [403],
    },
    "Fortinet FortiWeb": {
        "headers": [("Server", r"FortiWeb")],
        "cookies": [r"FORTIWAFSID"],
        "body": [r"FortiWeb", r"the requested url was blocked"],
        "block_status": [403],
    },
    "Citrix NetScaler": {
        "headers": [("Via", r"NS-CACHE")],
        "cookies": [r"citrix_ns_id", r"NSC_"],
        "body": [r"NetScaler", r"Citrix"],
        "block_status": [403],
    },
    "Wordfence": {
        "headers": [],
        "cookies": [r"wordfence_verifiedHuman"],
        "body": [r"Generated by Wordfence", r"This response was generated by Wordfence"],
        "block_status": [403],
    },
    "DenyAll / Rohde Schwarz": {
        "headers": [],
        "cookies": [],
        "body": [r"Condition Intercepted", r"DenyAll"],
        "block_status": [403],
    },
    "Azure Front Door / App Gateway": {
        "headers": [("X-Azure-Ref", r".+"), ("X-FD-HealthProbe", r".+")],
        "cookies": [r"ARRAffinity"],
        "body": [r"The page you are looking for is currently unavailable", r"Azure Front Door"],
        "block_status": [403],
    },
    "Generic / Unknown WAF": {
        # Fallback heuristic bucket: used only when the probe is clearly
        # blocked (403/406/429/999 etc.) but no vendor signature matched.
        "headers": [],
        "cookies": [],
        "body": [],
        "block_status": [403, 406, 429, 999],
    },
}

# Payloads used to provoke a WAF into reacting. Each is sent as its own,
# separate GET probe (never combined into a flood) -- the same "send a
# handful of different attack-shaped requests and see which get blocked"
# approach wafw00f/whatwaf use, just widened past a single SQLi string so a
# WAF that only has XSS/LFI/RCE rules (and no SQLi rule) still gets caught.
WAF_PROBE_PAYLOADS = {
    "sqli": "' OR '1'='1' -- -",
    "xss": "<script>alert(1)</script>",
    "traversal": "../../../../etc/passwd",
    "cmdi": "; cat /etc/passwd;",
}

# sqlmap's own generic WAF/IPS heuristic (lib/controller/checks.py:checkWaf,
# lib/core/settings.py:IPS_WAF_CHECK_PAYLOAD/IPS_WAF_CHECK_RATIO). Rather than
# matching a vendor signature, sqlmap fires one "kitchen sink" payload that
# mixes a SQLi UNION, an XSS tag, a path traversal, and an xp_cmdshell/RCE
# attempt into a single request, then diffs the response against the
# baseline page with a similarity ratio -- if the page comes back too
# different (ratio below IPS_WAF_CHECK_RATIO), *something* intercepted it,
# even if no known vendor signature matched. Values below are copied as-is
# from sqlmap's settings.py so the heuristic behaves the same way.
SQLMAP_IPS_WAF_CHECK_PAYLOAD = (
    "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',"
    "table_name FROM information_schema.tables WHERE 2>1--/**/; "
    "EXEC xp_cmdshell('cat ../../../etc/passwd')#"
)
SQLMAP_IPS_WAF_CHECK_RATIO = 0.5


# --------------------------------------------------------------------------
# 2. WAF -> sqlmap tamper script recommendations
#
# Mirrors the idea behind whatwaf's determine_tamper_scripts(): map a
# detected WAF/vendor to the sqlmap tamper scripts most commonly reported to
# help bypass it, with a one-line reason pulled from sqlmap's own tamper
# docstrings/purpose. Always verify against the current target -- this is a
# starting point, not a guarantee.
# --------------------------------------------------------------------------

TAMPER_MAP = {
    "Cloudflare": [
        ("space2comment", "Replaces spaces with /**/ comments to dodge keyword/space-based rules"),
        ("between", "Replaces > and = with NOT BETWEEN/BETWEEN to avoid simple operator filters"),
        ("charunicodeescape", "URL-encodes chars as %uXXXX, slips past some unicode-naive filters"),
        ("randomcase", "Randomizes keyword case (SeLeCt) to beat case-sensitive signatures"),
    ],
    "AWS WAF": [
        ("space2comment", "Breaks up SPACE-based keyword signatures used by AWS managed rule groups"),
        ("apostrophemask", "Replaces ' with its UTF-8 fullwidth equivalent %EF%BC%87"),
        ("multiplespaces", "Adds multiple spaces around keywords to break regex-based rules"),
    ],
    "Akamai": [
        ("space2plus", "Replaces spaces with + (Akamai Kona often normalizes %20 but not +)"),
        ("charencode", "URL-encodes the whole payload to bypass plain-text regex matching"),
        ("overlongutf8", "Uses overlong UTF-8 encoding to confuse byte-level regex engines"),
    ],
    "Imperva Incapsula": [
        ("space2comment", "Breaks keyword spacing rules"),
        ("charunicodeescape", "Unicode-escapes chars; Incapsula rules are often ASCII-centric"),
        ("randomcase", "Randomizes keyword casing against case-sensitive patterns"),
        ("versionedkeywords", "Wraps keywords in MySQL version comments /*!50000SELECT*/"),
    ],
    "F5 BIG-IP ASM": [
        ("space2comment", "Avoids space-delimited signature matches"),
        ("equaltolike", "Replaces = with LIKE to dodge operator-based signatures"),
        ("greatest", "Replaces MAX() with GREATEST() to avoid common function blacklists"),
    ],
    "ModSecurity / OWASP CRS": [
        ("charunicodeescape", "Unicode-escaping evades several CRS regex rules (common, well-documented)"),
        ("space2comment", "Defeats SPACE-based CRS rule 981257 and similar"),
        ("randomcase", "Evades case-sensitive CRS keyword patterns"),
        ("apostrophemask", "Avoids literal ' matching used in several injection rules"),
        ("multiplespaces", "Breaks up strict single-space regex assumptions in older CRS rules"),
    ],
    "Sucuri": [
        ("space2comment", "Breaks spacing-based detection"),
        ("charencode", "Full URL-encoding to dodge plaintext body/WAF rule matching"),
    ],
    "Barracuda": [
        ("space2comment", "Breaks keyword/space signature matching"),
        ("charunicodeescape", "Unicode escaping against ASCII-focused rules"),
    ],
    "Fortinet FortiWeb": [
        ("space2comment", "Breaks spacing-based signatures"),
        ("equaltolike", "Avoids '=' operator pattern matches"),
        ("randomcase", "Case randomization against case-sensitive rules"),
    ],
    "Citrix NetScaler": [
        ("space2comment", "Generic spacing bypass, effective against many AppFW default rules"),
        ("charencode", "URL-encode payload against plaintext matching"),
    ],
    "Wordfence": [
        ("space2comment", "Breaks spacing-based regex rules used by Wordfence's WAF ruleset"),
        ("charunicodeescape", "Unicode escaping against PHP-regex based rule matching"),
    ],
    "Azure Front Door / App Gateway": [
        ("space2comment", "Breaks spacing-based default rule set matches (OWASP CRS based)"),
        ("charunicodeescape", "Unicode escaping against CRS-based Azure WAF policy"),
    ],
    "DenyAll / Rohde Schwarz": [
        ("space2comment", "Generic spacing bypass"),
        ("charencode", "Full encoding bypass against plaintext pattern rules"),
    ],
    "Generic / Unknown WAF": [
        ("space2comment", "Safe general-purpose first try: breaks naive space/keyword matching"),
        ("charunicodeescape", "Safe general-purpose second try: unicode-escapes special chars"),
        ("randomcase", "Low-risk: randomizes SQL keyword casing"),
        ("between", "Low-risk: swaps > / = for NOT BETWEEN / BETWEEN"),
    ],
}


# --------------------------------------------------------------------------
# 2b. Tamper verification (--verify-tampers)
#
# Rather than just suggesting tampers by vendor name, actually apply each
# one to sqlmap's own kitchen-sink attack payload (SQLMAP_IPS_WAF_CHECK_PAYLOAD,
# the same one sqlmap_waf_heuristic() uses) and resend it, then compare the
# response against the clean baseline page with the same similarity-ratio
# technique sqlmap itself uses for checkWaf(). A ratio near 1.0 means the
# response looks just like an ordinary page again (the tamper likely got
# past whatever blocked the untampered payload); a ratio near 0 means it
# still looks like a block page.
#
# These are practical reimplementations of the real tamper/*.py scripts in
# the sqlmap source (same regexes/algorithms, ported from the actual
# source), not byte-exact -- in particular randomcase/multiplespaces/
# versionedkeywords use a small hand-picked SQL keyword set here instead of
# sqlmap's full kb.keywords list, since we're only ever tampering our own
# synthetic probe payload, not arbitrary user-supplied SQL.
# --------------------------------------------------------------------------

SQL_KEYWORDS = {
    "AND", "OR", "SELECT", "UNION", "ALL", "NULL", "FROM", "WHERE", "TABLE", "TABLES",
    "SCHEMA", "INFORMATION_SCHEMA", "CONCAT", "CHAR", "CAST", "EXEC", "EXECUTE", "AS",
    "WAITFOR", "DELAY", "SLEEP", "BENCHMARK", "DROP", "INSERT", "UPDATE", "DELETE",
    "ORDER", "BY", "GROUP", "HAVING", "LIKE", "BETWEEN", "CASE", "WHEN", "THEN",
    "ELSE", "END", "XP_CMDSHELL", "IFNULL", "CURRENT_USER",
}


def _tamper_space2comment(payload):
    if not payload:
        return payload
    out = []
    quote = doublequote = firstspace = False
    for i, ch in enumerate(payload):
        if not firstspace:
            if ch.isspace():
                firstspace = True
                out.append("/**/")
                continue
        elif ch == "'" and (i == 0 or payload[i - 1] != "\\"):
            quote = not quote
        elif ch == '"' and (i == 0 or payload[i - 1] != "\\"):
            doublequote = not doublequote
        elif ch == " " and not doublequote and not quote:
            out.append("/**/")
            continue
        out.append(ch)
    return "".join(out)


def _tamper_space2plus(payload):
    if not payload:
        return payload
    out = []
    quote = doublequote = firstspace = False
    for i, ch in enumerate(payload):
        if not firstspace:
            if ch.isspace():
                firstspace = True
                out.append("+")
                continue
        elif ch == "'" and (i == 0 or payload[i - 1] != "\\"):
            quote = not quote
        elif ch == '"' and (i == 0 or payload[i - 1] != "\\"):
            doublequote = not doublequote
        elif ch == " " and not doublequote and not quote:
            out.append("+")
            continue
        out.append(ch)
    return "".join(out)


def _tamper_charunicodeescape(payload):
    if not payload:
        return payload
    out = []
    i = 0
    while i < len(payload):
        if payload[i] == "%" and i < len(payload) - 2 and payload[i + 1] in string.hexdigits and payload[i + 2] in string.hexdigits:
            out.append("\\u00%s" % payload[i + 1:i + 3])
            i += 3
        else:
            out.append("\\u%04X" % ord(payload[i]))
            i += 1
    return "".join(out)


def _tamper_charencode(payload):
    if not payload:
        return payload
    out = []
    i = 0
    while i < len(payload):
        if payload[i] == "%" and i < len(payload) - 2 and payload[i + 1] in string.hexdigits and payload[i + 2] in string.hexdigits:
            out.append(payload[i:i + 3])
            i += 3
        else:
            out.append("%%%.2X" % ord(payload[i]))
            i += 1
    return "".join(out)


def _tamper_overlongutf8(payload):
    if not payload:
        return payload
    out = []
    i = 0
    while i < len(payload):
        if payload[i] == "%" and i < len(payload) - 2 and payload[i + 1] in string.hexdigits and payload[i + 2] in string.hexdigits:
            out.append(payload[i:i + 3])
            i += 3
        else:
            ch = payload[i]
            if ch not in string.ascii_letters + string.digits:
                ordv = ord(ch)
                if ordv <= 0x7FF:
                    out.append("%%%.2X%%%.2X" % (0xc0 + (ordv >> 6), 0x80 + (ordv & 0x3f)))
                else:
                    out.append("".join("%%%.2X" % b for b in ch.encode("utf8")))
            else:
                out.append(ch)
            i += 1
    return "".join(out)


def _tamper_apostrophemask(payload):
    return payload.replace("'", "%EF%BC%87") if payload else payload


def _tamper_randomcase(payload):
    if not payload:
        return payload

    def repl(m):
        word = m.group()
        if word.upper() in SQL_KEYWORDS:
            return "".join(c.upper() if random.randint(0, 1) else c.lower() for c in word)
        return word

    return re.sub(r"\b[A-Za-z_]{2,}\b", repl, payload)


def _tamper_multiplespaces(payload):
    if not payload:
        return payload
    words = []
    for m in re.finditer(r"\b[A-Za-z_]+\b", payload):
        w = m.group()
        if w.upper() in SQL_KEYWORDS and w not in words:
            words.append(w)
    out = payload
    for w in words:
        out = re.sub(
            r"(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % re.escape(w),
            lambda m, w=w: " " * random.randint(1, 4) + w + " " * random.randint(1, 4),
            out,
        )
    return out


def _tamper_versionedkeywords(payload):
    if not payload:
        return payload

    def repl(m):
        word = m.group("word")
        if word.upper() in SQL_KEYWORDS:
            return m.group().replace(word, "/*!%s*/" % word)
        return m.group()

    out = re.sub(r"(?:^|(?<=\W))(?P<word>[A-Za-z_]+)(?=[^\w(]|\Z)", repl, payload)
    return out.replace(" /*!", "/*!").replace("*/ ", "*/")


def _tamper_equaltolike(payload):
    if not payload:
        return payload
    return re.sub(r"\s*(?<![<>!=])=(?!=)\s*", " LIKE ", payload)


def _tamper_between(payload):
    if not payload:
        return payload
    retVal = payload
    m = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*(?<![<])>(?!=)\s*([^>]+)\s*\Z", payload)
    if m:
        repl = "%s %s NOT BETWEEN 0 AND %s" % (m.group(2), m.group(4), m.group(5))
        retVal = retVal.replace(m.group(0), repl)
    else:
        retVal = re.sub(r"\s*(?<![<])>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))", r" NOT BETWEEN 0 AND \g<1>", payload)

    if retVal == payload:
        m2 = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*(?<![<>!])=(?!=)\s*([\w()]+)\s*", payload)
        if m2:
            repl = "%s %s BETWEEN %s AND %s" % (m2.group(2), m2.group(4), m2.group(5), m2.group(5))
            retVal = retVal.replace(m2.group(0), repl)

    retVal = re.sub(r"(?i)(\bWHEN\s+)([\w.]+)\s*(?<![<>!])=(?!=)\s*([\w.]+)(?=\s)",
                     r"\g<1>\g<2> BETWEEN \g<3> AND \g<3>", retVal)
    return retVal


def _tamper_greatest(payload):
    if not payload:
        return payload
    retVal = payload
    m = re.search(r"(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)
    if m:
        repl = "%sGREATEST(%s,%s+1)=%s" % (m.group(1), m.group(3), m.group(4), m.group(3))
        retVal = retVal.replace(m.group(0), repl)
    return retVal


TAMPER_FUNCTIONS = {
    "space2comment": _tamper_space2comment,
    "space2plus": _tamper_space2plus,
    "charunicodeescape": _tamper_charunicodeescape,
    "charencode": _tamper_charencode,
    "overlongutf8": _tamper_overlongutf8,
    "apostrophemask": _tamper_apostrophemask,
    "randomcase": _tamper_randomcase,
    "multiplespaces": _tamper_multiplespaces,
    "versionedkeywords": _tamper_versionedkeywords,
    "equaltolike": _tamper_equaltolike,
    "between": _tamper_between,
    "greatest": _tamper_greatest,
}


# --------------------------------------------------------------------------
# 3. HTTP helpers (async, aiohttp-backed)
# --------------------------------------------------------------------------

def check_tls_cert(hostname, port, timeout=6):
    """One-shot TLS probe. This exists purely to surface *what's wrong*
    with the cert as an informational warning -- hostname mismatch,
    self-signed, expired, etc. -- not to block or affect anything else.
    Still uses blocking socket/ssl (there's no asyncio-native equivalent
    worth the complexity for a two-handshake one-off check); the async
    call site runs it in a thread executor so it never blocks the event
    loop or other concurrently-scanned targets. Not used at all when
    --tor is active, since a raw socket here would bypass the Tor circuit
    entirely and leak the real source IP to the target -- see run_target()."""
    result = {
        "valid": None, "error": None, "subject_cn": None, "sans": [],
        "issuer_cn": None, "not_after": None, "self_signed": False,
    }

    # Pass 1: strict verification (hostname check + trust chain), to learn
    # *whether* and *why* it fails.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                result["valid"] = True
    except ssl.SSLCertVerificationError as e:
        result["valid"] = False
        result["error"] = getattr(e, "verify_message", None) or str(e)
    except ssl.SSLError as e:
        result["valid"] = False
        result["error"] = str(e)
    except (socket.timeout, OSError) as e:
        result["error"] = f"connection failed: {e}"
        return result

    # Pass 2: grab the raw certificate regardless of validity, purely for
    # display -- who it's actually issued to, who signed it, when it
    # expires. ssl.getpeercert() (the dict form) only decodes fields when
    # the chain validated, so it comes back {} for exactly the self-signed/
    # untrusted/expired certs we most want to describe here. Pulling the
    # DER bytes instead (binary_form=True works unconditionally) and
    # parsing them with `cryptography` sidesteps that.
    try:
        ctx2 = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend()) if der else None
    except Exception:
        cert = None

    if cert is not None:
        def _cn(name):
            attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None

        result["subject_cn"] = _cn(cert.subject)
        result["issuer_cn"] = _cn(cert.issuer)
        result["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result["sans"] = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            result["sans"] = []
        result["self_signed"] = cert.issuer == cert.subject

    return result


def _short_error(e):
    """Collapse a chained exception's text (requests/urllib3-style nested
    "Caused by X(Y(...))" chains, or aiohttp's own often-terse messages)
    down to one human-readable reason. aiohttp exceptions (e.g. a bare
    asyncio.TimeoutError) sometimes stringify to an empty string -- falls
    back to the exception's class name in that case."""
    msg = str(e)
    if "Caused by" in msg:
        msg = msg.split("Caused by", 1)[1].strip()
        while True:
            m = re.match(r"^\w+\(\s*", msg)
            if not m:
                break
            msg = msg[m.end():]
            msg = msg.rstrip(")")
        msg = re.sub(r"^\d+,\s*", "", msg)  # drop a leading errno like "1, "
        msg = msg.strip().strip("'\"")
    msg = msg.strip()
    if not msg:
        msg = type(e).__name__
    return msg[:200]


class _Resp:
    """Minimal response shape mirroring the bits of `requests.Response`
    this tool actually touches (.status_code, .headers, .text, .cookies),
    built from an aiohttp ClientResponse once its body has been fully read.
    Keeping this shape means _match_signature()/detect_tech()/etc. didn't
    need to change at all when the HTTP layer moved from requests to
    aiohttp -- only fetch() itself and the call sites that await it did."""
    __slots__ = ("status_code", "headers", "text", "cookies")

    def __init__(self, status_code, headers, text, cookies):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.cookies = cookies


async def fetch(session, url, timeout=None):
    try:
        kwargs = {"allow_redirects": True, "ssl": False}
        if timeout is not None:
            kwargs["timeout"] = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, **kwargs) as resp:
            try:
                text = await resp.text(errors="replace")
            except (UnicodeDecodeError, LookupError):
                raw = await resp.read()
                text = raw.decode("utf-8", errors="replace")
            return _Resp(resp.status, resp.headers, text, resp.cookies)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        reason = _short_error(e)
        seen = _seen_errors()
        if reason not in seen:
            _emit(c_bad(f"[!] Request failed: {reason}"))
        seen[reason] = seen.get(reason, 0) + 1
        return None


def print_error_summary():
    seen = _seen_errors()
    if not seen:
        return
    total = sum(seen.values())
    extra = total - len(seen)
    if extra > 0:
        _emit(c_dim(f"\n[*] ({extra} additional request(s) failed with an already-reported reason, suppressed)"))


# --------------------------------------------------------------------------
# 4. WAF detection
# --------------------------------------------------------------------------

def _match_signature(sig, resp, other_status=None):
    if resp is None:
        return False
    for header_name, pattern in sig.get("headers", []):
        val = resp.headers.get(header_name, "")
        if val and re.search(pattern, val, re.I):
            return True
    cookie_names = " ".join(resp.cookies.keys()) + " " + resp.headers.get("Set-Cookie", "")
    for pattern in sig.get("cookies", []):
        if re.search(pattern, cookie_names, re.I):
            return True
    body = resp.text[:20000] if resp.text else ""
    for pattern in sig.get("body", []):
        if re.search(pattern, body, re.I):
            return True
    return False


def _probe_url_for(base_url, payload):
    parsed = urlparse.urlsplit(base_url)
    sep = "&" if parsed.query else "?"
    return base_url + sep + "ppfinger=" + urlparse.quote(payload, safe="")


async def sqlmap_waf_heuristic(session, base_url, baseline, delay=0.3):
    """Re-implements sqlmap's lib/controller/checks.py:checkWaf() heuristic:
    fire ONE request carrying a kitchen-sink SQLi+XSS+traversal+RCE payload
    (sqlmap's own IPS_WAF_CHECK_PAYLOAD, verbatim) and diff its response
    against the baseline page with a similarity ratio. sqlmap doesn't try to
    name the WAF here -- it just flags "something intercepted this" when the
    page comes back more different than IPS_WAF_CHECK_RATIO (0.5) allows.
    This catches WAFs/IPS whose block page doesn't match any of our vendor
    signatures. Returns (flagged: bool, ratio: float, probe_response)."""
    if baseline is None or not baseline.text:
        return False, None, None

    probe_url = _probe_url_for(base_url, SQLMAP_IPS_WAF_CHECK_PAYLOAD)
    if delay:
        await asyncio.sleep(delay)
    probe = await fetch(session, probe_url)
    if probe is None:
        # connection reset/refused on a hostile-looking payload is itself
        # exactly what sqlmap treats as a positive WAF/IPS signal
        return True, 0.0, None

    ratio = difflib.SequenceMatcher(None, baseline.text, probe.text or "").quick_ratio()
    flagged = ratio < SQLMAP_IPS_WAF_CHECK_RATIO
    return flagged, ratio, probe


async def detect_waf(session, base_url, delay=0.3, baseline=None):
    """Return (matched_vendor_names, baseline_resp, probe_responses_by_name,
    sqlmap_heuristic_result). Sends one baseline request (unless one is
    already supplied -- run_target() does its own reachability check up
    front and passes that through, so the target isn't hit twice), then
    one probe per entry in WAF_PROBE_PAYLOADS (sqli/xss/traversal/cmdi) --
    mirroring how wafw00f/whatwaf try several attack *categories* rather
    than a single payload, since a WAF may only have a rule for one of
    them -- plus sqlmap's own generic kitchen-sink heuristic as a second
    opinion."""
    if baseline is None:
        baseline = await fetch(session, base_url)

    probes = {}
    for name, payload in WAF_PROBE_PAYLOADS.items():
        if delay:
            await asyncio.sleep(delay)
        probes[name] = await fetch(session, _probe_url_for(base_url, payload))

    matched = set()
    all_responses = [baseline] + list(probes.values())
    for name, sig in WAF_SIGNATURES.items():
        if name == "Generic / Unknown WAF":
            continue
        if any(_match_signature(sig, resp) for resp in all_responses):
            matched.add(name)

    baseline_status = baseline.status_code if baseline is not None else None
    if not matched:
        for resp in probes.values():
            if resp is not None and resp.status_code in WAF_SIGNATURES["Generic / Unknown WAF"]["block_status"] \
               and resp.status_code != baseline_status:
                matched.add("Generic / Unknown WAF")
                break

    sqlmap_flagged, sqlmap_ratio, sqlmap_probe = await sqlmap_waf_heuristic(session, base_url, baseline, delay=delay)
    if sqlmap_flagged and not matched:
        matched.add("Generic / Unknown WAF (sqlmap heuristic only)")

    return {
        "matched": sorted(matched),
        "baseline": baseline,
        "probes": probes,
        "sqlmap_heuristic": {"flagged": sqlmap_flagged, "ratio": sqlmap_ratio, "response": sqlmap_probe},
    }


# Confidence bands for verify_tampers()'s ratio, same SQLMAP_IPS_WAF_CHECK_RATIO
# (0.5) sqlmap itself uses as the "still looks blocked" cutoff, plus a higher
# band above which the response looks close enough to the clean baseline to
# call it a likely bypass rather than just "not clearly still blocked".
TAMPER_LIKELY_BYPASS_RATIO = 0.85


async def verify_tampers(session, base_url, baseline, tampers, delay=0.3):
    """For each candidate (name, reason) tamper script, actually transforms
    sqlmap's own kitchen-sink attack payload with it and resends it, then
    diffs the response against the clean baseline page with the same
    similarity-ratio technique sqlmap_waf_heuristic() uses. Returns a list
    of dicts sorted by ratio descending (best chance of working first) --
    a ratio near 1.0 means the response now looks like an ordinary page
    again (likely bypassed whatever blocked the untampered payload); a
    ratio near 0 means it still looks like a block page. A hard
    bypassed/blocked cutoff would hide exactly this gradient, which is the
    actual useful signal for picking which tamper to try first."""
    results = []
    for name, reason in tampers:
        func = TAMPER_FUNCTIONS.get(name)
        if func is None:
            results.append({"name": name, "reason": reason, "ratio": None, "status": "untested"})
            continue

        transformed = func(SQLMAP_IPS_WAF_CHECK_PAYLOAD)
        if transformed == SQLMAP_IPS_WAF_CHECK_PAYLOAD:
            # this tamper doesn't change our synthetic payload at all (e.g. no
            # '>' or '=' for between/equaltolike/greatest to grab onto) --
            # nothing new was actually tested, so don't claim a result
            results.append({"name": name, "reason": reason, "ratio": None, "status": "no-op"})
            continue

        if delay:
            await asyncio.sleep(delay)
        # tamper outputs like charencode/overlongutf8/charunicodeescape are
        # already percent- or backslash-escaped; re-escaping their '%' with
        # the normal quote() would double-encode and corrupt them, so keep
        # '%' as a safe (already-encoded) character here, unlike _probe_url_for().
        sep = "&" if urlparse.urlsplit(base_url).query else "?"
        probe_url = base_url + sep + "ppfinger=" + urlparse.quote(transformed, safe="%")
        resp = await fetch(session, probe_url)
        if resp is None:
            results.append({"name": name, "reason": reason, "ratio": None, "status": "error"})
            continue

        ratio = difflib.SequenceMatcher(None, baseline.text, resp.text or "").quick_ratio()
        if ratio >= TAMPER_LIKELY_BYPASS_RATIO:
            status = "likely-bypass"
        elif ratio >= SQLMAP_IPS_WAF_CHECK_RATIO:
            status = "uncertain"
        else:
            status = "still-blocked"
        results.append({"name": name, "reason": reason, "ratio": ratio, "status": status})

    # Best chance of working first; untested/no-op/error (ratio=None) sink to the bottom.
    results.sort(key=lambda r: r["ratio"] if r["ratio"] is not None else -1, reverse=True)
    return results


async def rate_probe(session, base_url, count=10):
    """Optional, bounded burst check (default OFF -- pass --rate-probe).
    Fires `count` back-to-back GET requests (no delay) at the same URL and
    watches for a 429/503/Retry-After flip partway through. This is NOT
    something wafw00f/whatwaf/sqlmap do by default -- it's a distinct
    signal (edge/CDN rate-limiting, e.g. Cloudflare "Too Many Requests")
    that a single-shot probe can't surface. Kept small and one-shot so it
    stays a fingerprinting check, not a load test."""
    statuses = []
    rate_limited_at = None
    for i in range(count):
        resp = await fetch(session, base_url)
        code = resp.status_code if resp is not None else None
        statuses.append(code)
        if code in (429, 503) and rate_limited_at is None:
            rate_limited_at = i + 1
        retry_after = resp.headers.get("Retry-After") if resp is not None else None
        if retry_after and rate_limited_at is None:
            rate_limited_at = i + 1
    return {"statuses": statuses, "rate_limited_at": rate_limited_at}


# --------------------------------------------------------------------------
# 5. Form crawling + tech detection (PHP / ASP[X] only, skip Java/API)
# --------------------------------------------------------------------------

STATIC_EXCLUDE_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".js", ".ico", ".woff",
    ".woff2", ".ttf", ".pdf", ".zip", ".rar", ".mp4", ".mp3", ".webp",
)

JAVA_API_EXT = (".jsp", ".jspx", ".do", ".action", ".jsf")
PHP_EXT = (".php", ".php3", ".php4", ".php5", ".phtml")
ASP_EXT = (".asp", ".aspx", ".ashx", ".asmx")

API_PATH_HINTS = re.compile(r"/(api|rest|graphql|v[0-9]+)(/|$)", re.I)
JSON_CT_HINT = re.compile(r"application/(json|.*\+json)", re.I)


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        full = urlparse.urljoin(base_url, href)
        links.add(full)
    return links


def same_domain(url, root_netloc):
    try:
        return urlparse.urlsplit(url).netloc == root_netloc
    except Exception:
        return False


def extract_forms(html, page_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "").strip()
        method = form.get("method", "get").strip().lower() or "get"
        full_action = urlparse.urljoin(page_url, action) if action else page_url

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            itype = tag.get("type", "text").lower() if tag.name == "input" else tag.name
            if itype in ("submit", "button", "image", "reset", "file"):
                # still capture submit buttons' name/value since sqlmap
                # includes them, but skip file inputs (can't curl-forge files meaningfully)
                if itype == "file":
                    continue
            value = tag.get("value", "")
            if tag.name == "select":
                opt = tag.find("option")
                value = opt.get("value", opt.text.strip() if opt else "") if opt else value
            if not value:
                value = _sample_value_for(name, itype)
            inputs.append({"name": name, "type": itype, "value": value})

        forms.append({
            "page_url": page_url,
            "action": full_action,
            "method": method,
            "inputs": inputs,
        })
    return forms


def _sample_value_for(name, itype):
    n = name.lower()
    if itype == "password":
        return "Password123!"
    if itype == "email" or "email" in n:
        return "test@example.com"
    if itype == "hidden":
        return "1"
    if "user" in n or "login" in n:
        return "testuser"
    if "search" in n or "q" == n or "query" in n:
        return "test"
    return "ppfinger"


def detect_tech(resp, html, form_action):
    """Return one of 'PHP', 'ASP', 'ASPX', 'JAVA', 'API', 'UNKNOWN' for a given form/page."""
    action_path = urlparse.urlsplit(form_action).path.lower()

    if action_path.endswith(ASP_EXT):
        return "ASPX" if action_path.endswith(".aspx") else "ASP"
    if action_path.endswith(PHP_EXT):
        return "PHP"
    if action_path.endswith(JAVA_API_EXT):
        return "JAVA"
    if API_PATH_HINTS.search(action_path):
        return "API"

    headers = resp.headers if resp is not None else {}
    powered_by = headers.get("X-Powered-By", "")
    server = headers.get("Server", "")
    content_type = headers.get("Content-Type", "")

    if JSON_CT_HINT.search(content_type):
        return "API"
    # Generic "php" anywhere in X-Powered-By, plus framework-specific
    # headers surfaced by nuclei's tech-detect templates: Laravel reports
    # its own version header, and ThinkPHP reports its own X-Powered-By.
    if re.search(r"php", powered_by, re.I):
        return "PHP"
    if "x-laravel-version" in headers or re.search(r"laravel|thinkphp", powered_by, re.I):
        return "PHP"
    if re.search(r"asp\.net", powered_by, re.I) or re.search(r"asp\.net", server, re.I):
        return "ASPX" if "aspx" in (html or "").lower() else "ASP"
    if re.search(r"servlet|tomcat|jboss|wildfly|glassfish", server + powered_by, re.I):
        return "JAVA"

    cookie_names = " ".join(resp.cookies.keys()) if resp is not None else ""
    if "PHPSESSID" in cookie_names:
        return "PHP"
    if re.search(r"XSRF-TOKEN|laravel_session", cookie_names, re.I):
        # Laravel sets XSRF-TOKEN (CSRF cookie) and a "<app>_session" cookie;
        # both are PHP-specific regardless of app name.
        return "PHP"
    if "ASP.NET_SessionId" in cookie_names:
        return "ASPX"
    if "JSESSIONID" in cookie_names:
        return "JAVA"

    if html:
        if re.search(r"__VIEWSTATE|__EVENTVALIDATION", html):
            return "ASPX"
        if re.search(r"\.php[\"'?]", html, re.I):
            return "PHP"
        # Framework/CMS body markers lifted from nuclei's tech-detect
        # templates (livewire-detect, thinkphp-detect, default-*-page):
        # these are PHP-only frameworks, so a hit is a reliable PHP signal
        # even when the form action itself has no .php extension (common
        # with front-controller routing in Laravel/Symfony/CodeIgniter/etc).
        if re.search(
            r"wire:id=|wire:initial-data=|livewire\.(?:min\.)?js|"      # Laravel Livewire
            r"laravel_session|csrf-token\"\s+content=|"                  # Laravel meta/cookie
            r"/thinkphp/library/think/|/Library/Think/|"                 # ThinkPHP
            r"Welcome to CodeIgniter|Welcome to CakePHP|Welcome to Symfony!|"  # default pages
            r"Powered by DouPHP|phpMyAdmin",
            html, re.I,
        ):
            return "PHP"

    if action_path == "" or action_path == "/":
        return "UNKNOWN"
    return "UNKNOWN"


async def probe_composer_disclosure(session, start_url):
    """One-shot check for exposed composer.json / composer.lock, same idea
    as nuclei's laravel-eol template: a world-readable composer file is a
    PHP-only artifact (Composer is PHP's package manager), so finding one
    is a reliable PHP signal even when no form on the page reveals it."""
    parsed = urlparse.urlsplit(start_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    for path in ("composer.json", "composer.lock"):
        resp = await fetch(session, urlparse.urljoin(root, path))
        if resp is not None and resp.status_code == 200 and re.search(r'"(require|name|packages)"', resp.text or ""):
            return True
    return False


async def crawl_for_forms(session, start_url, max_pages, delay):
    root_netloc = urlparse.urlsplit(start_url).netloc
    seen = set()
    queue = deque([start_url])
    all_forms = []
    pages_fetched = 0
    composer_exposed = await probe_composer_disclosure(session, start_url)

    while queue and pages_fetched < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)

        if url.lower().endswith(STATIC_EXCLUDE_EXT):
            continue

        resp = await fetch(session, url)
        pages_fetched += 1
        if delay:
            await asyncio.sleep(delay)
        if resp is None or not resp.text:
            continue

        forms = extract_forms(resp.text, url)
        for f in forms:
            tech = detect_tech(resp, resp.text, f["action"])
            if tech == "UNKNOWN" and composer_exposed:
                tech = "PHP"
            f["tech"] = tech
            all_forms.append(f)

        if pages_fetched < max_pages:
            for link in extract_links(resp.text, url):
                if same_domain(link, root_netloc) and link not in seen and link.lower().endswith(STATIC_EXCLUDE_EXT) is False:
                    queue.append(link)

    return all_forms, pages_fetched, composer_exposed


# --------------------------------------------------------------------------
# 6. curl command generation
# --------------------------------------------------------------------------

def build_curl(form):
    method = form["method"].upper()
    action = form["action"]
    data_pairs = [f"{urlparse.quote(i['name'])}={urlparse.quote(str(i['value']))}" for i in form["inputs"]]
    data_str = "&".join(data_pairs)

    if method == "GET":
        sep = "&" if urlparse.urlsplit(action).query else "?"
        full_url = action + (sep + data_str if data_str else "")
        return f'curl "{full_url}"'
    else:
        if data_str:
            return f'curl "{action}" --data "{data_str}"'
        return f'curl "{action}" -X POST'


# --------------------------------------------------------------------------
# 7. RAM-conscious concurrency
#
# Multi-target mode scans several targets at once via asyncio, which is
# where the real "faster" win lives (wall-clock time for N targets drops
# toward the slowest single target in each concurrency-wide batch, instead
# of the sum of all of them). Two layers keep that from turning into an
# OOM on a small box:
#   1. compute_default_concurrency() sizes how many targets to START
#      scanning at once from a fraction of *available* system RAM, so a
#      2GB VPS doesn't try to run as wide as a 32GB workstation.
#   2. MemoryGate is a live safety net on top of that: a background task
#      that pauses *starting new* target scans (already-running ones are
#      left alone -- never killed) if system memory climbs past a ceiling
#      during the run, and resumes once it drops back down.
# --------------------------------------------------------------------------

DEFAULT_RAM_FRACTION = 0.25        # use ~25% of available RAM to size default concurrency
EST_MB_PER_WORKER = 60             # rough per-concurrent-target memory budget (session + buffered pages/forms)
DEFAULT_MAX_MEMORY_PERCENT = 85.0  # live ceiling: pause starting new targets above this system RAM usage


def compute_default_concurrency():
    """Sizes the default number of targets scanned at once from available
    system RAM (~25% of it, divided into a rough per-worker budget), so
    ppfngr runs wide and fast on a beefy box but doesn't try to open 30
    concurrent scans on a 1GB VPS. Falls back to a conservative default of
    4 if psutil isn't installed or the check fails for any reason."""
    if not _HAS_PSUTIL:
        return 4
    try:
        available_mb = psutil.virtual_memory().available / (1024 * 1024)
    except Exception:
        return 4
    budget_mb = available_mb * DEFAULT_RAM_FRACTION
    workers = int(budget_mb / EST_MB_PER_WORKER)
    return max(1, min(32, workers))


class MemoryGate:
    """Live backpressure for multi-target runs: a background task that
    periodically checks system memory usage and, if it climbs above
    max_percent, pauses new target scans from *starting* (anything already
    running finishes normally -- nothing is killed) until usage drops back
    down. compute_default_concurrency() picks a sane starting width; this
    is the safety net for when real usage runs higher than estimated (a
    target with huge HTML pages, a slow one holding buffers open, etc). A
    no-op if psutil isn't installed -- the gate just stays permanently open."""

    def __init__(self, max_percent=DEFAULT_MAX_MEMORY_PERCENT, check_interval=1.0):
        self.max_percent = max_percent
        self.check_interval = check_interval
        self.ok = asyncio.Event()
        self.ok.set()
        self._task = None
        self._paused_announced = False

    async def _watch(self):
        while True:
            try:
                pct = psutil.virtual_memory().percent
            except Exception:
                pct = 0.0
            if pct >= self.max_percent:
                if not self._paused_announced:
                    print(c_warn(f"[!] Memory usage at {pct:.0f}% -- pausing new target scans "
                                 f"until it drops below {self.max_percent:g}%"))
                    self._paused_announced = True
                self.ok.clear()
            else:
                if self._paused_announced:
                    print(c_ok(f"[*] Memory usage back to {pct:.0f}% -- resuming new target scans"))
                    self._paused_announced = False
                self.ok.set()
            await asyncio.sleep(self.check_interval)

    def start(self):
        if _HAS_PSUTIL:
            self._task = asyncio.create_task(self._watch())

    def stop(self):
        if self._task is not None:
            self._task.cancel()

    async def wait(self):
        await self.ok.wait()


# --------------------------------------------------------------------------
# 8. Main
# --------------------------------------------------------------------------

def sanitize_filename(target):
    netloc = urlparse.urlsplit(target).netloc or target
    return re.sub(r"[^a-zA-Z0-9._-]", "_", netloc)


def _tor_connector(proxy_url):
    """Builds a fresh ProxyConnector for a Tor SOCKS proxy URL, always with
    rdns=True -- DNS resolution happens *through* Tor too, not locally, so
    the target's hostname is never leaked outside the circuit. (requests/
    PySocks spelled this as a socks5h:// scheme; aiohttp-socks's URL parser
    doesn't accept that scheme at all -- it's a plain socks5:// URL plus
    this separate rdns keyword instead.) Centralized here so every call
    site gets the same behavior instead of risking one that forgets it."""
    return ProxyConnector.from_url(proxy_url, rdns=True)


async def setup_tor(tor_port, timeout):
    """Validates a local Tor SOCKS proxy (requires aiohttp-socks and a
    running Tor client, e.g. the Tor Browser Bundle or the `tor` service,
    listening on 127.0.0.1:<tor_port>, default 9050) by hitting Tor
    Project's own IP-check API through it before the real scan starts.
    Returns (is_tor, info, proxy_url); per-target sessions each build
    their own fresh ProxyConnector from proxy_url via _tor_connector()
    rather than sharing this one, since a connector is tied to one
    ClientSession's lifetime."""
    proxy_url = f"socks5://127.0.0.1:{tor_port}"
    try:
        connector = _tor_connector(proxy_url)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get("https://check.torproject.org/api/ip", ssl=False) as resp:
                data = await resp.json(content_type=None)
        if data.get("IsTor"):
            return True, data.get("IP"), proxy_url
        return False, data.get("IP"), proxy_url
    except Exception as e:
        return None, _short_error(e), proxy_url


def write_batch_report(batch_results, args):
    """Multi-target mode only: writes one aggregate report covering every
    target scanned in the run -- JSON (--json) or a plain-text summary
    otherwise. This is separate from the per-target form_results-*.txt
    curl files, which are still written individually as before."""
    os.makedirs(args.out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")

    if args.json:
        path = os.path.join(args.out_dir, f"ppfngr-results-{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(batch_results, fh, indent=2)
    else:
        path = os.path.join(args.out_dir, f"ppfngr-results-{stamp}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"ppfngr multi-target results -- {stamp}\n")
            fh.write(f"{len(batch_results)} target(s) scanned\n\n")
            for r in batch_results:
                fh.write(f"=== {r['target']} ===\n")
                fh.write(f"Reachable: {r['reachable']}\n")
                if not r["reachable"]:
                    fh.write(f"Error: {r.get('error')}\n\n")
                    continue
                if r.get("tls"):
                    fh.write(f"TLS: {r['tls']}\n")
                fh.write(f"WAF matched: {', '.join(r['waf']['matched']) or 'none'}\n")
                if r["waf"].get("heuristic_ratio") is not None:
                    fh.write(f"sqlmap heuristic ratio: {r['waf']['heuristic_ratio']:.2f}\n")
                if r.get("rate_limit"):
                    fh.write(f"Rate limit: {r['rate_limit']}\n")
                if r.get("tamper_verify"):
                    fh.write(f"Tamper verify: {r['tamper_verify']}\n")
                fh.write(f"Forms kept: {r['forms_kept']}  skipped: {r['forms_skipped']}\n")
                if r.get("form_results_file"):
                    fh.write(f"Form results file: {r['form_results_file']}\n")
                fh.write(f"Result count: {r['result_count']}\n\n")

    print(c_ok(f"[+] Wrote batch report ({len(batch_results)} target(s)) to {c_bold(path)}"))


def _new_record(target):
    return {
        "target": target,
        "reachable": False,
        "error": None,
        "tls": None,
        "waf": {"matched": [], "probes": {}, "heuristic_ratio": None},
        "rate_limit": None,
        "tamper_verify": None,
        "composer_exposed": False,
        "forms_kept": 0,
        "forms_skipped": 0,
        "form_results_file": None,
        "result_count": 0,
    }


async def run_target(raw_target, args, timeout, tor_proxy_url=None):
    """Runs the full pipeline (TLS check, WAF fingerprint, tamper
    suggestions/verification, form crawl) against one target, inside its
    own aiohttp session. Always returns a structured result dict (used for
    the exit code, the multi-target summary line, and --json/text batch
    reports); prints that target's whole output as one buffered block via
    _emit(), flushed in the `finally` below regardless of which return
    path was taken -- this is what keeps concurrently-scanned targets'
    output from interleaving."""
    _OUTPUT_BUF.set([])
    _SEEN_ERRORS_VAR.set({})

    target = raw_target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    record = _new_record(target)

    try:
        if args.random_agent:
            user_agent = random.choice(RANDOM_USER_AGENTS)
            _emit(c_dim(f"[*] --random-agent: using '{user_agent}'"))
        else:
            user_agent = DEFAULT_UA

        if tor_proxy_url:
            connector = _tor_connector(tor_proxy_url)
        else:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": user_agent},
        ) as session:
            _emit(c_bold(c_mag(target)))
            result_count = 0

            # Reachability check up front: if we can't even get a baseline
            # response, every later step would just fail the exact same way
            # again and again. Bail here with one clear line instead of
            # repeating the same connection error through every check.
            baseline = await fetch(session, target)
            if baseline is None:
                _emit(c_bad("[-] No connection to host -- target is unreachable. Nothing further to check."))
                record["error"] = "no connection"
                print_error_summary()
                return record

            record["reachable"] = True
            parsed_target = urlparse.urlsplit(target)

            if parsed_target.scheme == "https":
                if tor_proxy_url:
                    # A raw socket here would connect directly, bypassing the
                    # Tor circuit entirely and leaking the real source IP --
                    # skip rather than silently deanonymize the scan.
                    _emit(c_dim("[*] tls-cert check skipped under --tor (would bypass the Tor circuit over a raw socket)"))
                else:
                    port = parsed_target.port or 443
                    loop = asyncio.get_running_loop()
                    cert = await loop.run_in_executor(None, check_tls_cert, parsed_target.hostname, port, timeout)
                    if cert["valid"] is True:
                        detail = f"valid, issuer={cert['issuer_cn']}, expires={cert['not_after']}"
                        finding("tls-cert", "ssl", "info", target, detail)
                        record["tls"] = detail
                        result_count += 1
                    elif cert["valid"] is False:
                        mismatch = f", not matching '{parsed_target.hostname}'" if cert['subject_cn'] != parsed_target.hostname else ""
                        detail = (f"{cert['error']} -- issued to {cert['subject_cn']}"
                                  f"{' (self-signed)' if cert['self_signed'] else ''}{mismatch}, expires {cert['not_after']}")
                        finding("tls-cert", "ssl", "medium", target, detail)
                        record["tls"] = detail
                        result_count += 1
                    # cert["valid"] is None (handshake never completed) isn't printed
                    # as its own finding -- same root cause the reachability check
                    # above would already have reported.

            waf_result = await detect_waf(session, target, delay=args.delay, baseline=baseline)
            matched = waf_result["matched"]
            heuristic = waf_result["sqlmap_heuristic"]
            record["waf"]["matched"] = matched
            record["waf"]["heuristic_ratio"] = heuristic["ratio"]

            probe_summary = " ".join(
                f"{name}={resp.status_code if resp is not None else 'ERR'}"
                for name, resp in waf_result["probes"].items()
            )
            record["waf"]["probes"] = {
                name: (resp.status_code if resp is not None else None)
                for name, resp in waf_result["probes"].items()
            }
            ratio_summary = f"ratio={heuristic['ratio']:.2f}" if heuristic["ratio"] is not None else ""

            if matched:
                finding("waf-detect", "http", "info", target, ", ".join(matched))
            else:
                finding("waf-detect", "http", "info", target, "no known WAF signature matched")
            sub(f"probes: {probe_summary}  {ratio_summary}".strip())
            result_count += 1

            if args.rate_probe:
                rp = await rate_probe(session, target, count=args.rate_probe_count)
                if rp["rate_limited_at"]:
                    detail = f"rate-limited at request #{rp['rate_limited_at']} of {args.rate_probe_count}"
                    finding("rate-limit", "http", "low", target, detail)
                    record["rate_limit"] = detail
                else:
                    detail = f"no rate-limiting in a burst of {args.rate_probe_count}"
                    finding("rate-limit", "http", "info", target, detail)
                    record["rate_limit"] = detail
                result_count += 1

            tampers = TAMPER_MAP.get(matched[0], TAMPER_MAP["Generic / Unknown WAF"]) if matched else TAMPER_MAP["Generic / Unknown WAF"]

            if args.verify_tampers and matched:
                verify_results = await verify_tampers(session, target, baseline, tampers, delay=args.delay)
                best = [r for r in verify_results if r["status"] == "likely-bypass"]
                if best:
                    detail = f"likely bypass: {best[0]['name']} (ratio={best[0]['ratio']:.2f})"
                    finding("tamper-verify", "http", "high", target, detail)
                    record["tamper_verify"] = detail
                elif any(r["status"] == "uncertain" for r in verify_results):
                    detail = "no clear bypass, but some responses weren't a clean block either"
                    finding("tamper-verify", "http", "medium", target, detail + " -- see ratios below")
                    record["tamper_verify"] = detail
                else:
                    detail = "none of the suggested tampers got past this WAF"
                    finding("tamper-verify", "http", "info", target, detail)
                    record["tamper_verify"] = detail
                result_count += 1

                status_label = {
                    "likely-bypass": c_ok("LIKELY BYPASS"),
                    "uncertain": c_warn("UNCERTAIN    "),
                    "still-blocked": c_bad("STILL BLOCKED"),
                    "no-op": c_dim("NO-OP        "),
                    "error": c_warn("ERROR        "),
                    "untested": c_dim("UNTESTED     "),
                }
                for r in verify_results:
                    ratio_str = f"{r['ratio']:.2f}" if r["ratio"] is not None else "  - "
                    sub(f"{ratio_str}  {status_label[r['status']]}  {r['name']:<20} {r['reason']}")
                ranked = ",".join(r["name"] for r in verify_results if r["ratio"] is not None)
                if ranked:
                    sub(f"sqlmap --tamper={ranked}  (ranked best-chance-first)")
            else:
                tamper_list = ",".join(t[0] for t in tampers)
                sub(f"sqlmap --tamper={tamper_list}")
                for name, reason in tampers:
                    sub(f"  {name:<20} {reason}")

            record["result_count"] = result_count

            if args.no_crawl:
                _emit(c_dim(f"\n[*] {result_count} result(s). --no-crawl set, skipping form discovery."))
                print_error_summary()
                return record

            forms, pages_fetched, composer_exposed = await crawl_for_forms(session, target, args.max_pages, args.delay)
            record["composer_exposed"] = composer_exposed
            if composer_exposed:
                finding("composer-disclosure", "http", "low", target, "composer.json/composer.lock is exposed (confirms PHP)")
                result_count += 1

            kept = [f for f in forms if f["tech"] in ("PHP", "ASP", "ASPX")]
            skipped = [f for f in forms if f["tech"] in ("JAVA", "API")]
            record["forms_kept"] = len(kept)
            record["forms_skipped"] = len(skipped)

            for f in kept:
                finding("form-detect", "http", "info", f["action"], f"{f['method'].upper()} {f['tech']}")
                result_count += 1

            record["result_count"] = result_count

            if not kept:
                _emit(c_dim(f"\n[*] {result_count} result(s). Crawled {pages_fetched} page(s), "
                            f"{len(skipped)} Java/API form(s) skipped, no PHP/ASP(X) forms found; nothing written."))
                print_error_summary()
                return record

            fname = f"form_results-{sanitize_filename(target)}.txt"
            os.makedirs(args.out_dir, exist_ok=True)
            out_path = os.path.join(args.out_dir, fname)

            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(f"# ppfinger form results for {target}\n")
                fh.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                fh.write(f"# {len(kept)} form(s) kept (PHP / ASP / ASP.NET). Java/API forms excluded.\n\n")
                for f in kept:
                    fh.write(f"# Found on: {f['page_url']}\n")
                    fh.write(f"# Method:   {f['method'].upper()}  Tech: {f['tech']}\n")
                    fh.write(build_curl(f) + "\n\n")

            record["form_results_file"] = out_path
            _emit(c_ok(f"\n[+] {result_count} result(s). Wrote {len(kept)} curl command(s) to {c_bold(out_path)}"))
            print_error_summary()
            return record
    finally:
        # Deliberately NOT printed here: this runs the instant *this*
        # target's own work finishes, which -- since other targets keep
        # running concurrently in the background regardless of which one
        # amain() happens to be awaiting -- is not necessarily in the same
        # order targets were submitted in (a fast failure can finish before
        # a slow real scan even though it started later). Stashing the
        # buffered text on the record and letting amain() print it while
        # awaiting each task *in submission order* is what actually
        # guarantees ordered, non-interleaved output; printing here would not.
        buf = _OUTPUT_BUF.get()
        record["_output"] = "\n".join(buf) if buf else ""


async def amain():
    parser = argparse.ArgumentParser(
        description="WAF fingerprinter + sqlmap tamper recommender + PHP/ASP(X) form finder."
    )
    parser.add_argument("target", nargs="?", default=None,
                         help="Target base URL, e.g. https://target.example.com. Omit this and pipe "
                              "a list of targets (one per line) on stdin instead for multi-target mode, "
                              "e.g. `cat subdomains.txt | python ppfinger.py`.")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to crawl for forms (default 10)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default 0.5)")
    parser.add_argument("--out-dir", default=".", help="Directory to write form_results-<target>.txt into")
    parser.add_argument("--no-crawl", action="store_true", help="Skip form crawling, only run WAF fingerprinting")
    parser.add_argument("--rate-probe", action="store_true",
                         help="Also fire a small burst of back-to-back requests to check for "
                              "rate-limit-based protection (e.g. Cloudflare 429s). Off by default.")
    parser.add_argument("--rate-probe-count", type=int, default=10,
                         help="Number of requests to send for --rate-probe (default 10)")
    parser.add_argument("--tor", action="store_true",
                         help="Route all traffic through a local Tor SOCKS proxy (127.0.0.1:9050 by "
                              "default). Requires a running Tor client and the aiohttp-socks package.")
    parser.add_argument("--tor-port", type=int, default=9050,
                         help="Local Tor SOCKS port to use with --tor (default 9050)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--random-agent", action="store_true",
                         help="Use a random, common browser User-Agent instead of ppfinger's own "
                              "(some WAF rules key off a scanner-looking UA)")
    parser.add_argument("--verify-tampers", action="store_true",
                         help="Actually apply each suggested sqlmap tamper script to a real attack "
                              "payload and resend it, ranking them by how close the response comes "
                              "back to the clean baseline (likely bypass) vs. still looking blocked, "
                              "instead of just suggesting by vendor name. Only runs when a WAF was "
                              "detected; adds one extra request per suggested tamper script.")
    parser.add_argument("--timeout", type=float, default=None,
                         help="Per-request timeout in seconds. Default: 10, or 15 under --tor "
                              "(Tor circuits add real latency -- 10s false-positives as unreachable often).")
    parser.add_argument("--concurrency", type=int, default=None,
                         help="How many targets to scan at once in multi-target (stdin) mode. "
                              "Default: sized automatically from ~25%% of available system RAM "
                              "(see compute_default_concurrency()). Ignored for a single target.")
    parser.add_argument("--max-memory-percent", type=float, default=DEFAULT_MAX_MEMORY_PERCENT,
                         help=f"Live safety ceiling (default {DEFAULT_MAX_MEMORY_PERCENT:.0f}%%): pause "
                              "starting new target scans while system memory usage is at or above this, "
                              "resume once it drops back down. Requires psutil.")
    parser.add_argument("--json", action="store_true",
                         help="Multi-target mode only: write the aggregate batch report as JSON "
                              "(ppfngr-results-<timestamp>.json) instead of a plain-text summary.")
    args = parser.parse_args()

    if args.no_color:
        global c_info, c_ok, c_warn, c_bad, c_bold, c_dim, c_mag
        c_info = c_ok = c_warn = c_bad = c_bold = c_dim = c_mag = lambda msg: msg
    else:
        print_banner()

    if not _HAS_PSUTIL:
        print(c_dim("[*] psutil not installed -- RAM-based concurrency sizing and the memory watcher "
                    "are disabled (falling back to a fixed default concurrency of 4)."))

    # Target resolution: either the positional arg, or -- if omitted -- a
    # list of targets piped on stdin, one per line (blank lines and #
    # comments ignored), e.g. `cat subdomains.txt | python ppfinger.py`.
    if args.target:
        targets = [args.target]
    elif not sys.stdin.isatty():
        targets = [
            line.strip() for line in sys.stdin
            if line.strip() and not line.strip().startswith("#")
        ]
    else:
        parser.error("no target given and stdin isn't piped -- pass a target, or pipe a list of "
                      "targets on stdin (e.g. `cat subdomains.txt | python ppfinger.py`)")

    if not targets:
        print(c_bad("[-] No targets to scan (stdin was empty)."))
        sys.exit(1)

    timeout = args.timeout if args.timeout is not None else (DEFAULT_TOR_TIMEOUT if args.tor else DEFAULT_TIMEOUT)

    # Tor is set up once for the whole run (one exit circuit for every
    # target); each per-target session builds its own connector from the
    # validated proxy_url rather than sharing this probe's session/connector.
    tor_proxy_url = None
    if args.tor:
        print(c_info(f"[*] Routing through Tor (127.0.0.1:{args.tor_port})..."))
        is_tor, info, proxy_url = await setup_tor(args.tor_port, timeout)
        if is_tor is True:
            print(c_ok(f"[+] Confirmed exiting through Tor. Exit IP: {info}"))
            tor_proxy_url = proxy_url
        elif is_tor is False:
            print(c_bad(f"[!] Proxy reachable but Tor Project does not confirm a Tor exit "
                        f"(reported IP: {info}) -- refusing to continue over a connection that "
                        f"isn't confirmed Tor."))
            sys.exit(1)
        else:
            print(c_bad(f"[!] Could not reach Tor SOCKS proxy on 127.0.0.1:{args.tor_port}: {info}"))
            print(c_bad("    --tor was requested but Tor is not reachable -- stopping "
                        "(no silent fallback to a direct connection)."))
            sys.exit(1)

    multi = len(targets) > 1
    concurrency = args.concurrency or compute_default_concurrency()
    if multi:
        sizing = "fixed default (psutil unavailable)" if not _HAS_PSUTIL else \
            f"~{DEFAULT_RAM_FRACTION * 100:.0f}% of available RAM"
        print(c_dim(f"[*] Scanning {len(targets)} target(s), {concurrency} at a time "
                    f"({sizing}; override with --concurrency)."))

    memory_gate = MemoryGate(max_percent=args.max_memory_percent)
    memory_gate.start()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def run_one(raw_target):
        await memory_gate.wait()
        async with sem:
            await memory_gate.wait()  # re-check right before actually starting in case it flipped while queued
            return await run_target(raw_target, args, timeout, tor_proxy_url)

    # create_task() schedules every target concurrently right away; printing
    # each one's buffered output here, in submission order, as we await them
    # back one at a time (rather than printing inside each task as soon as
    # *it* finishes) is what keeps output non-interleaved and predictable --
    # a target that fails fast won't jump ahead of one still mid-scan, even
    # though the actual work is genuinely running concurrently in the background.
    tasks = [asyncio.create_task(run_one(t)) for t in targets]
    batch_results = []
    for task in tasks:
        record = await task
        print(record.pop("_output", ""))
        batch_results.append(record)
        if multi:
            print()

    memory_gate.stop()

    if multi:
        ok_count = sum(1 for r in batch_results if r["reachable"])
        print(c_bold(f"[*] Done: {c_ok(str(ok_count))} reachable / {len(batch_results)} target(s) scanned."))
        write_batch_report(batch_results, args)

    sys.exit(0 if all(r["reachable"] for r in batch_results) else 1)


def main():
    asyncio.run(amain())


if __name__ == "__main__":
    main()
