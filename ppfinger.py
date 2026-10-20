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
     rationale for each.
  5. Crawls the target (same-domain only, shallow, rate-limited) looking for
     HTML <form> elements, in the spirit of sqlmap's --forms. For each form
     found, it fingerprints the backend language from the form action
     extension, response headers, cookies, body markers (Laravel/Livewire,
     ThinkPHP, framework default pages) and exposed composer.json/.lock.
     Only forms that look like PHP or ASP/ASP.NET are kept (Java/JSP/.do and
     anything that looks like a JSON/REST API endpoint are skipped). Each
     kept form is written out as a ready-to-run curl command to
     form_results-<target>.txt.

Usage:
    python ppfinger.py https://target.example.com
    python ppfinger.py https://target.example.com --max-pages 15 --delay 1.0
    python ppfinger.py https://target.example.com --out-dir ./results
    python ppfinger.py https://target.example.com --rate-probe --rate-probe-count 15
"""

import argparse
import difflib
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse as urlparse
from collections import deque

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
from cryptography import x509
from cryptography.hazmat.backends import default_backend

requests.packages.urllib3.disable_warnings()  # self-signed lab certs are common
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
# 0. Color output helpers
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


def status_color(code):
    """Color a status code (or 'ERR') by what it means: 2xx/3xx green-ish,
    4xx/5xx red (likely a WAF/block), anything else dim."""
    if code == "ERR" or code is None:
        return c_bad("ERR")
    if 200 <= code < 400:
        return c_ok(str(code))
    if code in (401, 403, 406, 429, 999):
        return c_bad(str(code))
    if 400 <= code < 600:
        return c_warn(str(code))
    return c_dim(str(code))


def section(title, step=None):
    """Prints a colored section header with a horizontal rule, e.g.
    '-- [1/4] Fingerprinting WAF/CDN --------------'. Plain ASCII only --
    some Windows consoles are stuck on a legacy codepage (cp1252) that
    can't encode Unicode box-drawing characters."""
    label = f"[{step}] {title}" if step else title
    rule_len = max(4, 60 - len(label))
    print(c_bold(c_mag(f"\n-- {label} {'-' * rule_len}")))


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
_BANNER_FLAVOR = "Cl0udfl4re · Ak4mai · M0dSecur1ty"


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
# 3. HTTP helpers
# --------------------------------------------------------------------------

def check_tls_cert(hostname, port, timeout=6):
    """One-shot TLS probe, independent of the requests session (which runs
    verify=False everywhere else so a bad cert never blocks scanning). This
    exists purely to surface *what's wrong* with the cert as an
    informational warning -- hostname mismatch, self-signed, expired, etc.
    -- not to block or affect anything else. Returns None if the target
    isn't even listening on TLS at that host:port."""
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
    """Collapse requests/urllib3's deeply-nested chained exception text
    (HTTPSConnectionPool(...): Max retries exceeded ... (Caused by
    SSLError(SSLError(1, '...'))) ) down to just the one human-readable
    reason inside it."""
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
    return msg or str(e)[:150]


# Dedupe repeated identical connection errors (common when a target is
# simply unreachable/wrong-scheme -- every one of a dozen probes fails with
# the exact same reason) so the terminal doesn't get spammed with the same
# line over and over. First occurrence of each distinct reason is shown in
# full; repeats just bump a counter, surfaced by print_error_summary().
_SEEN_ERRORS = {}


def fetch(session, url, timeout=DEFAULT_TIMEOUT):
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return resp
    except requests.RequestException as e:
        reason = _short_error(e)
        if reason not in _SEEN_ERRORS:
            print(c_bad(f"[!] Request failed: {reason}"), file=sys.stderr)
        _SEEN_ERRORS[reason] = _SEEN_ERRORS.get(reason, 0) + 1
        return None


def print_error_summary():
    if not _SEEN_ERRORS:
        return
    total = sum(_SEEN_ERRORS.values())
    extra = total - len(_SEEN_ERRORS)
    if extra > 0:
        print(c_dim(f"\n[*] ({extra} additional request(s) failed with an already-reported reason, suppressed)"))


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


def sqlmap_waf_heuristic(session, base_url, baseline, delay=0.3):
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
        time.sleep(delay)
    probe = fetch(session, probe_url)
    if probe is None:
        # connection reset/refused on a hostile-looking payload is itself
        # exactly what sqlmap treats as a positive WAF/IPS signal
        return True, 0.0, None

    ratio = difflib.SequenceMatcher(None, baseline.text, probe.text or "").quick_ratio()
    flagged = ratio < SQLMAP_IPS_WAF_CHECK_RATIO
    return flagged, ratio, probe


def detect_waf(session, base_url, delay=0.3, baseline=None):
    """Return (matched_vendor_names, baseline_resp, probe_responses_by_name,
    sqlmap_heuristic_result). Sends one baseline request (unless one is
    already supplied -- main() does its own reachability check up front and
    passes that through, so the target isn't hit twice), then one probe per
    entry in WAF_PROBE_PAYLOADS (sqli/xss/traversal/cmdi) -- mirroring how
    wafw00f/whatwaf try several attack *categories* rather than a single
    payload, since a WAF may only have a rule for one of them -- plus
    sqlmap's own generic kitchen-sink heuristic as a second opinion."""
    if baseline is None:
        baseline = fetch(session, base_url)

    probes = {}
    for name, payload in WAF_PROBE_PAYLOADS.items():
        if delay:
            time.sleep(delay)
        probes[name] = fetch(session, _probe_url_for(base_url, payload))

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

    sqlmap_flagged, sqlmap_ratio, sqlmap_probe = sqlmap_waf_heuristic(session, base_url, baseline, delay=delay)
    if sqlmap_flagged and not matched:
        matched.add("Generic / Unknown WAF (sqlmap heuristic only)")

    return {
        "matched": sorted(matched),
        "baseline": baseline,
        "probes": probes,
        "sqlmap_heuristic": {"flagged": sqlmap_flagged, "ratio": sqlmap_ratio, "response": sqlmap_probe},
    }


def rate_probe(session, base_url, count=10):
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
        resp = fetch(session, base_url, timeout=5)
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


def probe_composer_disclosure(session, start_url):
    """One-shot check for exposed composer.json / composer.lock, same idea
    as nuclei's laravel-eol template: a world-readable composer file is a
    PHP-only artifact (Composer is PHP's package manager), so finding one
    is a reliable PHP signal even when no form on the page reveals it."""
    parsed = urlparse.urlsplit(start_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    for path in ("composer.json", "composer.lock"):
        resp = fetch(session, urlparse.urljoin(root, path))
        if resp is not None and resp.status_code == 200 and re.search(r'"(require|name|packages)"', resp.text or ""):
            return True
    return False


def crawl_for_forms(session, start_url, max_pages, delay):
    root_netloc = urlparse.urlsplit(start_url).netloc
    seen = set()
    queue = deque([start_url])
    all_forms = []
    pages_fetched = 0
    composer_exposed = probe_composer_disclosure(session, start_url)

    while queue and pages_fetched < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)

        if url.lower().endswith(STATIC_EXCLUDE_EXT):
            continue

        resp = fetch(session, url)
        pages_fetched += 1
        if delay:
            time.sleep(delay)
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
# 7. Main
# --------------------------------------------------------------------------

def sanitize_filename(target):
    netloc = urlparse.urlsplit(target).netloc or target
    return re.sub(r"[^a-zA-Z0-9._-]", "_", netloc)


def setup_tor_session(session, tor_port, timeout=10):
    """Route the session through a local Tor SOCKS proxy (requires PySocks
    and a running Tor client, e.g. the Tor Browser Bundle or the `tor`
    service, listening on 127.0.0.1:<tor_port>, default 9050). Uses
    socks5h:// (the trailing h means DNS resolution happens *through* Tor
    too, not locally) so the target's hostname is never leaked outside the
    Tor circuit. Confirms the proxy actually works by hitting Tor Project's
    own IP-check API before the real scan starts."""
    proxy_url = f"socks5h://127.0.0.1:{tor_port}"
    session.proxies.update({"http": proxy_url, "https": proxy_url})
    try:
        resp = session.get("https://check.torproject.org/api/ip", timeout=timeout, verify=False)
        data = resp.json()
        if data.get("IsTor"):
            return True, data.get("IP")
        return False, data.get("IP")
    except requests.RequestException as e:
        # Trim requests' verbose chained exception text down to the one
        # line that actually matters (e.g. "actively refused it" = no Tor
        # client listening on that port).
        msg = str(e)
        reason = msg.rsplit("Caused by", 1)[-1].strip(" )") if "Caused by" in msg else msg
        return None, reason


def main():
    parser = argparse.ArgumentParser(
        description="WAF fingerprinter + sqlmap tamper recommender + PHP/ASP(X) form finder."
    )
    parser.add_argument("target", help="Target base URL, e.g. https://target.example.com")
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
                              "default). Requires a running Tor client and the PySocks package.")
    parser.add_argument("--tor-port", type=int, default=9050,
                         help="Local Tor SOCKS port to use with --tor (default 9050)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--random-agent", action="store_true",
                         help="Use a random, common browser User-Agent instead of ppfinger's own "
                              "(some WAF rules key off a scanner-looking UA)")
    args = parser.parse_args()

    if args.no_color:
        global c_info, c_ok, c_warn, c_bad, c_bold, c_dim, c_mag
        c_info = c_ok = c_warn = c_bad = c_bold = c_dim = c_mag = lambda msg: msg
    else:
        print_banner()

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    session = requests.Session()
    if args.random_agent:
        user_agent = random.choice(RANDOM_USER_AGENTS)
        print(c_dim(f"[*] --random-agent: using '{user_agent}'"))
    else:
        user_agent = DEFAULT_UA
    session.headers.update({"User-Agent": user_agent})

    if args.tor:
        print(c_info(f"[*] Routing through Tor (127.0.0.1:{args.tor_port})..."))
        is_tor, info = setup_tor_session(session, args.tor_port)
        if is_tor is True:
            print(c_ok(f"[+] Confirmed exiting through Tor. Exit IP: {info}"))
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

    print(c_bold(f">> Target: {c_mag(target)}"))

    # Reachability check up front: if we can't even get a baseline response,
    # every later step (TLS check, WAF probes, tamper suggestions, form
    # crawl) would just fail the exact same way again and again. Bail here
    # with one clear line instead of repeating the same connection error
    # through 4 sections -- this baseline is then reused by detect_waf()
    # below so the target isn't hit twice for it.
    baseline = fetch(session, target)
    if baseline is None:
        print(c_bad("\n[-] No connection to host -- target is unreachable. Nothing further to check."))
        print_error_summary()
        sys.exit(1)

    parsed_target = urlparse.urlsplit(target)
    if parsed_target.scheme == "https":
        section("Checking TLS certificate", "0/4")
        port = parsed_target.port or 443
        cert = check_tls_cert(parsed_target.hostname, port)
        if cert["valid"] is True:
            print(c_ok(f"  [+] SSL cert is valid for {parsed_target.hostname} "
                       f"(issuer: {cert['issuer_cn']}, expires: {cert['not_after']})"))
        elif cert["valid"] is False:
            print(c_warn("  [!] SSL cert NOT valid for the target -- informational only, not blocking:"))
            print(c_warn(f"      Reason:      {cert['error']}"))
            print(c_warn(f"      Cert is for: {cert['subject_cn']}"
                         f"{c_bold(' (self-signed)') if cert['self_signed'] else ''}"))
            if cert["sans"]:
                print(c_warn(f"      SAN(s):      {', '.join(cert['sans'])}"))
            print(c_warn(f"      Issued by:   {cert['issuer_cn']}"))
            print(c_warn(f"      Expires:     {cert['not_after']}"))
            print(c_dim(f"      -> cert on the wire belongs to '{cert['subject_cn']}', not "
                        f"'{parsed_target.hostname}' -- a browser would show an insecure-connection warning here."))
        else:
            print(c_dim(f"  TLS handshake didn't complete: {cert['error']}"))

    section("Fingerprinting WAF / CDN", "1/4")
    waf_result = detect_waf(session, target, delay=args.delay, baseline=baseline)
    matched = waf_result["matched"]

    if baseline is not None:
        print(f"  Baseline status:          {status_color(baseline.status_code)}")
    for name, resp in waf_result["probes"].items():
        status = resp.status_code if resp is not None else "ERR"
        print(f"  Probe ({name:<9}) status: {status_color(status)}")

    heuristic = waf_result["sqlmap_heuristic"]
    if heuristic["ratio"] is not None:
        if heuristic["flagged"]:
            tag = c_bad("BLOCKED-LIKE")
        else:
            tag = c_ok("similar to baseline")
        print(f"  sqlmap-style heuristic (diff ratio {heuristic['ratio']:.2f}): {tag}")

    if matched:
        print(c_bad(f"\n  [+] Detected WAF(s)/protection: {c_bold(', '.join(matched))}"))
    else:
        print(c_ok("\n  [-] No known WAF signature matched (target may be unprotected, or using an unlisted WAF)."))

    if args.rate_probe:
        print(c_info(f"\n  --rate-probe: firing {args.rate_probe_count} back-to-back requests..."))
        rp = rate_probe(session, target, count=args.rate_probe_count)
        colored_statuses = [status_color(s) for s in rp["statuses"]]
        print(f"  Statuses: [{', '.join(colored_statuses)}]")
        if rp["rate_limited_at"]:
            print(c_bad(f"  [+] Rate-limit response seen at request #{rp['rate_limited_at']} "
                        f"-- target has edge/CDN rate-limiting (a form of WAF protection)"))
        else:
            print(c_ok("  No rate-limiting observed in this burst."))

    section("sqlmap tamper script recommendations", "2/4")
    if matched:
        for waf in matched:
            tampers = TAMPER_MAP.get(waf, TAMPER_MAP["Generic / Unknown WAF"])
            print(c_bold(c_warn(f"\n  == {waf} ==")))
            for name, reason in tampers:
                print(f"    --tamper={c_ok(f'{name:<22}')} {c_dim(reason)}")
            tamper_list = ",".join(t[0] for t in tampers)
            print(c_bold(f"\n  >> sqlmap --tamper={tamper_list}"))
    else:
        print("  No WAF matched; tamper scripts likely unnecessary. If injections still fail,")
        print("  try the generic set below as a first pass:")
        for name, reason in TAMPER_MAP["Generic / Unknown WAF"]:
            print(f"    --tamper={c_ok(f'{name:<22}')} {c_dim(reason)}")

    if args.no_crawl:
        print(c_dim("\n[*] --no-crawl set, skipping form discovery."))
        print_error_summary()
        return

    section("Crawling for forms", "3/4")
    print(f"  max {args.max_pages} pages, {args.delay}s delay")
    forms, pages_fetched, composer_exposed = crawl_for_forms(session, target, args.max_pages, args.delay)
    print(f"  Fetched {pages_fetched} page(s), found {len(forms)} form(s) total.")
    if composer_exposed:
        print(c_warn("  [+] composer.json/composer.lock is exposed -- confirmed PHP (likely Laravel/Composer-based)"))

    kept = [f for f in forms if f["tech"] in ("PHP", "ASP", "ASPX")]
    skipped = [f for f in forms if f["tech"] in ("JAVA", "API")]
    unknown = [f for f in forms if f["tech"] == "UNKNOWN"]

    print(f"  Kept (PHP/ASP/ASPX): {c_ok(str(len(kept)))}")
    print(f"  Skipped (Java/API):  {c_dim(str(len(skipped)))}")
    print(f"  Unknown tech:        {c_dim(str(len(unknown)))} (not written out)")

    if not kept:
        print(c_warn("\n[-] No PHP or ASP/ASP.NET forms found; nothing written."))
        print_error_summary()
        return

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

    print(c_ok(f"\n[+] Wrote {len(kept)} curl command(s) to {c_bold(out_path)}"))
    print_error_summary()


if __name__ == "__main__":
    main()
