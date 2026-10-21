#!/usr/bin/env bash
# Installs ppfngr as a `uv tool` so it runs from anywhere on PATH as `ppfngr`,
# in its own isolated environment (no venv activation needed, no polluting
# whatever other Python env you're in). Re-run this any time after pulling
# changes to reinstall with --force.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v uv >/dev/null 2>&1; then
    echo "[!] uv is not installed. Install it first:"
    echo "      curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "[*] Installing ppfngr via uv tool..."
uv tool install --force .

if ! command -v ppfngr >/dev/null 2>&1; then
    echo
    echo "[!] 'ppfngr' isn't on PATH yet. uv installs its tool shims to ~/.local/bin"
    echo "    (or \$UV_TOOL_BIN_DIR, if you've set that). Run this once, then open a"
    echo "    new shell:"
    echo
    echo "      uv tool update-shell"
    echo
    exit 0
fi

echo
echo "[+] Installed. Try it:"
echo "      ppfngr https://target.example.com"
echo "      cat subdomains.txt | ppfngr"
