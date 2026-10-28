#!/usr/bin/env bash
# CyberGuard AI - ClamAV Signature Update Script
set -euo pipefail

echo "[*] Triggering freshclam signature update..."
if command -v freshclam >/dev/null 2>&1; then
    freshclam --verbose
    echo "[+] Signatures successfully updated."
elif docker ps --format '{{.Names}}' | grep -q "cyberguard-clamav"; then
    echo "[*] Running freshclam inside cyberguard-clamav container..."
    docker exec -it cyberguard-clamav freshclam
    echo "[+] Docker container signatures updated."
else
    echo "[-] freshclam is not installed locally and cyberguard-clamav container is not running."
    exit 1
fi
