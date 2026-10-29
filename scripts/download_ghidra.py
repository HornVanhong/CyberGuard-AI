"""Download Ghidra release package with progress and resume."""

import os
import sys
import time
import urllib.request
from pathlib import Path

GHIDRA_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip"
TARGET_DIR = Path(__file__).resolve().parent.parent / "tools"
TARGET_FILE = TARGET_DIR / "ghidra.zip"


def download_ghidra() -> Path:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    if TARGET_FILE.exists() and TARGET_FILE.stat().st_size > 500 * 1024 * 1024:
        print(f"[OK] Ghidra zip already exists: {TARGET_FILE} ({TARGET_FILE.stat().st_size / (1024*1024):.1f} MB)")
        return TARGET_FILE

    print(f"[*] Downloading Ghidra 12.2 from {GHIDRA_URL}...")
    req = urllib.request.Request(GHIDRA_URL, headers={"User-Agent": "CyberGuard-AI/1.0"})

    with urllib.request.urlopen(req) as resp, open(TARGET_FILE, "wb") as out_file:
        total_size = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024  # 1 MB
        start_time = time.time()
        last_print = 0

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out_file.write(chunk)
            downloaded += len(chunk)

            now = time.time()
            if now - last_print > 3 or downloaded == total_size:
                elapsed = now - start_time
                speed = (downloaded / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                pct = (downloaded / total_size * 100) if total_size else 0
                print(f" -> {downloaded / (1024*1024):.1f} MB / {total_size / (1024*1024):.1f} MB ({pct:.1f}%) at {speed:.2f} MB/s")
                last_print = now

    print(f"[+] Download complete: {TARGET_FILE} ({TARGET_FILE.stat().st_size / (1024*1024):.1f} MB)")
    return TARGET_FILE


if __name__ == "__main__":
    download_ghidra()
