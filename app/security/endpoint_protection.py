"""CyberGuard AI - Host Endpoint Protection & Defender Interceptor.

Detects when host operating system real-time protection (e.g. Microsoft Defender,
antivirus drivers) intercepts, quarantines, or locks a detected malicious payload.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.utils.logger import logger


@dataclass
class EndpointThreatInfo:
    threat_name: str
    severity: str
    category: str
    source: str
    quarantined: bool


def detect_defender_quarantine(target_hint: Optional[str] = None) -> Optional[EndpointThreatInfo]:
    """Checks if Microsoft Defender recently flagged or quarantined a target file."""
    if os.name != "nt":
        return None

    try:
        ps_script = (
            "$events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' "
            "-MaxEvents 8 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 1116, 1117 }; "
            "if ($events) { $events[0].Message }"
        )
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if res.returncode != 0 or not res.stdout:
            return None

        msg = res.stdout.strip()
        threat_name = "Malware / Trojan"
        severity = "Severe"
        category = "Trojan"
        quarantined = "Quarantine" in msg

        m_name = re.search(r"Name:\s*(.+)", msg)
        if m_name:
            threat_name = m_name.group(1).strip()

        m_sev = re.search(r"Severity:\s*(.+)", msg)
        if m_sev:
            severity = m_sev.group(1).strip()

        m_cat = re.search(r"Category:\s*(.+)", msg)
        if m_cat:
            category = m_cat.group(1).strip()

        return EndpointThreatInfo(
            threat_name=threat_name,
            severity=severity,
            category=category,
            source="Microsoft Defender Real-Time Protection",
            quarantined=quarantined,
        )
    except Exception as e:
        logger.debug("Error checking Defender events: %s", e)
        return None
