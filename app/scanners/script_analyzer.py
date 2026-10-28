"""CyberGuard AI - Static Script Security Analyzer.

Performs safe static inspection of scripts (Python, PowerShell, Bash, JavaScript, PHP, VBS)
without executing them. Detects obfuscation, dangerous shell commands, dynamic code execution,
credential dumping, persistence mechanisms, and embedded secrets.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional


class ScriptSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScriptFinding:
    """Represents a suspicious indicator detected during static script analysis."""

    category: str
    severity: ScriptSeverity
    description: str
    matched_snippet: str
    confidence: str  # High, Medium, Low


class ScriptAnalyzer:
    """Safe, non-executing static analyzer for scripts."""

    # Rule definitions: (Regex pattern, Category, Severity, Description, Confidence)
    PATTERNS = [
        # 1. PowerShell dangerous patterns
        (
            re.compile(r"(?i)(?:-enc(?:odedcommand)?|-e)\s+[A-Za-z0-9+/=]{16,}"),
            "PowerShell Obfuscation",
            ScriptSeverity.HIGH,
            "PowerShell encoded command execution (-EncodedCommand) detected.",
            "High",
        ),
        (
            re.compile(r"(?i)\b(?:iex|invoke-expression)\b\s*[\(\$]"),
            "PowerShell Execution",
            ScriptSeverity.HIGH,
            "Dynamic code execution via Invoke-Expression (IEX) detected.",
            "High",
        ),
        (
            re.compile(r"(?i)\.(?:downloadstring|downloadfile)\s*\("),
            "Download & Execute",
            ScriptSeverity.HIGH,
            "Remote payload download via WebClient/HttpClient detected.",
            "High",
        ),
        (
            re.compile(r"(?i)-executionpolicy\s+bypass|-ep\s+bypass"),
            "PowerShell Policy Bypass",
            ScriptSeverity.MEDIUM,
            "PowerShell ExecutionPolicy Bypass switch used.",
            "High",
        ),
        (
            re.compile(r"(?i)-windowstyle\s+hidden|-w\s+hidden"),
            "Stealth Execution",
            ScriptSeverity.MEDIUM,
            "Process launched with hidden window style.",
            "Medium",
        ),

        # 2. Dangerous Shell patterns
        (
            re.compile(r"(?i)(?:curl|wget)\s+[^|\n;]+\|\s*(?:sh|bash|zsh|dash|python)"),
            "Download & Execute",
            ScriptSeverity.CRITICAL,
            "Piped shell execution (curl/wget | sh/bash) detected.",
            "High",
        ),
        (
            re.compile(r"/(?:dev/tcp|dev/udp)/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+"),
            "Reverse Shell",
            ScriptSeverity.CRITICAL,
            "Bash /dev/tcp network reverse shell syntax detected.",
            "High",
        ),
        (
            re.compile(r"(?i)\bmkfifo\s+[^;]+;\s*(?:nc|netcat|sh|bash)"),
            "Reverse Shell",
            ScriptSeverity.CRITICAL,
            "FIFO named-pipe reverse shell pattern detected.",
            "High",
        ),
        (
            re.compile(r"\brm\s+-(?:rf|fr)\s+(?:/|/\*|--no-preserve-root)"),
            "Destructive Command",
            ScriptSeverity.CRITICAL,
            "Destructive root file deletion (rm -rf /) detected.",
            "High",
        ),

        # 3. Dynamic Code Execution
        (
            re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\("),
            "Dynamic Code Execution",
            ScriptSeverity.CRITICAL,
            "Obfuscated dynamic code execution (eval(base64_decode...)) detected.",
            "High",
        ),
        (
            re.compile(r"(?i)\bcreate_function\s*\([\'\"][^,]*[\'\"],\s*[\'\"](?:\beval\b|\bassert\b)"),
            "Dynamic Code Execution",
            ScriptSeverity.HIGH,
            "PHP create_function code execution vulnerability/payload.",
            "High",
        ),

        # 4. Credential Theft & Memory Dumping
        (
            re.compile(r"(?i)\b(?:mimikatz|sekurlsa|logonpasswords|lsass\.dmp|ntds\.dit)\b"),
            "Credential Theft",
            ScriptSeverity.CRITICAL,
            "Credential theft / LSASS memory dumping tool references.",
            "High",
        ),
        (
            re.compile(r"(?i)\breg\s+save\s+hklm\\(?:sam|system|security)\b"),
            "Credential Theft",
            ScriptSeverity.CRITICAL,
            "Registry SAM/SYSTEM hive extraction command detected.",
            "High",
        ),

        # 5. Persistence Mechanisms
        (
            re.compile(r"(?i)reg\s+add\s+[\'\"]?HK(?:LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            "Persistence",
            ScriptSeverity.HIGH,
            "Windows Registry Run key persistence modification detected.",
            "High",
        ),
        (
            re.compile(r"(?i)\bschtasks\s+/create\s+"),
            "Persistence",
            ScriptSeverity.MEDIUM,
            "Scheduled task creation command (schtasks) detected.",
            "Medium",
        ),
        (
            re.compile(r"(?i)\bcrontab\s+-(?:l|e|r)?\s*\|\s*crontab\b|\/etc\/cron\.(?:hourly|daily|weekly)"),
            "Persistence",
            ScriptSeverity.MEDIUM,
            "Linux crontab / scheduled job persistence modification.",
            "Medium",
        ),

        # 6. Hardcoded Secrets & Tokens
        (
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "Hardcoded Secret",
            ScriptSeverity.HIGH,
            "AWS Access Key ID hardcoded in script.",
            "High",
        ),
        (
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "Hardcoded Secret",
            ScriptSeverity.HIGH,
            "Private cryptographic key material embedded in script.",
            "High",
        ),
        (
            re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{35}\b"),
            "Hardcoded Secret",
            ScriptSeverity.MEDIUM,
            "Telegram Bot API Token hardcoded in script.",
            "High",
        ),
    ]

    @classmethod
    def analyze_file(cls, file_path: Path | str) -> List[ScriptFinding]:
        """Reads script text safely and evaluates static detection patterns."""
        p = Path(file_path)
        if not p.is_file():
            return []

        # Read first 512 KB to avoid hanging on multi-gigabyte files
        content = cls._read_text_safely(p, max_bytes=512 * 1024)
        if not content:
            return []

        findings: List[ScriptFinding] = []

        # Evaluate regex patterns
        for pattern, category, severity, description, confidence in cls.PATTERNS:
            match = pattern.search(content)
            if match:
                snippet = match.group(0)
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                findings.append(
                    ScriptFinding(
                        category=category,
                        severity=severity,
                        description=description,
                        matched_snippet=snippet,
                        confidence=confidence,
                    )
                )

        # Inspect large Base64 blobs for hidden executables or payloads
        b64_findings = cls._inspect_base64_blobs(content)
        findings.extend(b64_findings)

        return findings

    @classmethod
    def _inspect_base64_blobs(cls, text: str) -> List[ScriptFinding]:
        """Extracts and decodes candidate Base64 strings to check for PE headers (TVqQ) or payloads."""
        findings = []
        # Find continuous base64 strings of length >= 64
        b64_candidates = re.findall(r"[A-Za-z0-9+/=]{64,}", text)
        for b64_str in b64_candidates[:5]:
            try:
                decoded = base64.b64decode(b64_str, validate=True)
                if decoded.startswith(b"MZ"):
                    findings.append(
                        ScriptFinding(
                            category="Embedded Executable",
                            severity=ScriptSeverity.CRITICAL,
                            description="Base64-encoded Windows Executable (PE/MZ header) found inside script.",
                            matched_snippet=b64_str[:40] + "...",
                            confidence="High",
                        )
                    )
                    break
                elif b"powershell" in decoded.lower() or b"cmd.exe" in decoded.lower():
                    findings.append(
                        ScriptFinding(
                            category="Obfuscated Payload",
                            severity=ScriptSeverity.HIGH,
                            description="Base64-encoded shell payload found inside script.",
                            matched_snippet=b64_str[:40] + "...",
                            confidence="High",
                        )
                    )
                    break
            except Exception:
                continue

        return findings

    @staticmethod
    def _read_text_safely(file_path: Path, max_bytes: int = 512 * 1024) -> Optional[str]:
        """Reads file bytes with multiple encoding fallbacks (utf-8, latin-1, utf-16)."""
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(max_bytes)

            for enc in ("utf-8", "latin-1", "utf-16", "cp1252"):
                try:
                    return raw_bytes.decode(enc)
                except UnicodeDecodeError:
                    continue
            return raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return None
