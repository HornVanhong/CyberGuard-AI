"""CyberGuard AI - Gitleaks Secret & Credential Detection Adapter.

Inspects source code, scripts, configuration files, and text documents for
accidentally exposed API keys, private keys, access tokens, and credentials.
Supports both native 'gitleaks' CLI execution and an embedded high-precision
secret rule engine with mandatory credential redaction.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.scanners.base import (
    BaseScannerAdapter,
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.utils.logger import logger


class GitleaksAdapter(BaseScannerAdapter):
    """Adapter for Gitleaks credential & secret detection with embedded fallback."""

    name: str = "Gitleaks"
    version: str = "embedded"

    # High-fidelity regex rules matching common high-value secrets
    SECRET_RULES: List[Tuple[str, re.Pattern, Severity]] = [
        (
            "AWS Access Key ID",
            re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            Severity.HIGH,
        ),
        (
            "GitHub Personal Access Token",
            re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
            Severity.CRITICAL,
        ),
        (
            "Telegram Bot API Token",
            re.compile(r"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b"),
            Severity.HIGH,
        ),
        (
            "Google API / Gemini Key",
            re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"),
            Severity.HIGH,
        ),
        (
            "OpenAI Secret Key",
            re.compile(r"\b(sk-[a-zA-Z0-9]{20,48})\b"),
            Severity.HIGH,
        ),
        (
            "Slack Webhook / Token",
            re.compile(r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/[0-9a-zA-Z]+)"),
            Severity.HIGH,
        ),
        (
            "Private Cryptographic Key",
            re.compile(r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE\s+KEY-----"),
            Severity.CRITICAL,
        ),
        (
            "Stripe Secret Key",
            re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34})\b"),
            Severity.HIGH,
        ),
        (
            "JSON Web Token (JWT)",
            re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
            Severity.MEDIUM,
        ),
        (
            "Hardcoded Credential Assignment",
            re.compile(r"""(?i)(?:password|passwd|api_secret|client_secret)\s*[:=]\s*['"]([^\s'"]{8,64})['"]"""),
            Severity.MEDIUM,
        ),
    ]

    def __init__(self, gitleaks_path: Optional[str] = None) -> None:
        self.gitleaks_path = gitleaks_path or shutil.which("gitleaks") or shutil.which("gitleaks.exe")
        if self.gitleaks_path:
            try:
                proc = subprocess.run(
                    [self.gitleaks_path, "version"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if proc.returncode == 0:
                    self.version = f"cli-{proc.stdout.strip()}"
            except Exception:
                self.version = "cli-installed"

    def is_available(self) -> bool:
        # Always available via built-in high-precision regex engine or CLI
        return True

    @staticmethod
    def mask_secret(secret_text: str) -> str:
        """Sanitizes secret token strings to prevent sensitive credential leakage."""
        if len(secret_text) <= 8:
            return "****"
        return f"{secret_text[:4]}****{secret_text[-4:]}"

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        """Asynchronously executes Gitleaks / Secret detection on the file."""
        if not file_path.exists():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )

        start_time = time.perf_counter()

        # If native gitleaks CLI is available, try running it
        if self.gitleaks_path:
            try:
                cli_res = await self._run_cli_scan(file_path, start_time)
                if cli_res.status == ScanStatus.COMPLETED:
                    return cli_res
            except Exception as e:
                logger.debug("Native gitleaks CLI scan failed, falling back to embedded engine: %s", e)

        # Fallback to embedded high-precision pattern scanner
        return await asyncio.to_thread(self._scan_embedded_sync, file_path, start_time)

    async def _run_cli_scan(self, file_path: Path, start_time: float) -> ScannerResult:
        proc = await asyncio.create_subprocess_exec(
            str(self.gitleaks_path),
            "detect",
            "--no-git",
            "--source",
            str(file_path),
            "--report-format",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Gitleaks returns 1 if leaks were detected, 0 if clean
        if proc.returncode not in (0, 1):
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"gitleaks CLI returned code {proc.returncode}: {stderr.decode()}",
                execution_time_ms=elapsed_ms,
            )

        findings: List[Finding] = []
        if proc.returncode == 1:
            try:
                leaks = json.loads(stdout.decode()) if stdout else []
                for leak in leaks:
                    rule = leak.get("RuleID", "Secret")
                    secret = leak.get("Secret", "")
                    masked = self.mask_secret(secret)
                    findings.append(
                        Finding(
                            title=f"Hardcoded Credential / Secret: {rule}",
                            description=f"Gitleaks detected hardcoded secret matching rule '{rule}'.",
                            severity=Severity.HIGH,
                            evidence=f"Masked={masked}, Line={leak.get('StartLine', 0)}",
                            confidence="High",
                        )
                    )
            except Exception as e:
                logger.warning("Failed to parse gitleaks CLI JSON output: %s", e)

        sev = Severity.HIGH if findings else Severity.CLEAN
        return ScannerResult(
            scanner_name=self.name,
            scanner_version=self.version,
            status=ScanStatus.COMPLETED,
            findings=findings,
            severity=sev,
            confidence="High",
            metadata={"source": "gitleaks-cli", "leak_count": len(findings)},
            execution_time_ms=elapsed_ms,
        )

    def _scan_embedded_sync(self, file_path: Path, start_time: float) -> ScannerResult:
        findings: List[Finding] = []

        try:
            # Read first 1MB of file content as text
            content = file_path.read_text(encoding="utf-8", errors="ignore")[:1024 * 1024]
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"Could not read text for secret scanning: {e}",
                execution_time_ms=elapsed_ms,
            )

        detected_rules = set()
        for rule_name, pattern, severity in self.SECRET_RULES:
            match = pattern.search(content)
            if match and rule_name not in detected_rules:
                detected_rules.add(rule_name)
                matched_raw = match.group(0)
                masked = self.mask_secret(matched_raw)

                findings.append(
                    Finding(
                        title=f"Hardcoded Secret Detected ({rule_name})",
                        description=f"File contains hardcoded credential or secret matching '{rule_name}'.",
                        severity=severity,
                        evidence=f"Token={masked}",
                        confidence="High",
                    )
                )

        if any(f.severity == Severity.CRITICAL for f in findings):
            overall_sev = Severity.CRITICAL
        elif any(f.severity == Severity.HIGH for f in findings):
            overall_sev = Severity.HIGH
        elif findings:
            overall_sev = Severity.MEDIUM
        else:
            overall_sev = Severity.CLEAN

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return ScannerResult(
            scanner_name=self.name,
            scanner_version=self.version,
            status=ScanStatus.COMPLETED,
            findings=findings,
            severity=overall_sev,
            confidence="High" if findings else "Moderate",
            metadata={"source": "embedded-rules", "matches": len(findings)},
            execution_time_ms=elapsed_ms,
        )
