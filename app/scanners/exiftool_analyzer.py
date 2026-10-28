"""CyberGuard AI - ExifTool Metadata & Polyglot Security Inspector.

Interfaces with ExifTool (via CLI binary or pyexiftool) to safely inspect
metadata, detect embedded script tags in EXIF fields (image polyglots / webshells),
and identify suspicious compiler / tooling footprints.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.scanners.base import (
    BaseScannerAdapter,
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.utils.logger import logger


class ExifToolAdapter(BaseScannerAdapter):
    """Adapter for Phil Harvey's ExifTool."""

    name: str = "ExifTool"
    version: str = "unknown"

    SUSPICIOUS_METADATA_PATTERNS = [
        (re.compile(r"<\?php", re.IGNORECASE), "Embedded PHP script in metadata (Webshell polyglot)"),
        (re.compile(r"<script", re.IGNORECASE), "Embedded HTML/JavaScript in metadata"),
        (re.compile(r"eval\s*\(", re.IGNORECASE), "Dynamic evaluation code in metadata"),
        (re.compile(r"base64_decode", re.IGNORECASE), "Base64 decode invocation in metadata"),
        (re.compile(r"powershell", re.IGNORECASE), "PowerShell reference in metadata"),
        (re.compile(r"(?:metasploit|cobalt\s*strike|mimikatz)", re.IGNORECASE), "Known exploit framework artifact"),
    ]

    def __init__(self, exiftool_path: Optional[str] = None) -> None:
        self.exiftool_path = exiftool_path or shutil.which("exiftool") or shutil.which("exiftool.exe")
        if self.exiftool_path:
            try:
                proc = subprocess.run(
                    [self.exiftool_path, "-ver"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if proc.returncode == 0:
                    self.version = proc.stdout.strip()
            except Exception:
                self.version = "installed"

    def is_available(self) -> bool:
        return bool(self.exiftool_path and Path(self.exiftool_path).exists())

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        """Asynchronously executes ExifTool metadata inspection."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message=(
                    "ExifTool binary not found in PATH. "
                    "Install via: apt-get install -y libimage-exiftool-perl (Linux) "
                    "or download exiftool.exe (Windows)."
                ),
            )

        if not file_path.exists():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )

        start_time = time.perf_counter()
        try:
            return await asyncio.to_thread(self._scan_sync, file_path, start_time)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error("ExifTool scan error on %s: %s", file_path.name, e)
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=str(e),
                execution_time_ms=elapsed_ms,
            )

    def _scan_sync(self, file_path: Path, start_time: float) -> ScannerResult:
        try:
            proc = subprocess.run(
                [str(self.exiftool_path), "-j", "-fast", str(file_path)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message="ExifTool execution timed out.",
                execution_time_ms=elapsed_ms,
            )

        if proc.returncode != 0:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"ExifTool returned code {proc.returncode}: {proc.stderr.strip()}",
                execution_time_ms=elapsed_ms,
            )

        findings: List[Finding] = []
        raw_metadata: Dict[str, Any] = {}

        try:
            data = json.loads(proc.stdout)
            if isinstance(data, list) and data:
                raw_metadata = data[0]
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"Failed to parse ExifTool JSON: {e}",
                execution_time_ms=elapsed_ms,
            )

        # Inspect all metadata values for suspicious patterns
        has_polyglot = False
        for key, val in raw_metadata.items():
            val_str = str(val)
            for pattern, threat_desc in self.SUSPICIOUS_METADATA_PATTERNS:
                if pattern.search(val_str):
                    has_polyglot = True
                    findings.append(
                        Finding(
                            title=f"Suspicious Metadata ({key})",
                            description=f"{threat_desc} detected in tag '{key}'.",
                            severity=Severity.HIGH,
                            evidence=f"Tag={key}, Preview={val_str[:60]}",
                            confidence="High",
                        )
                    )

        overall_sev = Severity.HIGH if has_polyglot else Severity.CLEAN
        confidence = "High" if has_polyglot else "Moderate"

        # Sanitize metadata dictionary (retain top useful fields)
        safe_keys = ["FileType", "MIMEType", "FileSize", "ImageSize", "CreateDate", "ModifyDate", "Software", "Author"]
        filtered_meta = {k: raw_metadata[k] for k in safe_keys if k in raw_metadata}

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return ScannerResult(
            scanner_name=self.name,
            scanner_version=self.version,
            status=ScanStatus.COMPLETED,
            findings=findings,
            severity=overall_sev,
            confidence=confidence,
            metadata=filtered_meta,
            execution_time_ms=elapsed_ms,
        )
