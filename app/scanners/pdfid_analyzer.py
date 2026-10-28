"""CyberGuard AI - PDFiD Suspicious Structural Indicator Analyzer.

Integrates Didier Stevens' PDFiD tool to passively scan PDF files for
embedded JavaScript, launch actions, automatic execution hooks, and
hexadecimal name obfuscation without rendering untrusted content.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List

from app.scanners.base import (
    BaseScannerAdapter,
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.utils.logger import logger

try:
    from pdfid import pdfid
    _PDFID_AVAILABLE = True
    _PDFID_VERSION = getattr(pdfid, "__version__", "1.1.3")
except ImportError:
    _PDFID_AVAILABLE = False
    _PDFID_VERSION = "unavailable"


class PDFiDAdapter(BaseScannerAdapter):
    """Adapter for Didier Stevens' PDFiD engine."""

    name: str = "PDFiD"
    version: str = _PDFID_VERSION

    # Critical triggers and their assigned default severities
    INDICATOR_SEVERITIES: Dict[str, Severity] = {
        "/Launch": Severity.CRITICAL,
        "/JavaScript": Severity.HIGH,
        "/JS": Severity.HIGH,
        "/EmbeddedFile": Severity.HIGH,
        "/OpenAction": Severity.MEDIUM,
        "/AA": Severity.MEDIUM,
        "/AcroForm": Severity.LOW,
        "/JBIG2Decode": Severity.MEDIUM,
        "/RichMedia": Severity.MEDIUM,
        "/XFA": Severity.LOW,
    }

    def is_available(self) -> bool:
        return _PDFID_AVAILABLE

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        """Asynchronously executes PDFiD structural analysis on a PDF file."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="PDFiD is not installed. Install via: pip install pdfid",
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
            logger.error("PDFiD scan error on %s: %s", file_path.name, e)
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=str(e),
                execution_time_ms=elapsed_ms,
            )

    def _scan_sync(self, file_path: Path, start_time: float) -> ScannerResult:
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {}

        try:
            dom = pdfid.PDFiD(str(file_path), allNames=True, extraData=True)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"PDF parsing error: {e}",
                execution_time_ms=elapsed_ms,
            )

        # Extract root attributes
        header = dom.documentElement.getAttribute("Header") or "Unknown"
        is_pdf = dom.documentElement.getAttribute("IsPDF") == "True"
        entropy = dom.documentElement.getAttribute("Entropy")

        metadata["header"] = header
        metadata["is_pdf"] = is_pdf
        if entropy:
            metadata["entropy"] = entropy

        if not is_pdf:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.COMPLETED,
                findings=[
                    Finding(
                        title="Malformed / Non-Standard PDF Header",
                        description=f"File does not begin with standard PDF header. Found: {header}",
                        severity=Severity.HIGH,
                        confidence="High",
                    )
                ],
                severity=Severity.HIGH,
                confidence="High",
                metadata=metadata,
                execution_time_ms=elapsed_ms,
            )

        # Inspect keyword nodes
        keyword_counts: Dict[str, int] = {}
        has_js = False
        has_open_action = False
        has_launch = False
        has_obfuscation = False

        for node in dom.getElementsByTagName("Keyword"):
            name = node.getAttribute("Name")
            count = int(node.getAttribute("Count") or 0)
            hex_count = int(node.getAttribute("HexcodeCount") or 0)
            keyword_counts[name] = count

            if hex_count > 0:
                has_obfuscation = True
                findings.append(
                    Finding(
                        title=f"Hexadecimal Obfuscation in PDF Name ({name})",
                        description=f"PDF name '{name}' employs hex-encoding ({hex_count} instances) to evade naive string search.",
                        severity=Severity.HIGH,
                        evidence=f"HexcodeCount={hex_count}",
                        confidence="High",
                    )
                )

            if count > 0 and name in self.INDICATOR_SEVERITIES:
                sev = self.INDICATOR_SEVERITIES[name]
                if name in ("/JavaScript", "/JS"):
                    has_js = True
                    desc = f"Contains {count} embedded JavaScript element(s)."
                elif name == "/Launch":
                    has_launch = True
                    desc = f"Contains {count} Launch action(s) capable of triggering external commands."
                elif name in ("/OpenAction", "/AA"):
                    has_open_action = True
                    desc = f"Contains {count} automatic action hook(s) executed upon opening."
                elif name == "/EmbeddedFile":
                    desc = f"Contains {count} embedded file payload attachment(s)."
                else:
                    desc = f"Contains {count} instances of suspicious structural element {name}."

                findings.append(
                    Finding(
                        title=f"PDF Structural Indicator: {name}",
                        description=desc,
                        severity=sev,
                        evidence=f"Keyword={name}, Count={count}",
                        confidence="High",
                    )
                )

        metadata["keyword_counts"] = keyword_counts

        # Overall severity correlation
        if has_launch or (has_js and has_open_action):
            overall_sev = Severity.CRITICAL
            confidence = "High"
        elif has_js or has_obfuscation or keyword_counts.get("/EmbeddedFile", 0) > 0:
            overall_sev = Severity.HIGH
            confidence = "High"
        elif has_open_action or keyword_counts.get("/JBIG2Decode", 0) > 0:
            overall_sev = Severity.MEDIUM
            confidence = "Moderate"
        elif findings:
            overall_sev = Severity.LOW
            confidence = "Moderate"
        else:
            overall_sev = Severity.CLEAN
            confidence = "High"

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return ScannerResult(
            scanner_name=self.name,
            scanner_version=self.version,
            status=ScanStatus.COMPLETED,
            findings=findings,
            severity=overall_sev,
            confidence=confidence,
            metadata=metadata,
            execution_time_ms=elapsed_ms,
        )
