"""CyberGuard AI - oletools Office Document & Macro Security Analyzer.

Utilizes oletools (olevba) to passively inspect Microsoft Office documents
(OLE2: .doc, .xls, .ppt and OpenXML: .docm, .xlsm, .pptm, .docx) for hidden
VBA macros, auto-exec hooks, system execution calls, and obfuscation.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, List

from app.scanners.base import (
    BaseScannerAdapter,
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.utils.logger import logger

try:
    import oletools
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    _OLETOOLS_AVAILABLE = True
    _OLETOOLS_VERSION = getattr(oletools, "__version__", "0.60.2")
except ImportError:
    _OLETOOLS_AVAILABLE = False
    _OLETOOLS_VERSION = "unavailable"


class OletoolsAdapter(BaseScannerAdapter):
    """Adapter for Philippe Lagadec's oletools suite."""

    name: str = "oletools"
    version: str = _OLETOOLS_VERSION

    def is_available(self) -> bool:
        return _OLETOOLS_AVAILABLE

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        """Asynchronously executes olevba analysis on an Office document."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="oletools is not installed. Install via: pip install oletools",
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
            logger.error("oletools scan error on %s: %s", file_path.name, e)
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=str(e),
                execution_time_ms=elapsed_ms,
            )

    def _scan_sync(self, file_path: Path, start_time: float) -> ScannerResult:
        findings: List[Finding] = []
        has_autoexec = False
        has_suspicious = False
        has_hex_obfuscation = False

        try:
            parser = VBA_Parser(str(file_path))
        except Exception as e:
            # File might not be an OLE/OpenXML package (e.g. plain text or corrupted)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.COMPLETED,
                findings=[],
                severity=Severity.CLEAN,
                confidence="High",
                metadata={"parsed": False, "error": str(e)},
                execution_time_ms=elapsed_ms,
            )

        try:
            has_macros = parser.detect_vba_macros()
            if not has_macros:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return ScannerResult(
                    scanner_name=self.name,
                    scanner_version=self.version,
                    status=ScanStatus.COMPLETED,
                    findings=[],
                    severity=Severity.CLEAN,
                    confidence="High",
                    metadata={"has_macros": False, "type": parser.type},
                    execution_time_ms=elapsed_ms,
                )

            # Analyze VBA macro code
            results = parser.analyze_macros()
            for kw_type, keyword, description in results:
                desc_lower = description.lower()
                sev = Severity.MEDIUM
                conf = "High"

                if kw_type == "AutoExec":
                    has_autoexec = True
                    sev = Severity.HIGH
                    title = f"VBA Auto-Execution Hook: {keyword}"
                elif kw_type == "Suspicious":
                    has_suspicious = True
                    sev = Severity.HIGH
                    if any(term in desc_lower for term in ["shell", "powershell", "execute", "download", "url"]):
                        sev = Severity.CRITICAL
                    title = f"Suspicious VBA API Invocation: {keyword}"
                elif kw_type == "IOC":
                    sev = Severity.HIGH
                    title = f"VBA Network / System IOC: {keyword}"
                elif kw_type == "Hex String":
                    has_hex_obfuscation = True
                    sev = Severity.MEDIUM
                    title = f"Obfuscated Hex String: {keyword[:20]}..."
                else:
                    title = f"VBA Indicator ({kw_type}): {keyword}"

                findings.append(
                    Finding(
                        title=title,
                        description=description,
                        severity=sev,
                        evidence=f"Keyword={keyword}, Type={kw_type}",
                        confidence=conf,
                    )
                )

            # Determine overall severity
            if any(f.severity == Severity.CRITICAL for f in findings):
                overall_sev = Severity.CRITICAL
                confidence = "High"
            elif has_autoexec and has_suspicious:
                overall_sev = Severity.CRITICAL
                confidence = "High"
            elif has_suspicious or has_autoexec:
                overall_sev = Severity.HIGH
                confidence = "High"
            elif findings:
                overall_sev = Severity.MEDIUM
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
                metadata={"has_macros": True, "type": parser.type, "total_indicators": len(results)},
                execution_time_ms=elapsed_ms,
            )
        finally:
            parser.close()
