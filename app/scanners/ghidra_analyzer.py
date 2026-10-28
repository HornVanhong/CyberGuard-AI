"""CyberGuard AI - Ghidra SRE & Decompiler Adapter.

Uses NSA's Ghidra headless analyzer (analyzeHeadless) to perform:
1. Program disassembly and metadata extraction (language, compiler, image base)
2. Dangerous API cross-reference (XREF) discovery (VirtualAlloc, CreateRemoteThread, etc.)
3. Pseudo-C decompilation of entry points / main functions
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
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


class GhidraAdapter(BaseScannerAdapter):
    """Adapter for Ghidra Headless Analyzer (analyzeHeadless)."""

    name: str = "Ghidra (SRE & Decompiler)"
    version: str = "12.2"

    def __init__(
        self,
        ghidra_path: Optional[str] = None,
        timeout_seconds: float = 45.0,
    ) -> None:
        self.ghidra_path = (
            ghidra_path
            or os.getenv("GHIDRA_PATH")
            or shutil.which("analyzeHeadless")
            or shutil.which("analyzeHeadless.bat")
            or self._discover_ghidra_path()
        )
        self.timeout_seconds = timeout_seconds
        self.scripts_dir = Path(__file__).parent / "ghidra_scripts"

    def _discover_ghidra_path(self) -> Optional[str]:
        common_paths = [
            "/opt/ghidra/support/analyzeHeadless",
            "/usr/local/ghidra/support/analyzeHeadless",
            "/app/ghidra/support/analyzeHeadless",
            "C:\\ghidra\\support\\analyzeHeadless.bat",
            "D:\\ghidra\\support\\analyzeHeadless.bat",
        ]
        for p in common_paths:
            if Path(p).exists():
                return p
        return None

    def is_available(self) -> bool:
        """Checks if both Ghidra analyzeHeadless and Java are available."""
        java_available = bool(shutil.which("java") or os.getenv("JAVA_HOME"))
        ghidra_available = bool(self.ghidra_path and Path(self.ghidra_path).exists())
        return ghidra_available and java_available

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        """Executes headless analysis on executable binaries."""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="Ghidra or Java (OpenJDK 17+) not found. Install Ghidra to enable deep decompilation.",
            )

        if not file_path.exists():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )

        start_time = time.perf_counter()
        temp_dir = tempfile.mkdtemp(prefix="ghidra_proj_")
        report_file = Path(temp_dir) / "ghidra_report.json"

        try:
            # Build analyzeHeadless command
            # analyzeHeadless <project_location> <project_name> -import <file> -readOnly -deleteProject -scriptPath <path> -postScript <script> <args>
            cmd = [
                str(self.ghidra_path),
                temp_dir,
                "CyberGuardTempProj",
                "-import",
                str(file_path),
                "-readOnly",
                "-deleteProject",
                "-noanalysis",  # Fast import; script handles targeted decompilation
                "-scriptPath",
                str(self.scripts_dir),
                "-postScript",
                "AnalyzeBinary.java",
                str(report_file),
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout_seconds
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return ScannerResult(
                    scanner_name=self.name,
                    scanner_version=self.version,
                    status=ScanStatus.ERROR,
                    error_message=f"Ghidra analysis timed out after {self.timeout_seconds}s.",
                    execution_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if not report_file.exists():
                logger.warning(f"Ghidra report not generated: {stderr.decode(errors='replace')[:300]}")
                return ScannerResult(
                    scanner_name=self.name,
                    scanner_version=self.version,
                    status=ScanStatus.ERROR,
                    error_message="Ghidra completed but did not produce a report.",
                    execution_time_ms=elapsed_ms,
                )

            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            findings: List[Finding] = []
            dangerous_apis = data.get("dangerous_apis", [])
            compiler = data.get("compiler", "Unknown")
            func_count = data.get("function_count", 0)
            decompiled_code = data.get("decompiled_code", "")

            # 1. Evaluate Dangerous APIs
            high_risk_calls = []
            for item in dangerous_apis:
                api = item.get("api", "")
                callers = item.get("callers", [])
                high_risk_calls.append(f"{api} (xrefs: {len(callers)})")

            if high_risk_calls:
                findings.append(
                    Finding(
                        title="High-Risk API Cross-References",
                        description=f"Identified {len(high_risk_calls)} sensitive system APIs with active caller cross-references.",
                        severity=Severity.HIGH if len(high_risk_calls) >= 3 else Severity.MEDIUM,
                        confidence=0.90,
                        evidence=", ".join(high_risk_calls[:8]),
                    )
                )

            # 2. General metadata finding
            findings.append(
                Finding(
                    title="Ghidra Binary Architecture",
                    description=f"Identified {func_count} functions; compiled with {compiler}.",
                    severity=Severity.LOW if func_count > 0 else Severity.CLEAN,
                    confidence=0.95,
                    evidence=f"Functions: {func_count} | Language: {data.get('language_id', '')}",
                )
            )

            # Compute overall severity
            if any(f.severity == Severity.CRITICAL for f in findings):
                overall_sev = Severity.CRITICAL
            elif any(f.severity == Severity.HIGH for f in findings):
                overall_sev = Severity.HIGH
            elif any(f.severity == Severity.MEDIUM for f in findings):
                overall_sev = Severity.MEDIUM
            else:
                overall_sev = Severity.CLEAN

            result = ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.COMPLETED,
                findings=findings,
                severity=overall_sev,
                confidence=0.90,
                execution_time_ms=elapsed_ms,
            )
            # Attach decompiled snippet for forensic inspection
            result.metadata = {
                "entry_function": data.get("entry_function", ""),
                "decompiled_code": decompiled_code,
                "function_count": func_count,
            }
            return result

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Ghidra execution error: {e}")
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"Ghidra error: {e}",
                execution_time_ms=elapsed_ms,
            )
        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
