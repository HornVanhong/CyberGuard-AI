"""CyberGuard AI - Multi-Engine Scanner Orchestrator.

Manages execution of modular cybersecurity scanners based on verified file format.
Executes tools concurrently where safe, enforces processing timeouts,
and aggregates standardized ScannerResult records.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.scanners.base import (
    BaseScannerAdapter,
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.scanners.file_analyzer import FileAnalyzer, FileCategory, FileTypeAnalysis
from app.scanners.clamav_scanner import ClamAVScanner, ClamAVStatus
from app.scanners.yara_scanner import YaraScanner, YaraStatus
from app.scanners.oletools_analyzer import OletoolsAdapter
from app.scanners.pdfid_analyzer import PDFiDAdapter
from app.scanners.exiftool_analyzer import ExifToolAdapter
from app.scanners.executable_analyzer import CapaAdapter, DiecAdapter
from app.scanners.gitleaks_analyzer import GitleaksAdapter
from app.scanners.script_analyzer import ScriptAnalyzer, ScriptFinding
from app.scanners.pdf_analyzer import PDFAnalyzer, PDFFinding
from app.scanners.archive_analyzer import ArchiveAnalyzer, ArchiveFinding
from app.scanners.office_analyzer import OfficeAnalyzer, OfficeFinding
from app.utils.logger import logger


@dataclass
class OrchestrationResult:
    """Consolidated results from all scanners executed for a file."""

    file_analysis: FileTypeAnalysis
    clamav_result: Optional[ClamAVResult] = None
    yara_result: Optional[YaraResult] = None
    adapter_results: List[ScannerResult] = field(default_factory=list)
    script_findings: Optional[List[ScriptFinding]] = None
    pdf_findings: Optional[List[PDFFinding]] = None
    archive_findings: Optional[List[ArchiveFinding]] = None
    office_findings: Optional[List[OfficeFinding]] = None

    def get_result_by_scanner(self, scanner_name: str) -> Optional[ScannerResult]:
        for res in self.adapter_results:
            if scanner_name.lower() in res.scanner_name.lower():
                return res
        return None

    def get_all_findings(self) -> List[Finding]:
        findings = []
        for res in self.adapter_results:
            findings.extend(res.findings)
        return findings

    def get_engines_summary(self) -> Dict[str, List[str]]:
        checked = []
        unavailable = []
        failed = []

        for res in self.adapter_results:
            if res.status == ScanStatus.COMPLETED:
                checked.append(res.scanner_name)
            elif res.status == ScanStatus.UNAVAILABLE:
                unavailable.append(res.scanner_name)
            elif res.status == ScanStatus.ERROR:
                failed.append(res.scanner_name)

        return {
            "checked": checked,
            "unavailable": unavailable,
            "failed": failed,
        }


class ScannerOrchestrator:
    """Selects and executes applicable security tools based on file type."""

    def __init__(
        self,
        clamav: Optional[ClamAVScanner] = None,
        yara: Optional[YaraScanner] = None,
    ) -> None:
        self.clamav = clamav or ClamAVScanner()
        self.yara = yara or YaraScanner()
        self.oletools = OletoolsAdapter()
        self.pdfid = PDFiDAdapter()
        self.exiftool = ExifToolAdapter()
        self.capa = CapaAdapter()
        self.diec = DiecAdapter()
        self.gitleaks = GitleaksAdapter()

    async def execute_scan(
        self,
        file_path: Path,
        clean_filename: str,
        timeout: float = 30.0,
    ) -> OrchestrationResult:
        """Executes applicable multi-engine scan on target file."""
        # 1. Identify format and check extension masquerading
        file_analysis = await asyncio.to_thread(
            FileAnalyzer.analyze, file_path, clean_filename
        )

        ext = Path(clean_filename).suffix.lower()
        adapter_results: List[ScannerResult] = []

        # 2. Universal Scanners: ClamAV, YARA, ExifTool
        clamav_res, yara_res = await asyncio.gather(
            self.clamav.scan_file(file_path),
            self.yara.scan_file(file_path),
        )
        adapter_results.append(self._convert_clamav_result(clamav_res))
        adapter_results.append(self._convert_yara_result(yara_res))

        exif_task = self.exiftool.scan(file_path)

        # 3. Format-specific scanners
        format_tasks = [exif_task]

        # Executables (.exe, .dll, .sys, .elf, .msi, etc.)
        is_executable = (
            file_analysis.category == FileCategory.EXECUTABLE
            or ext in [".exe", ".dll", ".sys", ".elf", ".bin", ".msi", ".com", ".scr"]
        )
        if is_executable:
            format_tasks.append(self.capa.scan(file_path))
            format_tasks.append(self.diec.scan(file_path))

        # Office documents (.doc, .xls, .ppt, .docm, .xlsm, .docx, .pptx)
        is_office = (
            file_analysis.category == FileCategory.DOCUMENT
            and ext in [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".rtf"]
        )
        if is_office:
            format_tasks.append(self.oletools.scan(file_path))

        # PDF documents
        is_pdf = (
            file_analysis.category == FileCategory.DOCUMENT and ext == ".pdf"
        )
        if is_pdf:
            format_tasks.append(self.pdfid.scan(file_path))

        # Source code & Scripts (.py, .js, .ts, .php, .sh, .ps1, .env, .json, etc.)
        is_script_or_text = (
            file_analysis.category in (FileCategory.SCRIPT, FileCategory.TEXT)
            or ext in [
                ".py", ".js", ".ts", ".mjs", ".php", ".ps1", ".bat", ".cmd", ".sh", ".bash",
                ".vbs", ".env", ".json", ".yml", ".yaml", ".ini", ".conf", ".sql", ".txt"
            ]
        )
        if is_script_or_text:
            format_tasks.append(self.gitleaks.scan(file_path))

        # Run format-specific scanners concurrently with timeout
        completed_results = await asyncio.gather(*format_tasks, return_exceptions=True)

        for res in completed_results:
            if isinstance(res, ScannerResult):
                adapter_results.append(res)
            elif isinstance(res, Exception):
                logger.error("Scanner task raised unhandled exception: %s", res)

        # 4. Complementary deep analyzers
        script_findings = None
        pdf_findings = None
        archive_findings = None
        office_findings = None

        if is_script_or_text:
            script_findings = await asyncio.to_thread(ScriptAnalyzer.analyze_file, file_path)

        if is_pdf:
            pdf_findings = await asyncio.to_thread(PDFAnalyzer.analyze_file, file_path)

        if file_analysis.category == FileCategory.ARCHIVE or ext in [".zip", ".tar", ".gz", ".tgz"]:
            archive_findings = await asyncio.to_thread(ArchiveAnalyzer.analyze_file, file_path)

        if is_office:
            office_findings = await asyncio.to_thread(OfficeAnalyzer.analyze_file, file_path)

        return OrchestrationResult(
            file_analysis=file_analysis,
            clamav_result=clamav_res,
            yara_result=yara_res,
            adapter_results=adapter_results,
            script_findings=script_findings,
            pdf_findings=pdf_findings,
            archive_findings=archive_findings,
            office_findings=office_findings,
        )

    def _convert_clamav_result(self, res: Any) -> ScannerResult:
        """Converts ClamAVResult to ScannerResult."""
        try:
            if res.status == ClamAVStatus.MALWARE_DETECTED:
                return ScannerResult(
                    scanner_name="ClamAV Antivirus",
                    scanner_version=getattr(self.clamav, "version", "daemon"),
                    status=ScanStatus.COMPLETED,
                    findings=[
                        Finding(
                            title=f"Malware Signature Detected: {res.threat_name}",
                            description=f"ClamAV detected confirmed signature: {res.threat_name}",
                            severity=Severity.CRITICAL,
                            evidence=res.raw_response,
                            confidence="High",
                        )
                    ],
                    severity=Severity.CRITICAL,
                    confidence="High",
                    metadata={"threat_name": res.threat_name},
                )
            elif res.status == ClamAVStatus.CLEAN:
                return ScannerResult(
                    scanner_name="ClamAV Antivirus",
                    scanner_version="daemon",
                    status=ScanStatus.COMPLETED,
                    findings=[],
                    severity=Severity.CLEAN,
                    confidence="High",
                )
            elif res.status == ClamAVStatus.UNAVAILABLE:
                return ScannerResult(
                    scanner_name="ClamAV Antivirus",
                    scanner_version="daemon",
                    status=ScanStatus.UNAVAILABLE,
                    error_message=res.error_message or "ClamAV daemon offline.",
                )
            else:
                return ScannerResult(
                    scanner_name="ClamAV Antivirus",
                    scanner_version="daemon",
                    status=ScanStatus.ERROR,
                    error_message=res.error_message or "Scan failed.",
                )
        except Exception as e:
            return ScannerResult(
                scanner_name="ClamAV Antivirus",
                scanner_version="daemon",
                status=ScanStatus.ERROR,
                error_message=str(e),
            )

    def _convert_yara_result(self, res: Any) -> ScannerResult:
        """Converts YaraResult to ScannerResult."""
        try:
            if res.status == YaraStatus.MATCHED:
                findings = []
                for m in res.matches:
                    sev = Severity.HIGH
                    if m.severity == "critical":
                        sev = Severity.CRITICAL
                    elif m.severity == "medium":
                        sev = Severity.MEDIUM
                    elif m.severity == "low":
                        sev = Severity.LOW

                    findings.append(
                        Finding(
                            title=f"YARA Rule Match: {m.rule_name}",
                            description=m.description or f"Matched signature rule '{m.rule_name}'",
                            severity=sev,
                            evidence=f"Strings={', '.join(m.strings[:3])}",
                            confidence="High",
                        )
                    )

                top_sev = Severity.CRITICAL if any(f.severity == Severity.CRITICAL for f in findings) else Severity.HIGH
                return ScannerResult(
                    scanner_name="YARA Pattern Engine",
                    scanner_version="yara-python",
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    severity=top_sev,
                    confidence="High",
                    metadata={"matches_count": len(res.matches)},
                )
            elif res.status == YaraStatus.NO_MATCH:
                return ScannerResult(
                    scanner_name="YARA Pattern Engine",
                    scanner_version="yara-python",
                    status=ScanStatus.COMPLETED,
                    findings=[],
                    severity=Severity.CLEAN,
                    confidence="High",
                )
            else:
                return ScannerResult(
                    scanner_name="YARA Pattern Engine",
                    scanner_version="yara-python",
                    status=ScanStatus.UNAVAILABLE if res.status == YaraStatus.UNAVAILABLE else ScanStatus.ERROR,
                    error_message=res.error_message or "YARA scanner failed.",
                )
        except Exception as e:
            return ScannerResult(
                scanner_name="YARA Pattern Engine",
                scanner_version="yara-python",
                status=ScanStatus.ERROR,
                error_message=str(e),
            )
