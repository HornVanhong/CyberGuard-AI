"""Tests for Telegram report formatting and localization."""

import pytest
from app.services.report_service import ReportService
from app.security.risk_engine import AssessmentResult, Verdict, RiskLevel
from app.scanners.file_analyzer import FileTypeAnalysis, FileCategory
from app.scanners.clamav_scanner import ClamAVResult, ClamAVStatus
from app.scanners.yara_scanner import YaraResult, YaraStatus
from app.services.virustotal_service import VTResult, VTStatus


def test_format_size():
    assert ReportService.format_size(500) == "500 B"
    assert ReportService.format_size(2048) == "2.0 KB"
    assert ReportService.format_size(5 * 1024 * 1024) == "5.0 MB"


def test_build_security_report_english():
    file_analysis = FileTypeAnalysis(
        declared_extension=".pdf",
        detected_mime="application/pdf",
        detected_type_name="PDF Document",
        category=FileCategory.DOCUMENT,
        is_mismatch=False,
        mismatch_severity="none",
        details="Match",
    )
    assessment = AssessmentResult(
        verdict=Verdict.SUSPICIOUS,
        risk_level=RiskLevel.MEDIUM,
        score=45,
        confidence="Moderate",
        findings=["Embedded JavaScript detected."],
        recommendations=["Do not open in standard viewer."],
    )
    clamav = ClamAVResult(status=ClamAVStatus.CLEAN)
    yara = YaraResult(status=YaraStatus.CLEAN)

    report = ReportService.build_security_report(
        scan_id="scan-abc-123",
        filename="invoice.pdf",
        file_size_bytes=1048576,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_analysis=file_analysis,
        assessment=assessment,
        clamav_result=clamav,
        yara_result=yara,
        lang="en",
    )

    assert "CYBERGUARD AI — SECURITY REPORT" in report
    assert "invoice.pdf" in report
    assert "SUSPICIOUS" in report
    assert "MEDIUM" in report
    assert "No detection does not guarantee that a file is safe" in report
    assert "scan-abc-123" in report


def test_build_security_report_khmer():
    file_analysis = FileTypeAnalysis(
        declared_extension=".pdf",
        detected_mime="application/pdf",
        detected_type_name="PDF Document",
        category=FileCategory.DOCUMENT,
        is_mismatch=False,
        mismatch_severity="none",
        details="Match",
    )
    assessment = AssessmentResult(
        verdict=Verdict.MALICIOUS,
        risk_level=RiskLevel.CRITICAL,
        score=95,
        confidence="High",
        findings=["រកឃើញកូដគ្រោះថ្នាក់"],
        recommendations=["សូមលុបឯកសារនេះចោល"],
    )

    report = ReportService.build_security_report(
        scan_id="scan-km-1",
        filename="payload.exe",
        file_size_bytes=2048,
        sha256="aa" * 32,
        file_analysis=file_analysis,
        assessment=assessment,
        lang="km",
    )

    assert "CYBERGUARD AI — របាយការណ៍សុវត្ថិភាព" in report
    assert "payload.exe" in report
    assert "CRITICAL" in report


def test_build_report_keyboard():
    kb = ReportService.build_report_keyboard(
        scan_id="scan-xyz",
        sha256="11" * 32,
        ai_enabled=True,
        vt_enabled=True,
        lang="en",
    )
    # Verify buttons are present
    button_texts = [btn.text for row in kb.inline_keyboard for btn in row]
    assert any("AI" in t for t in button_texts)
    assert any("VirusTotal" in t for t in button_texts)
    assert any("History" in t for t in button_texts)
