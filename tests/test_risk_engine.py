"""Tests for the Risk Assessment & Correlation Engine."""

import pytest
from app.security.risk_engine import RiskEngine, Verdict, RiskLevel
from app.scanners.clamav_scanner import ClamAVResult, ClamAVStatus
from app.scanners.yara_scanner import YaraResult, YaraStatus, YaraMatch
from app.scanners.file_analyzer import FileTypeAnalysis, FileCategory
from app.scanners.script_analyzer import ScriptFinding, ScriptSeverity
from app.scanners.pdf_analyzer import PDFFinding, PDFSeverity
from app.services.virustotal_service import VTResult, VTStatus


def _default_file_analysis(is_mismatch=False, severity="none"):
    return FileTypeAnalysis(
        declared_extension=".pdf",
        detected_mime="application/pdf",
        detected_type_name="PDF Document",
        category=FileCategory.DOCUMENT,
        is_mismatch=is_mismatch,
        mismatch_severity=severity,
        details="Disguised file" if is_mismatch else "Match",
    )


def test_clamav_positive_detection_verdict():
    # AV detection must produce MALICIOUS verdict and CRITICAL/HIGH risk
    clamav = ClamAVResult(
        status=ClamAVStatus.MALWARE_DETECTED,
        malware_name="Win.Trojan.Agent",
    )
    yara = YaraResult(status=YaraStatus.CLEAN)

    result = RiskEngine.evaluate(
        file_analysis=_default_file_analysis(),
        clamav_result=clamav,
        yara_result=yara,
    )

    assert result.verdict == Verdict.MALICIOUS
    assert result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert result.is_av_positive is True
    assert result.av_threat_name == "Win.Trojan.Agent"
    assert any("Win.Trojan.Agent" in f for f in result.findings)


def test_heuristic_suspicious_verdict():
    # Embedded JS in PDF without confirmed AV signature
    pdf_finding = [
        PDFFinding(
            category="Embedded JavaScript",
            severity=PDFSeverity.HIGH,
            description="Embedded JS found",
            matched_element="/JS",
            confidence="High",
        )
    ]
    clamav = ClamAVResult(status=ClamAVStatus.CLEAN)
    yara = YaraResult(status=YaraStatus.CLEAN)

    result = RiskEngine.evaluate(
        file_analysis=_default_file_analysis(),
        clamav_result=clamav,
        yara_result=yara,
        pdf_findings=pdf_finding,
    )

    assert result.verdict == Verdict.SUSPICIOUS
    assert result.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    assert result.is_av_positive is False
    assert result.score > 0


def test_clean_scanners_verdict():
    # When enabled scanners report clean, verdict is NO_KNOWN_THREAT_DETECTED (never labeled "SAFE")
    clamav = ClamAVResult(status=ClamAVStatus.CLEAN)
    yara = YaraResult(status=YaraStatus.CLEAN)

    result = RiskEngine.evaluate(
        file_analysis=_default_file_analysis(),
        clamav_result=clamav,
        yara_result=yara,
    )

    assert result.verdict == Verdict.NO_KNOWN_THREAT_DETECTED
    assert result.risk_level == RiskLevel.LOW
    assert result.score == 0
    assert result.confidence in ("Moderate", "High")
    # Verify disclaimer/recommendation exists
    assert any("No known signatures" in rec for rec in result.recommendations)


def test_unavailable_scanners_verdict():
    # When primary scanners are offline/unavailable, report INCONCLUSIVE with UNKNOWN risk
    clamav = ClamAVResult(status=ClamAVStatus.UNAVAILABLE)
    yara = YaraResult(status=YaraStatus.UNAVAILABLE)

    result = RiskEngine.evaluate(
        file_analysis=_default_file_analysis(),
        clamav_result=clamav,
        yara_result=yara,
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.risk_level == RiskLevel.UNKNOWN
    assert "ClamAV" in result.engines_unavailable
    assert "YARA" in result.engines_unavailable


def test_deduplication_of_findings():
    # Multiple reports of the same category should not unfairly over-inflate score
    script_findings = [
        ScriptFinding(
            category="PowerShell Obfuscation",
            severity=ScriptSeverity.HIGH,
            description="Encoded command 1",
            matched_snippet="-enc AAA",
            confidence="High",
        ),
        ScriptFinding(
            category="PowerShell Obfuscation",
            severity=ScriptSeverity.HIGH,
            description="Encoded command 2",
            matched_snippet="-enc BBB",
            confidence="High",
        ),
    ]

    result = RiskEngine.evaluate(
        file_analysis=_default_file_analysis(),
        script_findings=script_findings,
    )

    # Deduped to 1 finding in score calculation
    assert len(result.findings) == 1
