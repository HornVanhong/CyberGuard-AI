"""CyberGuard AI - Multi-Engine Risk Assessment & Correlation Engine.

Evaluates and correlates signals from Antivirus (ClamAV), YARA signatures,
format-specific analyzers (Scripts, PDFs, Archives, Office docs), extension
mismatch checks, and Threat Intelligence (VirusTotal).
Produces an objective Verdict, normalized Risk Level, and actionable recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from app.scanners.clamav_scanner import ClamAVResult, ClamAVStatus
from app.scanners.yara_scanner import YaraResult, YaraStatus
from app.scanners.file_analyzer import FileTypeAnalysis
from app.scanners.script_analyzer import ScriptFinding, ScriptSeverity
from app.scanners.pdf_analyzer import PDFFinding, PDFSeverity
from app.scanners.archive_analyzer import ArchiveFinding, ArchiveSeverity
from app.scanners.office_analyzer import OfficeFinding, OfficeSeverity

if TYPE_CHECKING:
    from app.services.virustotal_service import VTResult


class Verdict(str, Enum):
    """Overall security verdict."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NO_KNOWN_THREAT_DETECTED = "NO_KNOWN_THREAT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SCAN_FAILED = "SCAN_FAILED"


class RiskLevel(str, Enum):
    """Categorized threat risk level."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class AssessmentResult:
    """Consolidated risk assessment outcome."""

    verdict: Verdict
    risk_level: RiskLevel
    score: int  # 0 to 100
    confidence: str  # "High", "Moderate", "Low"
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    is_av_positive: bool = False
    av_threat_name: Optional[str] = None
    engines_checked: List[str] = field(default_factory=list)
    engines_unavailable: List[str] = field(default_factory=list)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "risk_level": self.risk_level.value,
            "score": self.score,
            "confidence": self.confidence,
            "findings_count": len(self.findings),
            "findings": self.findings[:10],
            "recommendations": self.recommendations[:5],
            "engines_checked": self.engines_checked,
            "engines_unavailable": self.engines_unavailable,
        }


class RiskEngine:
    """Correlates evidence across scanners and assigns objective risk scores."""

    # Base weights for heuristic indicators
    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 25,
        "medium": 12,
        "low": 4,
        "info": 0,
    }

    @classmethod
    def evaluate(
        cls,
        file_analysis: FileTypeAnalysis,
        clamav_result: Optional[ClamAVResult] = None,
        yara_result: Optional[YaraResult] = None,
        script_findings: Optional[List[ScriptFinding]] = None,
        pdf_findings: Optional[List[PDFFinding]] = None,
        archive_findings: Optional[List[ArchiveFinding]] = None,
        office_findings: Optional[List[OfficeFinding]] = None,
        vt_result: Optional[VTResult] = None,
    ) -> AssessmentResult:
        findings: List[str] = []
        recommendations: List[str] = []
        engines_checked: List[str] = []
        engines_unavailable: List[str] = []

        score = 0
        is_av_positive = False
        av_threat_name = None
        dedup_keys: Set[str] = set()

        # 1. Antivirus Assessment (Deterministic)
        if clamav_result:
            if clamav_result.status == ClamAVStatus.MALWARE_DETECTED:
                engines_checked.append("ClamAV")
                is_av_positive = True
                av_threat_name = clamav_result.malware_name or "Known Malware"
                findings.append(f"Antivirus detection: {av_threat_name} identified by ClamAV.")
                score += 85
            elif clamav_result.status == ClamAVStatus.CLEAN:
                engines_checked.append("ClamAV")
            elif clamav_result.status in (ClamAVStatus.UNAVAILABLE, ClamAVStatus.FAILED):
                engines_unavailable.append("ClamAV")

        # 2. File Format & Extension Mismatch
        engines_checked.append("Format Analyzer")
        if file_analysis.is_mismatch:
            findings.append(file_analysis.details)
            mismatch_weight = cls.SEVERITY_WEIGHTS.get(file_analysis.mismatch_severity, 15)
            score += mismatch_weight

        # 3. YARA Pattern Evaluation
        if yara_result:
            if yara_result.status == YaraStatus.MATCHES_FOUND:
                engines_checked.append("YARA")
                for m in yara_result.matches:
                    key = f"yara_{m.rule}"
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        sev = m.severity
                        w = cls.SEVERITY_WEIGHTS.get(sev, 20)
                        score += w
                        findings.append(f"YARA Rule [{m.rule}]: {m.description}")
            elif yara_result.status == YaraStatus.CLEAN:
                engines_checked.append("YARA")
            elif yara_result.status == YaraStatus.UNAVAILABLE:
                engines_unavailable.append("YARA")

        # 4. Script Static Analysis
        if script_findings:
            engines_checked.append("Script Analyzer")
            for sf in script_findings:
                key = f"script_{sf.category}"
                if key not in dedup_keys:
                    dedup_keys.add(key)
                    w = cls.SEVERITY_WEIGHTS.get(sf.severity.value.lower(), 15)
                    score += w
                    findings.append(f"Script Analysis ({sf.category}): {sf.description}")

        # 5. PDF Analysis
        if pdf_findings:
            engines_checked.append("PDF Analyzer")
            for pf in pdf_findings:
                key = f"pdf_{pf.category}"
                if key not in dedup_keys:
                    dedup_keys.add(key)
                    w = cls.SEVERITY_WEIGHTS.get(pf.severity.value.lower(), 12)
                    score += w
                    findings.append(f"PDF Analysis ({pf.category}): {pf.description}")

        # 6. Archive Analysis
        if archive_findings:
            engines_checked.append("Archive Analyzer")
            for af in archive_findings:
                key = f"archive_{af.category}"
                if key not in dedup_keys:
                    dedup_keys.add(key)
                    w = cls.SEVERITY_WEIGHTS.get(af.severity.value.lower(), 25)
                    score += w
                    findings.append(f"Archive Analysis ({af.category}): {af.description}")

        # 7. Office Analysis
        if office_findings:
            engines_checked.append("Office Analyzer")
            for of in office_findings:
                key = f"office_{of.category}"
                if key not in dedup_keys:
                    dedup_keys.add(key)
                    w = cls.SEVERITY_WEIGHTS.get(of.severity.value.lower(), 20)
                    score += w
                    findings.append(f"Office Document Analysis ({of.category}): {of.description}")

        # 8. VirusTotal External Threat Intelligence
        if vt_result and getattr(vt_result.status, "value", str(vt_result.status)) == "FOUND":
            engines_checked.append("VirusTotal")
            if vt_result.positives > 0:
                findings.append(
                    f"VirusTotal Intelligence: Detected by {vt_result.positives}/{vt_result.total_engines} security vendors."
                )
                if vt_result.malicious >= 3:
                    score += 60
                elif vt_result.malicious >= 1:
                    score += 35
                elif vt_result.suspicious >= 1:
                    score += 15

        # Normalize score to 0..100
        normalized_score = min(score, 100)

        # Determine Verdict and Risk Level
        if is_av_positive or (vt_result and vt_result.malicious >= 5) or normalized_score >= 70:
            verdict = Verdict.MALICIOUS
            risk_level = RiskLevel.CRITICAL if normalized_score >= 80 else RiskLevel.HIGH
        elif normalized_score >= 35:
            verdict = Verdict.SUSPICIOUS
            risk_level = RiskLevel.HIGH
        elif normalized_score >= 12:
            verdict = Verdict.SUSPICIOUS
            risk_level = RiskLevel.MEDIUM
        elif normalized_score > 0:
            verdict = Verdict.SUSPICIOUS
            risk_level = RiskLevel.LOW
        else:
            # Check if all primary engines were unavailable
            if not engines_checked or (len(engines_checked) == 1 and engines_checked[0] == "Format Analyzer" and engines_unavailable):
                verdict = Verdict.INCONCLUSIVE
                risk_level = RiskLevel.UNKNOWN
                findings.append("Primary antivirus and signature scanning engines were unavailable.")
            else:
                verdict = Verdict.NO_KNOWN_THREAT_DETECTED
                risk_level = RiskLevel.LOW

        # Confidence Calculation
        if len(engines_checked) >= 3 and not engines_unavailable:
            confidence = "High"
        elif len(engines_checked) >= 2:
            confidence = "Moderate"
        else:
            confidence = "Low"

        # Actionable Recommendations
        if verdict == Verdict.MALICIOUS:
            recommendations.append("Do NOT execute, open, or run this file.")
            recommendations.append("Delete the file permanently from your system.")
            recommendations.append("If this file was received via email or chat, report the sender.")
        elif verdict == Verdict.SUSPICIOUS:
            recommendations.append("Exercise extreme caution: suspicious patterns or macros were identified.")
            recommendations.append("Do not enable macros or bypass system security warnings.")
            recommendations.append("If opening is necessary, do so exclusively inside an isolated virtual machine.")
        elif verdict == Verdict.INCONCLUSIVE:
            recommendations.append("Scan could not be verified by all engines. Do not assume file is safe.")
            recommendations.append("Verify the source before interacting with the file.")
        else:  # NO_KNOWN_THREAT_DETECTED
            recommendations.append("No known signatures detected by enabled engines.")
            recommendations.append("Always verify the sender and maintain up-to-date endpoint protection.")
            recommendations.append("Remember: zero detections does not guarantee absolute safety.")

        return AssessmentResult(
            verdict=verdict,
            risk_level=risk_level,
            score=normalized_score,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            is_av_positive=is_av_positive,
            av_threat_name=av_threat_name,
            engines_checked=engines_checked,
            engines_unavailable=engines_unavailable,
        )
