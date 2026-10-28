"""CyberGuard AI - Telegram Security Report Generator.

Formats comprehensive, human-readable security reports adhering strictly
to the required layout, supporting bilingual outputs (English & Khmer),
and creating interactive inline keyboard action buttons.
"""

from __future__ import annotations

from typing import List, Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from app.i18n import t, get_user_lang
from app.security.risk_engine import AssessmentResult, Verdict, RiskLevel
from app.scanners.clamav_scanner import ClamAVResult, ClamAVStatus
from app.scanners.yara_scanner import YaraResult, YaraStatus
from app.scanners.file_analyzer import FileTypeAnalysis
from app.services.virustotal_service import VTResult, VTStatus


class ReportService:
    """Generates structured Telegram scan reports and interactive keyboards."""

    @classmethod
    def format_size(cls, bytes_count: int) -> str:
        """Converts bytes to human readable string (KB, MB, GB)."""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024 * 1024:
            return f"{bytes_count / 1024:.1f} KB"
        elif bytes_count < 1024 * 1024 * 1024:
            return f"{bytes_count / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"

    @classmethod
    def format_clamav_summary(cls, clamav: Optional[ClamAVResult]) -> str:
        if not clamav:
            return "Disabled"
        if clamav.status == ClamAVStatus.MALWARE_DETECTED:
            return f"🚨 THREAT FOUND ({clamav.malware_name})"
        elif clamav.status == ClamAVStatus.CLEAN:
            return "No detection"
        elif clamav.status == ClamAVStatus.UNAVAILABLE:
            return "Scanner unavailable"
        elif clamav.status == ClamAVStatus.FAILED:
            return "Scan failed"
        return "Inconclusive"

    @classmethod
    def format_yara_summary(cls, yara: Optional[YaraResult]) -> str:
        if not yara:
            return "Disabled"
        if yara.status == YaraStatus.MATCHES_FOUND:
            count = len(yara.matches)
            names = ", ".join(m.rule for m in yara.matches[:2])
            return f"⚠️ {count} match(es) ({names})"
        elif yara.status == YaraStatus.CLEAN:
            return "No detection"
        elif yara.status == YaraStatus.UNAVAILABLE:
            return "Scanner unavailable"
        return "Scan failed"

    @classmethod
    def format_vt_summary(cls, vt: Optional[VTResult]) -> str:
        if not vt or vt.status == VTStatus.DISABLED:
            return "Not checked"
        if vt.status == VTStatus.FOUND:
            if vt.positives > 0:
                return f"⚠️ Detected ({vt.positives}/{vt.total_engines} engines)"
            return f"Clean ({vt.total_engines} engines checked)"
        elif vt.status == VTStatus.NOT_FOUND:
            return "Hash not seen before on VirusTotal"
        elif vt.status == VTStatus.QUOTA_EXCEEDED:
            return "Quota exceeded"
        return "Lookup error"

    @classmethod
    def build_security_report(
        cls,
        scan_id: str,
        filename: str,
        file_size_bytes: int,
        sha256: str,
        file_analysis: FileTypeAnalysis,
        assessment: AssessmentResult,
        clamav_result: Optional[ClamAVResult] = None,
        yara_result: Optional[YaraResult] = None,
        vt_result: Optional[VTResult] = None,
        user_id: Optional[int] = None,
        lang: Optional[str] = None,
    ) -> str:
        """Formats the full markdown security report for Telegram."""
        if lang is None:
            lang = get_user_lang(user_id) if user_id else "en"

        size_str = cls.format_size(file_size_bytes)
        clamav_str = cls.format_clamav_summary(clamav_result)
        yara_str = cls.format_yara_summary(yara_result)
        vt_str = cls.format_vt_summary(vt_result)

        # Format-specific static status summary
        static_str = "Completed" if not assessment.findings else f"{len(assessment.findings)} indicator(s) identified"

        # Risk badge
        risk_emoji = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢",
            RiskLevel.UNKNOWN: "⚪",
        }.get(assessment.risk_level, "⚪")

        verdict_display = f"{risk_emoji} *{assessment.verdict.value}*"
        risk_display = f"{assessment.risk_level.value}"

        lines = [
            t("report_header", lang=lang),
            "",
            t("report_file", lang=lang, filename=filename),
            t("report_size", lang=lang, size_str=size_str),
            t("report_type", lang=lang, file_type=file_analysis.detected_type_name),
            t("report_hash", lang=lang, sha256=sha256),
            "",
            t("report_divider", lang=lang),
            t("report_results_title", lang=lang),
            "",
            t("report_clamav", lang=lang, result=clamav_str),
            t("report_yara", lang=lang, result=yara_str),
            t("report_static", lang=lang, result=static_str),
            t("report_vt", lang=lang, result=vt_str),
            "",
            t("report_divider", lang=lang),
            t("report_verdict", lang=lang, verdict=verdict_display),
            t("report_risk", lang=lang, risk_level=risk_display),
            t("report_score", lang=lang, score=assessment.score),
            "",
        ]

        # Detailed findings
        if assessment.findings:
            lines.append(t("report_findings_title", lang=lang))
            for idx, finding in enumerate(assessment.findings[:8], 1):
                lines.append(f"{idx}. {finding}")
            lines.append("")

        # Recommendations
        if assessment.recommendations:
            lines.append(t("report_recommendations_title", lang=lang))
            for rec in assessment.recommendations[:4]:
                lines.append(f"• {rec}")
            lines.append("")

        lines.extend([
            t("report_confidence", lang=lang, confidence=assessment.confidence),
            t("report_scan_id", lang=lang, scan_id=scan_id),
            "",
            t("report_disclaimer", lang=lang),
        ])

        return "\n".join(lines)

    @classmethod
    def build_report_keyboard(
        cls,
        scan_id: str,
        sha256: str,
        vt_result: Optional[VTResult] = None,
        ai_enabled: bool = False,
        vt_enabled: bool = False,
        lang: str = "en",
    ) -> InlineKeyboardMarkup:
        """Constructs interactive Telegram inline buttons."""
        buttons: List[List[InlineKeyboardButton]] = []
        row: List[InlineKeyboardButton] = []

        if ai_enabled:
            row.append(
                InlineKeyboardButton(
                    text=t("btn_ai_explain", lang=lang),
                    callback_data=f"ai_exp:{scan_id}",
                )
            )

        if vt_result and vt_result.status == VTStatus.FOUND and vt_result.permalink:
            row.append(
                InlineKeyboardButton(
                    text="🌐 VirusTotal Link",
                    url=vt_result.permalink,
                )
            )
        elif vt_enabled:
            row.append(
                InlineKeyboardButton(
                    text=t("btn_vt_lookup", lang=lang),
                    callback_data=f"vt_chk:{scan_id}",
                )
            )

        if row:
            buttons.append(row)

        # Clear data button
        buttons.append([
            InlineKeyboardButton(
                text=t("btn_delete_history", lang=lang),
                callback_data="cmd_cleardata",
            )
        ])

        return InlineKeyboardMarkup(buttons)
