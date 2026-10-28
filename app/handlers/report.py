"""CyberGuard AI - /report Command Handler & Downloadable Export."""

from __future__ import annotations

import io
import json
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized
from app.database.repository import ScanRepository
from app.services.report_service import ReportService
from app.scanners.file_analyzer import FileTypeAnalysis, FileCategory
from app.security.risk_engine import AssessmentResult, Verdict, RiskLevel
from app.utils.logger import logger


async def report_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    repo: ScanRepository,
) -> None:
    """Handles the /report command, displaying or exporting scan reports."""
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return

    user_id = user.id
    if not is_user_authorized(user_id, settings.ALLOWED_USER_IDS):
        await message.reply_text(t("unauthorized", user_id=user_id))
        return

    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)

    # Determine scan ID
    target_scan_id = ""
    if context.args:
        target_scan_id = context.args[0].strip()

    if target_scan_id:
        record = repo.get_scan(scan_id=target_scan_id, user_id=user_id)
        if not record:
            await message.reply_text(t("report_not_found", lang=lang, scan_id=target_scan_id))
            return
    else:
        record = repo.get_latest_user_scan(user_id=user_id)
        if not record:
            await message.reply_text(t("report_no_scan", lang=lang))
            return

    # Parse findings from summary
    findings: list[str] = []
    recommendations: list[str] = []
    try:
        summary_dict = json.loads(record.scanner_summary)
        findings = summary_dict.get("findings", [])
        recommendations = summary_dict.get("recommendations", [])
    except Exception:
        pass

    file_analysis = FileTypeAnalysis(
        declared_extension="",
        detected_mime="application/octet-stream",
        detected_type_name="Stored Audit Record",
        category=FileCategory.UNKNOWN,
        is_mismatch=False,
        mismatch_severity="none",
        details="Retrieved from audit record",
    )

    # Resilient verdict and risk level conversion
    verdict_str = record.verdict
    if verdict_str == "CLEAN":
        verdict_enum = Verdict.NO_KNOWN_THREAT_DETECTED
    else:
        try:
            verdict_enum = Verdict(verdict_str)
        except ValueError:
            verdict_enum = Verdict.INCONCLUSIVE

    try:
        risk_enum = RiskLevel(record.risk_level)
    except ValueError:
        risk_enum = RiskLevel.UNKNOWN

    assessment = AssessmentResult(
        verdict=verdict_enum,
        risk_level=risk_enum,
        score=record.score,
        confidence="High",
        findings=findings,
        recommendations=recommendations,
    )

    report_text = ReportService.build_security_report(
        scan_id=record.scan_id,
        filename=record.filename_sanitized,
        file_size_bytes=record.file_size,
        sha256=record.sha256,
        file_analysis=file_analysis,
        assessment=assessment,
        lang=lang,
    )

    # Keyboard offering AI explain and text download
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(t("btn_ai_explain", lang=lang), callback_data=f"ai_exp:{record.scan_id}"),
            InlineKeyboardButton(t("btn_download_report", lang=lang), callback_data=f"dl_rep:{record.scan_id}"),
        ]
    ])

    await message.reply_text(report_text, parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard)


async def download_report_callback(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    repo: ScanRepository,
) -> None:
    """Exports a clean plain-text security audit report for download."""
    query = update.callback_query
    if not query or not query.data:
        return

    user_id = query.from_user.id
    scan_id = query.data.split(":", 1)[1]

    record = repo.get_scan(scan_id=scan_id, user_id=user_id)
    if not record:
        await query.answer("Record not found.")
        return

    await query.answer("Generating report download...")

    # Build plain-text report document
    lines = [
        "===========================================================",
        "           CYBERGUARD AI - SECURITY AUDIT REPORT           ",
        "===========================================================",
        f"Scan ID:        {record.scan_id}",
        f"File Name:      {record.filename_sanitized}",
        f"File Size:      {record.file_size} bytes",
        f"SHA-256 Hash:   {record.sha256}",
        f"Scan Timestamp: {record.created_at}",
        f"Final Verdict:  {record.verdict}",
        f"Risk Level:     {record.risk_level}",
        f"Threat Score:   {record.score} / 100",
        "-----------------------------------------------------------",
        "FINDINGS:",
    ]

    try:
        summary_dict = json.loads(record.scanner_summary)
        for idx, f in enumerate(summary_dict.get("findings", []), 1):
            lines.append(f"  {idx}. {f}")
        lines.append("-----------------------------------------------------------")
        lines.append("RECOMMENDATIONS:")
        for r in summary_dict.get("recommendations", []):
            lines.append(f"  - {r}")
    except Exception:
        pass

    if record.ai_explanation:
        try:
            ai_data = json.loads(record.ai_explanation)
            lines.append("-----------------------------------------------------------")
            lines.append("GEMINI AI ANALYSIS SUMMARY:")
            lines.append(f"  {ai_data.get('summary', '')}")
            if ai_data.get("potential_impact"):
                lines.append(f"  Potential Impact: {ai_data.get('potential_impact')}")
        except Exception:
            pass

    lines.extend([
        "===========================================================",
        "DISCLAIMER: No automated scanner guarantees 100% safety.",
        "Generated by CyberGuard AI Security Pipeline.",
        "===========================================================",
    ])

    report_content = "\n".join(lines).encode("utf-8")
    bio = io.BytesIO(report_content)
    bio.name = f"cyberguard_report_{record.scan_id[:8]}.txt"

    await query.message.reply_document(
        document=bio,
        caption=f"📄 Downloadable security report for `{record.filename_sanitized}`",
        parse_mode=ParseMode.MARKDOWN,
    )
