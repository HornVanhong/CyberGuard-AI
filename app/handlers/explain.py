"""CyberGuard AI - /explain Command Handler."""

from __future__ import annotations

import json
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized
from app.services.ai_service import AIService
from app.database.repository import ScanRepository
from app.security.risk_engine import AssessmentResult, Verdict, RiskLevel
from app.utils.logger import logger


async def explain_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    ai: AIService,
    repo: ScanRepository,
) -> None:
    """Handles the /explain command to provide deep Gemini security explanations."""
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return

    user_id = user.id
    if not is_user_authorized(user_id, settings.ALLOWED_USER_IDS):
        await message.reply_text(t("unauthorized", user_id=user_id))
        return

    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)

    # 1. Determine target scan ID
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
            await message.reply_text(t("explain_no_scan", lang=lang))
            return

    thinking_msg = await message.reply_text(t("explain_thinking", lang=lang))

    # Reconstruct assessment object for structured explanation
    findings: list[str] = []
    recommendations: list[str] = []
    engines_checked: list[str] = []
    engines_unavail: list[str] = []

    try:
        summary_dict = json.loads(record.scanner_summary)
        findings = summary_dict.get("findings", [])
        recommendations = summary_dict.get("recommendations", [])
        engines_checked = summary_dict.get("engines_checked", [])
        engines_unavail = summary_dict.get("engines_unavailable", [])
    except Exception:
        pass

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
        confidence="Moderate",
        findings=findings,
        recommendations=recommendations,
        engines_checked=engines_checked,
        engines_unavailable=engines_unavail,
    )

    ai_res = await ai.generate_explanation(
        assessment=assessment,
        filename=record.filename_sanitized,
        file_type="Analyzed File",
        lang=lang,
    )

    if not ai_res.success:
        await thinking_msg.edit_text(f"⚠️ {ai_res.summary}")
        return

    # Persist explanation in DB
    try:
        repo.update_ai_explanation(record.scan_id, json.dumps(ai_res.to_dict()))
    except Exception as e:
        logger.warning("Failed to cache AI explanation in DB: %s", e)

    # Format structured response
    lines = [
        "🤖 *CYBERGUARD AI — DETAILED SECURITY ASSESSMENT*",
        f"📄 *File:* `{record.filename_sanitized}`",
        f"🚦 *Verdict:* *{record.verdict}* (Risk: {record.risk_level})",
        "",
        f"📝 *Summary:*\n{ai_res.summary}",
        "",
    ]

    if ai_res.explanation_of_indicators:
        lines.append("🔍 *Detected Indicators & Meanings:*")
        for item in ai_res.explanation_of_indicators[:5]:
            lines.append(f"• *{item.get('indicator', 'Indicator')}:* {item.get('explanation', '')}")
        lines.append("")

    if ai_res.potential_impact:
        lines.extend([
            f"⚠️ *Potential Impact:*\n{ai_res.potential_impact}",
            "",
        ])

    if ai_res.recommended_defensive_actions:
        lines.append("💡 *Actionable Next Steps:*")
        for step in ai_res.recommended_defensive_actions[:4]:
            lines.append(f"• {step}")
        lines.append("")

    if ai_res.important_uncertainties:
        lines.extend([
            f"ℹ️ *Uncertainties / Limitations:*\n{ai_res.important_uncertainties}",
            "",
        ])

    if ai_res.statement_of_scope:
        lines.extend([
            f"🛡️ *Scope of Analysis:*\n_{ai_res.statement_of_scope}_",
            "",
        ])

    lines.append(ai_res.disclaimer)
    final_text = "\n".join(lines)

    try:
        await thinking_msg.edit_text(final_text, parse_mode=ParseMode.MARKDOWN)
    except Exception:
        await thinking_msg.edit_text(final_text)
