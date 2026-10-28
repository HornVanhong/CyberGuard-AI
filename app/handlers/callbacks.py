"""CyberGuard AI - Interactive Callback Query Handlers.

Handles Telegram button interactions including:
- AI Security Explanations on demand
- On-demand VirusTotal hash lookups
- Language preference toggling (English / Khmer)
- User data history erasure
"""

from __future__ import annotations

import json
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.database.repository import ScanRepository
from app.i18n import set_user_lang, get_user_lang, t
from app.services.ai_service import AIService
from app.services.virustotal_service import VirusTotalService
from app.security.risk_engine import AssessmentResult, Verdict, RiskLevel
from app.handlers.help import help_handler
from app.handlers.status import status_handler
from app.handlers.history import cleardata_handler
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.yara_scanner import YaraScanner
from app.utils.logger import logger


async def callback_router(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    ai: AIService,
    vt: VirusTotalService,
    repo: ScanRepository,
    clamav: ClamAVScanner,
    yara: YaraScanner,
) -> None:
    """Routes inline button callback queries."""
    query = update.callback_query
    if not query or not query.data:
        return

    data = query.data
    user = query.from_user
    user_id = user.id

    # 1. Language switcher
    if data.startswith("lang:"):
        selected_lang = data.split(":", 1)[1]
        set_user_lang(user_id, selected_lang)
        await query.answer("Language updated / បានផ្លាស់ប្តូរភាសា!")
        lang_name = "English 🇬🇧" if selected_lang == "en" else "ភាសាខ្មែរ 🇰🇭"
        await query.message.reply_text(f"✅ Language set to *{lang_name}*.", parse_mode=ParseMode.MARKDOWN)
        return

    # 2. Command triggers
    if data == "cmd:help":
        await help_handler(update, context)
        return
    elif data == "cmd:status":
        await status_handler(update, context, clamav=clamav, yara=yara, vt=vt, ai=ai, repo=repo)
        return
    elif data == "cmd_cleardata":
        await cleardata_handler(update, context, repo=repo)
        return

    # 3. AI Explanation request
    if data.startswith("ai_exp:"):
        scan_id = data.split(":", 1)[1]
        await query.answer("🤖 Consulting CyberGuard AI Analyst...")

        record = repo.get_scan(scan_id=scan_id, user_id=user_id)
        if not record:
            await query.message.reply_text("⚠️ Scan record not found or access expired.")
            return

        lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)

        # Reconstruct light assessment result for AI prompt
        try:
            summary_dict = json.loads(record.scanner_summary)
            findings = summary_dict.get("findings", [])
            recommendations = summary_dict.get("recommendations", [])
        except Exception:
            findings = []
            recommendations = []

        fake_assessment = AssessmentResult(
            verdict=Verdict(record.verdict),
            risk_level=RiskLevel(record.risk_level),
            score=record.score,
            confidence="High",
            findings=findings,
            recommendations=recommendations,
        )

        ai_res = await ai.generate_explanation(
            assessment=fake_assessment,
            filename=record.filename_sanitized,
            file_type="Analyzed Payload",
            lang=lang,
        )

        if ai_res.success:
            lines = [
                "🤖 *CYBERGUARD AI — EXPLANATION*",
                f"📄 *File:* `{record.filename_sanitized}`",
                "",
                f"📝 *Summary:*\n{ai_res.summary}",
                "",
            ]
            if ai_res.risk_explanation:
                lines.extend([
                    f"⚠️ *Why this matters:*\n{ai_res.risk_explanation}",
                    "",
                ])
            if ai_res.actionable_steps:
                lines.append("💡 *Recommended Actions:*")
                for s in ai_res.actionable_steps[:3]:
                    lines.append(f"• {s}")
                lines.append("")

            lines.append(ai_res.disclaimer)
            await query.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
        else:
            await query.message.reply_text(
                f"⚠️ Could not generate AI explanation: {ai_res.summary}"
            )
        return

    # 4. On-demand VirusTotal lookup
    if data.startswith("vt_chk:"):
        scan_id = data.split(":", 1)[1]
        await query.answer("🌐 Querying VirusTotal Intelligence...")

        record = repo.get_scan(scan_id=scan_id, user_id=user_id)
        if not record:
            await query.message.reply_text("⚠️ Scan record not found.")
            return

        vt_res = await vt.lookup_hash(record.sha256)
        if vt_res.status.value == "FOUND":
            reply = (
                f"🌐 *VirusTotal Intelligence Report*\n"
                f"🔐 SHA-256: `{record.sha256}`\n"
                f"• Positives: *{vt_res.positives} / {vt_res.total_engines}* vendors\n"
                f"• Malicious: {vt_res.malicious}\n"
                f"• Suspicious: {vt_res.suspicious}\n"
                f"• Undetected: {vt_res.undetected}\n\n"
                f"🔗 [View Detailed Analysis on VirusTotal]({vt_res.permalink})"
            )
        elif vt_res.status.value == "NOT_FOUND":
            reply = (
                f"🌐 *VirusTotal Intelligence Report*\n"
                f"🔐 SHA-256: `{record.sha256}`\n\n"
                f"ℹ️ Hash not seen before on VirusTotal dataset.\n"
                f"*(Note: New or custom malware often has no existing VirusTotal record)*"
            )
        else:
            reply = f"⚠️ VirusTotal lookup failed: {vt_res.error_message}"

        await query.message.reply_text(reply, parse_mode=ParseMode.MARKDOWN)
