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
from app.handlers.history import history_handler, cleardata_handler
from app.handlers.privacy import privacy_handler
from app.handlers.scan import scan_command_handler
from app.handlers.report import download_report_callback
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
    if data == "cmd:scan":
        await query.answer()
        await scan_command_handler(update, context)
        return
    elif data == "cmd:ask":
        await query.answer()
        lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)
        context.user_data["waiting_for_ask"] = True
        await query.message.reply_text(
            f"{t('ask_prompt', lang=lang)}\n\n_Type `/cancel` to exit._",
            parse_mode=ParseMode.MARKDOWN,
        )
        return
    elif data == "cmd:history":
        await query.answer()
        await history_handler(update, context, repo=repo)
        return
    elif data == "cmd:help":
        await query.answer()
        await help_handler(update, context)
        return
    elif data == "cmd:status":
        await query.answer()
        await status_handler(update, context, clamav=clamav, yara=yara, vt=vt, ai=ai, repo=repo)
        return
    elif data == "cmd:privacy":
        await query.answer()
        await privacy_handler(update, context)
        return
    elif data == "cmd_cleardata":
        await query.answer()
        await cleardata_handler(update, context, repo=repo)
        return
    elif data.startswith("dl_rep:"):
        await download_report_callback(update, context, repo=repo)
        return
    elif data.startswith("ghidra:"):
        scan_id = data.split(":", 1)[1]
        context.args = [scan_id]
        from app.handlers.ghidra import ghidra_handler
        await ghidra_handler(update, context, repo=repo)
        return

    # 3. AI Explanation request
    if data.startswith("ai_exp:"):
        scan_id = data.split(":", 1)[1]
        await query.answer("🤖 Consulting Gemini AI Analyst...")

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
            engines_checked = summary_dict.get("engines_checked", [])
            engines_unavail = summary_dict.get("engines_unavailable", [])
        except Exception:
            findings = []
            recommendations = []
            engines_checked = []
            engines_unavail = []

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

        fake_assessment = AssessmentResult(
            verdict=verdict_enum,
            risk_level=risk_enum,
            score=record.score,
            confidence="High",
            findings=findings,
            recommendations=recommendations,
            engines_checked=engines_checked,
            engines_unavailable=engines_unavail,
        )

        ai_res = await ai.generate_explanation(
            assessment=fake_assessment,
            filename=record.filename_sanitized,
            file_type="Analyzed Payload",
            lang=lang,
        )

        if ai_res.success:
            # Cache in DB
            try:
                repo.update_ai_explanation(record.scan_id, json.dumps(ai_res.to_dict()))
            except Exception:
                pass

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
                for s in ai_res.recommended_defensive_actions[:3]:
                    lines.append(f"• {s}")
                lines.append("")

            if ai_res.statement_of_scope:
                lines.extend([
                    f"🛡️ *Analysis Scope:*\n_{ai_res.statement_of_scope}_",
                    "",
                ])

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
