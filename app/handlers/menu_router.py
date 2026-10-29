"""CyberGuard AI - Text & Menu Router Handler.

Routes incoming text messages from custom ReplyKeyboardMarkup buttons
to their dedicated handlers, or directs free-form questions to Gemini AI.
"""

from __future__ import annotations

from typing import Any
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import get_user_lang, t
from app.handlers.ask import _process_ask_question
from app.handlers.help import help_handler
from app.handlers.history import history_handler
from app.handlers.language import lang_handler
from app.handlers.privacy import privacy_handler
from app.handlers.scan import scan_command_handler
from app.handlers.status import status_handler
from app.handlers.ghidra import ghidra_handler
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.yara_scanner import YaraScanner
from app.scanners.url_analyzer import UrlAnalyzer, MessageAnalysisResult
from app.services.ai_service import AIService
from app.services.virustotal_service import VirusTotalService
from app.database.repository import ScanRepository
from app.security.validation import is_user_authorized


BUTTON_ACTIONS = {
    # Scan file
    "🔍 ស្កេនឯកសារ": "scan",
    "🔍 scan file": "scan",
    # Link & Phishing Analysis
    "🔗 វិភាគ link & សារ": "link",
    "🔗 check link & text": "link",
    # Ask AI
    "💬 សួរ ai security": "ask",
    "💬 ask ai security": "ask",
    # Status
    "⚙️ ស្ថានភាពម៉ាស៊ីន": "status",
    "⚙️ system status": "status",
    # Ghidra
    "🔬 ghidra decompiler": "ghidra",
    "🔬 ghidra sre": "ghidra",
    # History
    "📋 ប្រវត្តិស្កេន": "history",
    "📋 scan history": "history",
    # Language
    "🌐 ផ្លាស់ប្តូរភាសា": "lang",
    "🌐 switch language": "lang",
    # Privacy
    "🔐 គោលការណ៍ឯកជនភាព": "privacy",
    "🔐 privacy policy": "privacy",
    # Help
    "📚 ការណែនាំ & ជំនួយ": "help",
    "📚 help & guide": "help",
}


async def text_message_router(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    clamav: ClamAVScanner,
    yara: YaraScanner,
    vt: VirusTotalService,
    ai: AIService,
    repo: ScanRepository,
) -> None:
    """Routes incoming text messages from custom reply keyboards or free-form chat."""
    message = update.effective_message
    user = update.effective_user
    if not message or not user or not message.text:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await message.reply_text(t("unauthorized", user_id=user.id))
        return

    user_id = user.id
    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)
    raw_text = message.text.strip()
    normalized_text = raw_text.lower()

    # 1. Check if the message matches a reply keyboard button
    action = BUTTON_ACTIONS.get(normalized_text)

    if action == "scan":
        await scan_command_handler(update, context)
        return
    elif action == "link":
        context.user_data["waiting_for_link"] = True
        prompt = (
            "🔗 *CyberGuard AI — វិភាគ Link & សារបន្លំ (Phishing/Scam)*\n\n"
            "សូមផ្ញើ ឬ Forward តំណភ្ជាប់ (Link/URL) ឬសារដែលគួរឱ្យសង្ស័យមកកាន់ទីនេះ៖\n\n"
            "• កំណត់សម្គាល់ Bare IP, Shorteners (bit.ly, tinyurl), High-Risk TLDs\n"
            "• ស្វែងរកការក្លែងបន្លំម៉ាកសញ្ញា (ABA, ACLEDA, Telegram, Binance, Google)\n"
            "• វិភាគល្បិច Social Engineering (គំរាមបិទគណនី, ឈ្នះរង្វាន់, លួច OTP)\n"
            "• ត្រួតពិនិត្យ Threat Intel (VirusTotal) & Gemini AI\n\n"
            "_អ្នកអាច Paste Link ឬ Forward សារមកទីនេះដោយផ្ទាល់បានភ្លាមៗ!_"
            if lang == "km"
            else "🔗 *CyberGuard AI — Link & Phishing Analyzer*\n\n"
            "Please send or forward any suspicious link or message to this chat:\n\n"
            "• Detects URL shorteners, bare IP hosts, and high-risk TLDs\n"
            "• Brand impersonation checks (Banks, Telegram, Google, Binance)\n"
            "• Social engineering heuristics (Urgency, fake prizes, OTP harvesting)\n"
            "• VirusTotal Threat Intel & Gemini AI analysis\n\n"
            "_You can paste a URL or forward a message directly!_"
        )
        await message.reply_text(prompt, parse_mode=ParseMode.MARKDOWN)
        return
    elif action == "ask":
        context.user_data["waiting_for_ask"] = True
        prompt = (
            "💬 *CyberGuard AI Security Assistant*\n\n"
            "សូមសួរសំណួរពាក់ព័ន្ធនឹងសុវត្ថិភាពសាយប័រ ឬលទ្ធផលស្កេនចុងក្រោយរបស់អ្នក៖\n\n"
            "_វាយ `/cancel` ប្រសិនបើអ្នកចង់បោះបង់។_"
            if lang == "km"
            else "💬 *CyberGuard AI Security Assistant*\n\n"
            "Type your cybersecurity question below (or ask about your recent scan):\n\n"
            "_Type `/cancel` to exit._"
        )
        await message.reply_text(prompt, parse_mode=ParseMode.MARKDOWN)
        return
    elif action == "status":
        await status_handler(update, context, clamav=clamav, yara=yara, vt=vt, ai=ai, repo=repo)
        return
    elif action == "ghidra":
        await ghidra_handler(update, context, repo=repo)
        return
    elif action == "history":
        await history_handler(update, context, repo=repo)
        return
    elif action == "lang":
        await lang_handler(update, context)
        return
    elif action == "privacy":
        await privacy_handler(update, context)
        return
    elif action == "help":
        await help_handler(update, context)
        return

    # 2. Check if user is in 'waiting_for_link' mode or if text contains URLs
    detected_urls = UrlAnalyzer.extract_urls(raw_text)
    if context.user_data.get("waiting_for_link") or len(detected_urls) > 0:
        context.user_data["waiting_for_link"] = False
        await _process_link_analysis(message, user_id, raw_text, vt, ai, lang)
        return

    # 3. Check if user was in explicit interactive 'waiting_for_ask' mode
    if context.user_data.get("waiting_for_ask"):
        context.user_data["waiting_for_ask"] = False
        await _process_ask_question(message, user_id, raw_text, ai, repo, lang)
        return

    # 4. Direct free-form conversational question to Gemini Cybersecurity AI
    if ai.enabled and ai.is_configured:
        await _process_ask_question(message, user_id, raw_text, ai, repo, lang)
    else:
        await message.reply_text(
            "សូមជ្រើសរើសមុខងារពីក្តារចុចខាងក្រោម ឬផ្ញើឯកសារដើម្បីស្កេន៖"
            if lang == "km"
            else "Please select an option from the menu below or send a file to scan:"
        )


async def _process_link_analysis(
    message: Any,
    user_id: int,
    raw_text: str,
    vt: VirusTotalService,
    ai: AIService,
    lang: str,
) -> None:
    """Analyzes a URL or phishing message, queries VT & Gemini, and delivers report."""
    loading_text = (
        "🔄 *កំពុងវិភាគសុវត្ថិភាព Link និងទម្រង់សារ (Zero-Trust Phishing Inspection)...*\n_សូមរង់ចាំបន្តិច..._"
        if lang == "km"
        else "🔄 *Analyzing URL and message safety (Zero-Trust Phishing Inspection)...*\n_Please wait a moment..._"
    )
    progress_msg = await message.reply_text(loading_text, parse_mode=ParseMode.MARKDOWN)

    try:
        analyzer = UrlAnalyzer(vt_service=vt)
        analysis = await analyzer.analyze_message(raw_text)

        # Gemini AI Explanation
        ai_explanation = ""
        if ai.enabled and ai.is_configured:
            prompt = (
                f"[Phishing & Malicious Link Context]\n"
                f"Target Message/URL: {raw_text[:800]}\n"
                f"Extracted URLs: {', '.join(analysis.urls_found) if analysis.urls_found else 'None'}\n"
                f"Verdict: {analysis.verdict}\n"
                f"Risk Score: {analysis.risk_score}/100\n"
                f"Red Flags: {'; '.join(analysis.red_flags) if analysis.red_flags else 'None'}\n"
                f"Tactics: {'; '.join(analysis.social_engineering_tactics) if analysis.social_engineering_tactics else 'None'}\n\n"
                f"Provide a concise cybersecurity assessment in {'Khmer' if lang == 'km' else 'English'}."
            )
            ai_explanation = await ai.ask_gemini(prompt, lang=lang)

        verdict_emoji = "🔴" if analysis.verdict == "MALICIOUS" else ("🟡" if analysis.verdict == "SUSPICIOUS" else "🟢")
        verdict_str = (
            "MALICIOUS (គ្រោះថ្នាក់ខ្លាំង)" if analysis.verdict == "MALICIOUS"
            else ("SUSPICIOUS (គួរឱ្យសង្ស័យ)" if analysis.verdict == "SUSPICIOUS" else "LIKELY SAFE (ទំនងជាសុវត្ថិភាព)")
        ) if lang == "km" else analysis.verdict

        target_label = analysis.urls_found[0] if analysis.urls_found else (raw_text[:50] + "..." if len(raw_text) > 50 else raw_text)

        flags_text = ""
        if analysis.red_flags:
            flags_header = "\n\n⚠️ *សញ្ញាសម្គាល់ហានិភ័យ (Red Flags):*\n" if lang == "km" else "\n\n⚠️ *Threat Indicators (Red Flags):*\n"
            flags_text = flags_header + "\n".join(f"• {f}" for f in analysis.red_flags)

        tactics_text = ""
        if analysis.social_engineering_tactics:
            tactics_header = "\n\n🎭 *វិធីសាស្ត្រល្បួងបន្លំ (Social Engineering):*\n" if lang == "km" else "\n\n🎭 *Social Engineering Tactics:*\n"
            tactics_text = tactics_header + "\n".join(f"• {t}" for t in analysis.social_engineering_tactics)

        ai_section = ""
        if ai_explanation:
            ai_header = "\n\n🤖 *ការវិភាគពី Gemini AI:*\n" if lang == "km" else "\n\n🤖 *Gemini AI Assessment:*\n"
            ai_section = ai_header + ai_explanation

        recs_text = ""
        if analysis.recommendations:
            recs_header = "\n\n💡 *ការណែនាំសុវត្ថិភាព:*\n" if lang == "km" else "\n\n💡 *Security Recommendations:*\n"
            recs_text = recs_header + "\n".join(f"• {r}" for r in analysis.recommendations)

        header = "🔗 *CyberGuard AI — របាយការណ៍វិភាគ Link & សារ*" if lang == "km" else "🔗 *CyberGuard AI — Link & Phishing Analysis Report*"
        report = (
            f"{header}\n\n"
            f"🎯 *គោលដៅវិភាគ:* `{target_label}`\n"
            f"📊 *ការវាយតម្លៃ:* {verdict_emoji} *{verdict_str}*\n"
            f"📈 *ពិន្ទុហានិភ័យ:* {analysis.risk_score}/100"
            f"{tactics_text}{flags_text}{ai_section}{recs_text}"
        )

        await progress_msg.edit_text(report, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        err_msg = f"⚠️ ការវិភាគជួបបញ្ហា: {e}" if lang == "km" else f"⚠️ Analysis failed: {e}"
        await progress_msg.edit_text(err_msg)
