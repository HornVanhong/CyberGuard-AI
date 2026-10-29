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
from app.services.ai_service import AIService
from app.services.virustotal_service import VirusTotalService
from app.database.repository import ScanRepository
from app.security.validation import is_user_authorized


BUTTON_ACTIONS = {
    # Scan file
    "🔍 ស្កេនឯកសារ": "scan",
    "🔍 scan file": "scan",
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

    # 2. Check if user was in explicit interactive 'waiting_for_ask' mode
    if context.user_data.get("waiting_for_ask"):
        context.user_data["waiting_for_ask"] = False
        await _process_ask_question(message, user_id, raw_text, ai, repo, lang)
        return

    # 3. Direct free-form conversational question to Gemini Cybersecurity AI
    if ai.enabled and ai.is_configured:
        await _process_ask_question(message, user_id, raw_text, ai, repo, lang)
    else:
        await message.reply_text(
            "សូមជ្រើសរើសមុខងារពីក្តារចុចខាងក្រោម ឬផ្ញើឯកសារដើម្បីស្កេន៖"
            if lang == "km"
            else "Please select an option from the menu below or send a file to scan:"
        )
