"""CyberGuard AI - /lang and /language Command Handler.

Enables users to dynamically switch between English (en) and Khmer (km),
and updates Telegram's official Bot Menu commands specifically for their chat.
"""

from __future__ import annotations

from typing import List
from telegram import BotCommand, BotCommandScopeChat, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import get_user_lang, set_user_lang, t
from app.keyboards import get_main_reply_keyboard
from app.security.validation import is_user_authorized
from app.utils.logger import logger


def get_bot_commands(lang: str = "en") -> List[BotCommand]:
    """Returns official bot menu commands translated for the given language."""
    if lang == "km":
        return [
            BotCommand("start", "🚀 ចាប់ផ្តើម Bot និងបើកផ្ទាំងមឺនុយមេ"),
            BotCommand("scan", "🔍 ស្កេនឯកសារស្វែងរកមេរោគ"),
            BotCommand("check", "🔗 វិភាគ Link & សារបន្លំ (Phishing/Scam)"),
            BotCommand("status", "⚙️ ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន និង AI"),
            BotCommand("ask", "💬 សួរសំណួរសន្តិសុខសាយប័រជាមួយ AI"),
            BotCommand("explain", "💡 ពន្យល់លម្អិតពីលទ្ធផលស្កេនឯកសារ"),
            BotCommand("ghidra", "🔬 វិភាគស៊ីជម្រៅ និង Decompile (Ghidra)"),
            BotCommand("report", "📊 ទាញយករបាយការណ៍ស្កេនពេញលេញ"),
            BotCommand("history", "📋 មើលប្រវត្តិឯកសារដែលបានស្កេន"),
            BotCommand("cleardata", "🗑️ លុបប្រវត្តិ និងកំណត់ត្រាទាំងអស់"),
            BotCommand("privacy", "🔐 គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព"),
            BotCommand("lang", "🌐 ផ្លាស់ប្តូរភាសា (English / ខ្មែរ)"),
            BotCommand("help", "📚 ការណែនាំ និងរបៀបប្រើប្រាស់"),
        ]
    return [
        BotCommand("start", "🚀 Start bot and show main menu"),
        BotCommand("scan", "🔍 Scan a file for malware & threats"),
        BotCommand("check", "🔗 Check suspicious links & phishing text"),
        BotCommand("status", "⚙️ Check scanner engines & AI health"),
        BotCommand("ask", "💬 Ask cybersecurity AI assistant"),
        BotCommand("explain", "💡 Explain scan findings with Gemini AI"),
        BotCommand("ghidra", "🔬 Decompile binary with NSA Ghidra SRE"),
        BotCommand("report", "📊 View or download full scan report"),
        BotCommand("history", "📋 View your recent scan history"),
        BotCommand("cleardata", "🗑️ Delete your scan history records"),
        BotCommand("privacy", "🔐 Review zero-retention privacy policy"),
        BotCommand("lang", "🌐 Switch language (English / ខ្មែរ)"),
        BotCommand("help", "📚 User guide and risk levels explained"),
    ]


async def apply_user_language(bot, user_id: int, chat_id: int, lang: str) -> None:
    """Sets user language preference and dynamically updates the chat's Telegram Bot Menu commands."""
    set_user_lang(user_id, lang)
    try:
        commands = get_bot_commands(lang)
        await bot.set_my_commands(commands=commands, scope=BotCommandScopeChat(chat_id=chat_id))
        logger.info("Updated scoped Telegram menu commands for user %d (chat %d) to %s", user_id, chat_id, lang)
    except Exception as e:
        logger.warning("Could not set scoped bot commands for chat %d: %s", chat_id, e)


async def lang_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /lang and /language command to switch language."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    chat_id = update.effective_chat.id if update.effective_chat else user.id

    # Check if user specified a language argument (e.g. /lang en, /lang km)
    if context.args:
        chosen = context.args[0].lower().strip()
        if chosen in ("en", "english"):
            await apply_user_language(context.bot, user_id=user.id, chat_id=chat_id, lang="en")
            await update.effective_message.reply_text(
                "✅ Language switched to *English 🇬🇧*.\n_Telegram menu commands have been updated to English._",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=get_main_reply_keyboard(lang="en"),
            )
            return
        elif chosen in ("km", "khmer", "ខ្មែរ"):
            await apply_user_language(context.bot, user_id=user.id, chat_id=chat_id, lang="km")
            await update.effective_message.reply_text(
                "✅ បានប្តូរភាសាទៅជា *ភាសាខ្មែរ 🇰🇭* រួចរាល់។\n_Menu ពាក្យបញ្ជាលើ Telegram ត្រូវបានប្តូរទៅជាភាសាខ្មែរដូចគ្នា។_",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=get_main_reply_keyboard(lang="km"),
            )
            return

    # If no argument or unrecognized argument, display interactive buttons
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("English 🇬🇧", callback_data="lang:en"),
            InlineKeyboardButton("ភាសាខ្មែរ 🇰🇭", callback_data="lang:km"),
        ]
    ])

    current_lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)
    curr_label = "English 🇬🇧" if current_lang == "en" else "ភាសាខ្មែរ 🇰🇭"

    msg = (
        "🌐 *Language Selection / ជ្រើសរើសភាសា*\n\n"
        f"• Current Language / ភាសាបច្ចុប្បន្ន: *{curr_label}*\n\n"
        "Please choose your preferred language below:\n"
        "សូមជ្រើសរើសភាសាដែលលោកអ្នកចង់ប្រើប្រាស់ខាងក្រោម៖"
    )

    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.message.reply_text(
            text=msg,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=keyboard,
        )
    else:
        await update.message.reply_text(
            text=msg,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=keyboard,
        )
