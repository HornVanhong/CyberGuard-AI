"""CyberGuard AI - /lang and /language Command Handler.

Enables users to dynamically switch between English (en) and Khmer (km).
"""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import get_user_lang, set_user_lang, t
from app.security.validation import is_user_authorized


async def lang_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles /lang and /language command to switch language."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    # Check if user specified a language argument (e.g. /lang en, /lang km)
    if context.args:
        chosen = context.args[0].lower().strip()
        if chosen in ("en", "english"):
            set_user_lang(user.id, "en")
            await update.effective_message.reply_text(
                "✅ Language switched to *English 🇬🇧*.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return
        elif chosen in ("km", "khmer", "ខ្មែរ"):
            set_user_lang(user.id, "km")
            await update.effective_message.reply_text(
                "✅ បានប្តូរភាសាទៅជា *ភាសាខ្មែរ 🇰🇭* រួចរាល់។",
                parse_mode=ParseMode.MARKDOWN,
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
