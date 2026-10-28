"""CyberGuard AI - /start Command Handler."""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, set_user_lang, get_user_lang
from app.security.validation import is_user_authorized
from app.utils.logger import logger


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /start command."""
    user = update.effective_user
    if not user:
        return

    # Check authorization
    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    user_id = user.id
    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)
    max_mb = settings.MAX_FILE_SIZE_BYTES // (1024 * 1024)

    text = (
        f"{t('start_title', lang=lang)}\n\n"
        f"{t('start_intro', lang=lang)}\n\n"
        f"{t('start_capabilities', lang=lang)}\n\n"
        f"{t('start_limits', lang=lang, max_size_mb=max_mb)}\n\n"
        f"{t('start_privacy_notice', lang=lang)}\n\n"
        f"{t('start_prompt', lang=lang)}"
    )

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("English 🇬🇧", callback_data="lang:en"),
            InlineKeyboardButton("ភាសាខ្មែរ 🇰🇭", callback_data="lang:km"),
        ],
        [
            InlineKeyboardButton("📚 Help / Guide", callback_data="cmd:help"),
            InlineKeyboardButton("⚙️ System Status", callback_data="cmd:status"),
        ],
    ])

    await update.message.reply_text(
        text=text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=keyboard,
    )
