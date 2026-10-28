"""CyberGuard AI - /privacy Command Handler."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized


async def privacy_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /privacy command."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)

    text = (
        f"{t('privacy_title', lang=lang)}\n\n"
        f"{t('privacy_content', lang=lang)}"
    )

    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.message.reply_text(text=text, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(text=text, parse_mode=ParseMode.MARKDOWN)
