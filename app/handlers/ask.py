"""CyberGuard AI - /ask & /cancel Cybersecurity Assistant Handlers."""

from __future__ import annotations

from typing import Optional

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized
from app.services.ai_service import AIService
from app.database.repository import ScanRepository
from app.utils.logger import logger


async def ask_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    ai: AIService,
    repo: ScanRepository,
) -> None:
    """Handles /ask command to answer cybersecurity inquiries with latest scan context."""
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return

    user_id = user.id
    if not is_user_authorized(user_id, settings.ALLOWED_USER_IDS):
        await message.reply_text(t("unauthorized", user_id=user_id))
        return

    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)

    # Extract query if passed as arguments: /ask <query>
    query_text = ""
    if context.args:
        query_text = " ".join(context.args).strip()

    if not query_text:
        # Check if query came from callback query
        if update.callback_query:
            await update.callback_query.answer()
            context.user_data["waiting_for_ask"] = True
            await update.callback_query.message.reply_text(
                f"{t('ask_prompt', lang=lang)}\n\n_Type `/cancel` to exit._",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        # Prompt user to provide a question
        context.user_data["waiting_for_ask"] = True
        await message.reply_text(
            f"{t('ask_prompt', lang=lang)}\n\n_Type `/cancel` to exit._",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Process question
    await _process_ask_question(message, user_id, query_text, ai, repo, lang)


async def ask_text_message_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    ai: AIService,
    repo: ScanRepository,
) -> None:
    """Catches text messages when user is in the interactive 'waiting_for_ask' state."""
    message = update.effective_message
    user = update.effective_user
    if not message or not user or not message.text:
        return

    if not context.user_data.get("waiting_for_ask"):
        return  # Not in ask mode

    context.user_data["waiting_for_ask"] = False
    user_id = user.id
    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)
    query_text = message.text.strip()

    await _process_ask_question(message, user_id, query_text, ai, repo, lang)


async def _process_ask_question(
    message: Any,
    user_id: int,
    query_text: str,
    ai: AIService,
    repo: ScanRepository,
    lang: str,
) -> None:
    """Helper to query Gemini and deliver cybersecurity response."""
    thinking_msg = await message.reply_text(t("ask_thinking", lang=lang))

    latest_scan = repo.get_latest_user_scan(user_id=user_id)
    answer = await ai.answer_security_question(
        question=query_text,
        latest_scan=latest_scan,
        lang=lang,
    )

    try:
        await thinking_msg.edit_text(
            f"🤖 *CyberGuard AI Security Advice*\n\n{answer}",
            parse_mode=ParseMode.MARKDOWN,
        )
    except Exception:
        # Fallback if markdown parsing fails
        await thinking_msg.edit_text(f"🤖 CyberGuard AI Security Advice\n\n{answer}")


async def cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Cancels any pending interactive operation."""
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return

    user_id = user.id
    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)
    context.user_data["waiting_for_ask"] = False

    await message.reply_text(t("ask_cancelled", lang=lang))
