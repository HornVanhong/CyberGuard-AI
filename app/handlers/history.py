"""CyberGuard AI - /history & /cleardata Command Handlers."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized
from app.database.repository import ScanRepository


async def history_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    repo: ScanRepository,
) -> None:
    """Handles the /history command, showing recent scans isolated to the requesting user."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)
    records = repo.get_user_history(user_id=user.id, limit=5)

    if not records:
        text = t("history_empty", lang=lang)
    else:
        lines = [t("history_title", lang=lang), ""]
        for idx, rec in enumerate(records, 1):
            date_short = rec.created_at[:16].replace("T", " ")
            lines.append(
                f"{idx}. `{rec.filename_sanitized}`\n"
                f"   • Verdict: *{rec.verdict}* (Risk: {rec.risk_level})\n"
                f"   • SHA-256: `{rec.sha256[:16]}...`\n"
                f"   • Date: {date_short} UTC\n"
                f"   • Scan ID: `{rec.scan_id[:8]}...`"
            )
        lines.append("\n💡 Use `/cleardata` to erase your entire scan history.")
        text = "\n".join(lines)

    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.message.reply_text(text=text, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(text=text, parse_mode=ParseMode.MARKDOWN)


async def cleardata_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    repo: ScanRepository,
) -> None:
    """Handles the /cleardata command, completely removing the user's scan audit records."""
    user = update.effective_user
    if not user:
        return

    lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)
    deleted_count = repo.delete_user_history(user_id=user.id)

    text = f"{t('history_cleared', lang=lang)} ({deleted_count} records removed)"

    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.message.reply_text(text=text)
    else:
        await update.message.reply_text(text=text)
