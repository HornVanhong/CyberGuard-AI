"""Tests for Telegram bot command handlers."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from telegram import Update, User, Message, Chat

from app.database.repository import ScanRepository
from app.database.models import ScanRecord
from app.handlers.start import start_handler
from app.handlers.help import help_handler
from app.handlers.privacy import privacy_handler
from app.handlers.history import history_handler, cleardata_handler


def _create_mock_update(user_id=123, username="tester"):
    user = User(id=user_id, is_bot=False, first_name="Test", username=username)
    chat = Chat(id=user_id, type="private")
    message = MagicMock(spec=Message)
    message.reply_text = AsyncMock()
    message.from_user = user
    message.chat = chat

    update = MagicMock(spec=Update)
    update.effective_user = user
    update.effective_message = message
    update.message = message
    update.callback_query = None
    return update, user, message


@pytest.mark.asyncio
async def test_start_handler():
    update, user, message = _create_mock_update()
    context = MagicMock()

    await start_handler(update, context)
    assert message.reply_text.called
    args, kwargs = message.reply_text.call_args
    assert "CyberGuard AI" in kwargs.get("text", "")


@pytest.mark.asyncio
async def test_help_handler():
    update, user, message = _create_mock_update()
    context = MagicMock()

    await help_handler(update, context)
    assert message.reply_text.called
    args, kwargs = message.reply_text.call_args
    assert "Help & Guide" in kwargs.get("text", "")


@pytest.mark.asyncio
async def test_privacy_handler():
    update, user, message = _create_mock_update()
    context = MagicMock()

    await privacy_handler(update, context)
    assert message.reply_text.called
    args, kwargs = message.reply_text.call_args
    assert "Privacy & Security Policy" in kwargs.get("text", "")


@pytest.mark.asyncio
async def test_history_and_clear_handlers(test_db_path):
    repo = ScanRepository(db_path=test_db_path)
    update, user, message = _create_mock_update(user_id=888)
    context = MagicMock()

    # Empty history initially
    await history_handler(update, context, repo=repo)
    assert "no scan history" in message.reply_text.call_args[1]["text"].lower()

    # Add a scan record
    repo.save_scan(
        ScanRecord.create(
            scan_id="hist-1",
            user_id=888,
            filename_sanitized="file.exe",
            file_size=100,
            sha256="aa"*32,
            verdict="CLEAN",
            risk_level="LOW",
        )
    )

    # History shows record
    await history_handler(update, context, repo=repo)
    assert "file.exe" in message.reply_text.call_args[1]["text"]

    # Clear data
    await cleardata_handler(update, context, repo=repo)
    assert "erased" in message.reply_text.call_args[1]["text"].lower()

    # History is now empty again
    await history_handler(update, context, repo=repo)
    assert "no scan history" in message.reply_text.call_args[1]["text"].lower()
