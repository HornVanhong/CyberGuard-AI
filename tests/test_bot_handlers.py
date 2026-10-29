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
from app.handlers.ask import ask_handler, ask_text_message_handler, cancel_handler
from app.handlers.explain import explain_handler
from app.handlers.ghidra import ghidra_handler
from app.handlers.report import report_handler, download_report_callback
from app.services.ai_service import AIService, AIExplanationResult


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


@pytest.mark.asyncio
async def test_ask_handler_with_query(test_db_path):
    repo = ScanRepository(db_path=test_db_path)
    ai = MagicMock(spec=AIService)
    ai.answer_security_question = AsyncMock(return_value="A virus attaches to files; a Trojan disguises itself.")

    update, user, message = _create_mock_update(user_id=777)
    context = MagicMock()
    context.args = ["What", "is", "a", "Trojan?"]

    # Thinking reply mock
    thinking_msg = MagicMock(spec=Message)
    thinking_msg.edit_text = AsyncMock()
    message.reply_text.return_value = thinking_msg

    await ask_handler(update, context, ai=ai, repo=repo)
    assert message.reply_text.called
    assert thinking_msg.edit_text.called
    assert "Trojan disguises itself" in thinking_msg.edit_text.call_args[0][0]


@pytest.mark.asyncio
async def test_ask_handler_interactive_prompt_and_cancel():
    update, user, message = _create_mock_update(user_id=777)
    context = MagicMock()
    context.args = []
    context.user_data = {}

    # Calling without query enters interactive prompt
    await ask_handler(update, context, ai=MagicMock(), repo=MagicMock())
    assert context.user_data.get("waiting_for_ask") is True
    assert "question" in message.reply_text.call_args[0][0].lower()

    # Cancel resets state
    await cancel_handler(update, context)
    assert context.user_data.get("waiting_for_ask") is False
    assert "cancelled" in message.reply_text.call_args[0][0].lower()


@pytest.mark.asyncio
async def test_explain_handler_with_latest_scan(test_db_path):
    repo = ScanRepository(db_path=test_db_path)
    repo.save_scan(
        ScanRecord.create(
            scan_id="explain-scan-1",
            user_id=555,
            filename_sanitized="suspicious.pdf",
            file_size=5000,
            sha256="cc"*32,
            verdict="SUSPICIOUS",
            risk_level="MEDIUM",
            scanner_summary='{"findings": ["Embedded JS"], "recommendations": ["Do not open"]}',
        )
    )

    ai = MagicMock(spec=AIService)
    mock_ai_res = AIExplanationResult(
        success=True,
        summary="Document contains suspicious JavaScript.",
        detected_indicators=["Embedded JavaScript"],
        explanation_of_indicators=[{"indicator": "Embedded JS", "explanation": "Executes upon opening."}],
        severity="MEDIUM",
        confidence_level="High",
        potential_impact="Browser exploitation",
        recommended_defensive_actions=["Delete"],
        important_uncertainties="None",
        statement_of_scope="PDF static analysis",
        disclaimer="AI assessment disclaimer.",
    )
    ai.generate_explanation = AsyncMock(return_value=mock_ai_res)

    update, user, message = _create_mock_update(user_id=555)
    context = MagicMock()
    context.args = []

    thinking_msg = MagicMock(spec=Message)
    thinking_msg.edit_text = AsyncMock()
    message.reply_text.return_value = thinking_msg

    await explain_handler(update, context, ai=ai, repo=repo)
    assert thinking_msg.edit_text.called
    reply_text = thinking_msg.edit_text.call_args[0][0]
    assert "suspicious.pdf" in reply_text
    assert "Browser exploitation" in reply_text


@pytest.mark.asyncio
async def test_report_handler_and_download(test_db_path):
    repo = ScanRepository(db_path=test_db_path)
    repo.save_scan(
        ScanRecord.create(
            scan_id="report-scan-1",
            user_id=444,
            filename_sanitized="report_doc.pdf",
            file_size=4096,
            sha256="dd"*32,
            verdict="NO_KNOWN_THREAT_DETECTED",
            risk_level="LOW",
            scanner_summary='{"findings": [], "recommendations": ["Safe to open"]}',
        )
    )

    update, user, message = _create_mock_update(user_id=444)
    context = MagicMock()
    context.args = []

    await report_handler(update, context, repo=repo)
    assert message.reply_text.called
    report_text = message.reply_text.call_args[0][0]
    assert "report_doc.pdf" in report_text
    assert "SECURITY REPORT" in report_text

    # Test download callback
    query = MagicMock()
    query.data = "dl_rep:report-scan-1"
    query.from_user = user
    query.answer = AsyncMock()
    query.message = MagicMock()
    query.message.reply_document = AsyncMock()

    cb_update = MagicMock(spec=Update)
    cb_update.callback_query = query

    await download_report_callback(cb_update, context, repo=repo)
    assert query.message.reply_document.called
    doc_args = query.message.reply_document.call_args.kwargs
    assert "cyberguard_report_" in doc_args["document"].name


@pytest.mark.asyncio
async def test_ghidra_handler_no_scans(test_db_path, monkeypatch):
    from app.scanners.ghidra_analyzer import GhidraAdapter
    monkeypatch.setattr(GhidraAdapter, "is_available", lambda self: True)

    repo = ScanRepository(db_path=test_db_path)
    update, user, message = _create_mock_update(user_id=777)
    context = MagicMock()
    context.args = []

    await ghidra_handler(update, context, repo=repo)
    assert message.reply_text.called
    reply = message.reply_text.call_args[0][0]
    assert "Ghidra" in reply
    assert "upload or forward the executable file" in reply


@pytest.mark.asyncio
async def test_ghidra_handler_file_expired(test_db_path, monkeypatch):
    from app.scanners.ghidra_analyzer import GhidraAdapter
    monkeypatch.setattr(GhidraAdapter, "is_available", lambda self: True)

    repo = ScanRepository(db_path=test_db_path)
    repo.save_scan(
        ScanRecord.create(
            scan_id="ghidra-expired-1",
            user_id=777,
            filename_sanitized="malware_sample.exe",
            file_size=10240,
            sha256="ee"*32,
            verdict="SUSPICIOUS",
            risk_level="HIGH",
        )
    )

    update, user, message = _create_mock_update(user_id=777)
    context = MagicMock()
    context.args = []

    await ghidra_handler(update, context, repo=repo)
    assert message.reply_text.called
    reply = message.reply_text.call_args[0][0]
    assert "File Cache Expired" in reply
    assert "malware_sample.exe" in reply
