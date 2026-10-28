"""CyberGuard AI - /ghidra Deep Decompilation & Forensic Analysis Handler."""

from __future__ import annotations

import html
from pathlib import Path
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized
from app.database.repository import ScanRepository
from app.scanners.ghidra_analyzer import GhidraAdapter
from app.utils.logger import logger


async def ghidra_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    repo: ScanRepository,
) -> None:
    """Handles the /ghidra command to decompile and analyze binaries."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)
    adapter = GhidraAdapter()

    # 1. Check if Ghidra engine is installed and ready
    if not adapter.is_available():
        msg = (
            "🔬 *Ghidra Headless SRE & Decompiler Engine*\n\n"
            "⚪ *Status:* Not Installed / Java Missing\n\n"
            "Ghidra requires **Java OpenJDK 17+** and the Ghidra headless analyzer.\n"
            "To enable deep decompilation on executables, configure `GHIDRA_PATH` "
            "or run inside the full CyberGuard AI container with Ghidra enabled."
        )
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        return

    # 2. Identify target scan
    scan_id = None
    if context.args:
        scan_id = context.args[0].strip()
    else:
        latest = repo.get_latest_user_scan(user.id)
        if latest:
            scan_id = latest.scan_id

    if not scan_id:
        msg = (
            "🔬 *Ghidra Decompiler & Forensic SRE*\n\n"
            "Please specify a scan ID to decompile:\n"
            "`/ghidra [scan_id]`\n\n"
            "Or upload an executable file (`.exe`, `.dll`, `.elf`) first."
        )
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        return

    record = repo.get_scan(scan_id)
    if not record or record.user_id != user.id:
        await update.message.reply_text(t("explain_not_found"))
        return

    # Check sandbox file existence
    target_file = Path(settings.TEMP_DIR) / scan_id / record.file_name
    if not target_file.exists():
        # Fallback search inside temp directory
        matches = list((Path(settings.TEMP_DIR) / scan_id).glob("*"))
        if matches:
            target_file = matches[0]

    if not target_file.exists():
        msg = (
            f"⚠️ *File Sandbox Expired for Scan #{scan_id[:8]}*\n\n"
            "In accordance with our zero-retention security policy, original binaries "
            "are deleted immediately upon scan completion.\n\n"
            "To decompile with Ghidra, please re-upload the file."
        )
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        return

    status_msg = await update.effective_message.reply_text(
        "⏳ *Analyzing with NSA Ghidra Headless Engine...*\n"
        "_Disassembling instructions and decompiling functions (this may take 15-30s)..._",
        parse_mode=ParseMode.MARKDOWN,
    )

    result = await adapter.scan(target_file)

    meta = getattr(result, "metadata", {}) or {}
    decompiled = meta.get("decompiled_code", "")
    entry_fn = meta.get("entry_function", "main")
    func_count = meta.get("function_count", 0)

    # Format findings
    findings_text = ""
    for f in result.findings:
        findings_text += f"• *{f.title}* ({f.severity.value}): {f.description}\n"
        if f.evidence:
            findings_text += f"  ↳ Evidence: `{f.evidence}`\n"

    c_snippet = ""
    if decompiled and decompiled != "// No functions identified":
        # Truncate to fit Telegram message limit
        c_clean = decompiled[:1200]
        c_snippet = f"\n\n💻 *Decompiled Entry Function (`{entry_fn}`):*\n```c\n{c_clean}\n```"

    report_text = (
        f"🔬 *Ghidra Reverse Engineering Report*\n"
        f"📁 *Target:* `{record.file_name}`\n"
        f"🔢 *Functions Discovered:* `{func_count}`\n"
        f"⏱️ *Analysis Time:* `{result.execution_time_ms:.1f}ms`\n\n"
        f"📊 *Findings:*\n{findings_text if findings_text else '• No high-risk API xrefs detected.'}"
        f"{c_snippet}"
    )

    try:
        await status_msg.edit_text(report_text, parse_mode=ParseMode.MARKDOWN)
    except Exception:
        # Fallback to plain text if Markdown parsing fails on decompiled C characters
        await status_msg.edit_text(report_text)
