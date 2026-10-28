"""CyberGuard AI - File Upload & Scan Pipeline Handler.

Orchestrates the entire asynchronous scanning pipeline:
1. Permission & Rate Limiting Check
2. Pre-download size validation
3. Isolated sandbox directory allocation
4. Cryptographic hashing (SHA-256, SHA-1, MD5)
5. Format identification & extension mismatch detection
6. ClamAV streaming antivirus scan
7. YARA signature matching
8. Deep static format inspection (Scripts, PDFs, Archives, Office)
9. Threat intelligence correlation (VirusTotal)
10. Objective risk engine assessment
11. SQLite audit record persistence
12. Comprehensive Telegram report delivery
13. Guaranteed temporary file cleanup
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Optional

from telegram import Document, File, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import (
    is_user_authorized,
    sanitize_filename,
    validate_file_size,
)
from app.security.rate_limiter import RateLimiter
from app.security.risk_engine import RiskEngine, AssessmentResult
from app.database.models import ScanRecord
from app.database.repository import ScanRepository
from app.services.file_service import FileService
from app.services.hashing_service import HashingService
from app.services.virustotal_service import VirusTotalService
from app.services.report_service import ReportService
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.yara_scanner import YaraScanner
from app.scanners.file_analyzer import FileAnalyzer, FileCategory
from app.scanners.script_analyzer import ScriptAnalyzer
from app.scanners.pdf_analyzer import PDFAnalyzer
from app.scanners.archive_analyzer import ArchiveAnalyzer
from app.scanners.office_analyzer import OfficeAnalyzer
from app.utils.logger import logger


async def scan_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /scan command, asking the user to send or forward a file."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)
    await update.message.reply_text(
        text=t("start_prompt", lang=lang),
        parse_mode=ParseMode.MARKDOWN,
    )


async def document_upload_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    file_service: FileService,
    rate_limiter: RateLimiter,
    clamav: ClamAVScanner,
    yara: YaraScanner,
    vt: VirusTotalService,
    repo: ScanRepository,
) -> None:
    """Handles uploaded Telegram files and executes the scan pipeline."""
    message = update.effective_message
    user = update.effective_user
    if not message or not user:
        return

    user_id = user.id
    lang = get_user_lang(user_id, default=settings.DEFAULT_LANGUAGE)

    # 1. Authorization check
    if not is_user_authorized(user_id, settings.ALLOWED_USER_IDS):
        await message.reply_text(t("unauthorized", user_id=user_id))
        return

    # 2. Rate limiting check
    allowed, remaining, retry_after = rate_limiter.check_limit(user_id)
    if not allowed:
        await message.reply_text(
            t("rate_limited", lang=lang, wait_seconds=retry_after)
        )
        return

    # Identify document or photo
    raw_filename = "unnamed_payload.bin"
    file_size = 0
    telegram_file_id = ""

    if message.document:
        doc: Document = message.document
        raw_filename = doc.file_name or "document.bin"
        file_size = doc.file_size or 0
        telegram_file_id = doc.file_id
    elif message.photo:
        photo = message.photo[-1]  # Highest resolution
        raw_filename = f"photo_{photo.file_unique_id}.jpg"
        file_size = photo.file_size or 0
        telegram_file_id = photo.file_id
    elif message.video:
        video = message.video
        raw_filename = video.file_name or f"video_{video.file_unique_id}.mp4"
        file_size = video.file_size or 0
        telegram_file_id = video.file_id
    elif message.audio:
        audio = message.audio
        raw_filename = audio.file_name or f"audio_{audio.file_unique_id}.mp3"
        file_size = audio.file_size or 0
        telegram_file_id = audio.file_id
    else:
        await message.reply_text("Please upload a file or document to scan.")
        return

    # 3. Pre-download size validation
    max_bytes = settings.MAX_FILE_SIZE_BYTES
    if not validate_file_size(file_size, max_bytes):
        max_mb = max_bytes // (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        await message.reply_text(
            t("file_too_large", lang=lang, max_mb=max_mb, actual_mb=f"{actual_mb:.1f}")
        )
        return

    # 4. Generate unique Scan ID
    scan_id = str(uuid.uuid4())
    clean_filename = sanitize_filename(raw_filename)
    logger.info("Scan initialized: scan_id=%s, user_id=%d, file=%s", scan_id, user_id, clean_filename)

    # 5. Send initial progress message
    size_mb = f"{file_size / (1024 * 1024):.2f}"
    progress_msg = await message.reply_text(
        t("progress_downloading", lang=lang, size_mb=size_mb)
    )

    sandbox_dir: Optional[Path] = None

    try:
        # 6. Create isolated sandbox directory
        sandbox_dir = file_service.create_scan_sandbox(scan_id)
        local_file_path = file_service.prepare_target_path(sandbox_dir, clean_filename)

        # 7. Download Telegram file into isolated sandbox
        tg_file: File = await context.bot.get_file(telegram_file_id)
        await tg_file.download_to_drive(custom_path=local_file_path)

        # 8. Compute cryptographic hashes
        try:
            await progress_msg.edit_text(t("progress_hashing", lang=lang))
        except Exception:
            pass

        hashes = await HashingService.compute_hashes_async(local_file_path)

        # 9. Format inspection & Extension mismatch check
        file_analysis = await asyncio.to_thread(
            FileAnalyzer.analyze, local_file_path, clean_filename
        )

        # 10. Antivirus & Signature scanning
        try:
            await progress_msg.edit_text(t("progress_scanning", lang=lang))
        except Exception:
            pass

        # Run ClamAV and YARA scans
        clamav_task = clamav.scan_file(local_file_path)
        yara_task = yara.scan_file(local_file_path)

        clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)

        # 11. Format-specific static analysis
        try:
            await progress_msg.edit_text(t("progress_deep_analysis", lang=lang))
        except Exception:
            pass

        script_findings = None
        pdf_findings = None
        archive_findings = None
        office_findings = None

        ext = Path(clean_filename).suffix.lower()

        # Scripts
        if file_analysis.category == FileCategory.SCRIPT or ext in [
            ".py", ".js", ".mjs", ".php", ".ps1", ".bat", ".cmd", ".sh", ".bash", ".vbs"
        ]:
            script_findings = await asyncio.to_thread(ScriptAnalyzer.analyze_file, local_file_path)

        # PDF documents
        if file_analysis.category == FileCategory.DOCUMENT and ext == ".pdf":
            pdf_findings = await asyncio.to_thread(PDFAnalyzer.analyze_file, local_file_path)

        # Archives
        if file_analysis.category == FileCategory.ARCHIVE or ext in [".zip", ".tar", ".gz", ".tgz"]:
            archive_findings = await asyncio.to_thread(ArchiveAnalyzer.analyze_file, local_file_path)

        # Office documents
        if file_analysis.category == FileCategory.DOCUMENT and ext in [
            ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"
        ]:
            office_findings = await asyncio.to_thread(OfficeAnalyzer.analyze_file, local_file_path)

        # 12. Optional VirusTotal Intelligence (via hash lookup only)
        vt_result = None
        if vt.is_configured:
            try:
                await progress_msg.edit_text(t("progress_vt", lang=lang))
            except Exception:
                pass
            vt_result = await vt.lookup_hash(hashes.sha256)

        # 13. Risk Assessment & Correlation
        try:
            await progress_msg.edit_text(t("progress_correlating", lang=lang))
        except Exception:
            pass

        assessment: AssessmentResult = RiskEngine.evaluate(
            file_analysis=file_analysis,
            clamav_result=clamav_result,
            yara_result=yara_result,
            script_findings=script_findings,
            pdf_findings=pdf_findings,
            archive_findings=archive_findings,
            office_findings=office_findings,
            vt_result=vt_result,
        )

        # 14. Save audit record to SQLite database
        scan_record = ScanRecord.create(
            scan_id=scan_id,
            user_id=user_id,
            user_name=user.username,
            filename_sanitized=clean_filename,
            file_size=hashes.file_size_bytes,
            sha256=hashes.sha256,
            verdict=assessment.verdict.value,
            risk_level=assessment.risk_level.value,
            score=assessment.score,
            findings_count=len(assessment.findings),
            scanner_summary=json.dumps(assessment.to_summary_dict()),
        )
        repo.save_scan(scan_record)

        # 15. Generate structured Telegram report
        report_text = ReportService.build_security_report(
            scan_id=scan_id,
            filename=clean_filename,
            file_size_bytes=hashes.file_size_bytes,
            sha256=hashes.sha256,
            file_analysis=file_analysis,
            assessment=assessment,
            clamav_result=clamav_result,
            yara_result=yara_result,
            vt_result=vt_result,
            user_id=user_id,
            lang=lang,
        )

        keyboard = ReportService.build_report_keyboard(
            scan_id=scan_id,
            sha256=hashes.sha256,
            vt_result=vt_result,
            ai_enabled=settings.is_gemini_enabled,
            vt_enabled=settings.VIRUSTOTAL_ENABLED,
            lang=lang,
        )

        # 16. Deliver final report (edit or send new message)
        try:
            await progress_msg.edit_text(
                text=report_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=keyboard,
            )
        except Exception:
            # Fallback if markdown escaping encounters unusual characters
            await message.reply_text(
                text=report_text,
                reply_markup=keyboard,
            )

    except Exception as e:
        logger.error("Scan pipeline exception for scan_id=%s: %s", scan_id, e, exc_info=True)
        try:
            await progress_msg.edit_text(
                t("scan_failed", lang=lang, error="Internal processing error. Please try again.")
            )
        except Exception:
            pass

    finally:
        # 17. GUARANTEED SANDBOX CLEANUP
        if sandbox_dir:
            file_service.cleanup_scan_dir(sandbox_dir)
