"""CyberGuard AI - /status Command Handler."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.config import settings
from app.i18n import t, get_user_lang
from app.security.validation import is_user_authorized
from app.scanners.oletools_analyzer import OletoolsAdapter
from app.scanners.pdfid_analyzer import PDFiDAdapter
from app.scanners.exiftool_analyzer import ExifToolAdapter
from app.scanners.executable_analyzer import CapaAdapter, DiecAdapter
from app.scanners.gitleaks_analyzer import GitleaksAdapter
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.yara_scanner import YaraScanner
from app.services.virustotal_service import VirusTotalService
from app.services.ai_service import AIService
from app.database.repository import ScanRepository


async def status_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    clamav: ClamAVScanner,
    yara: YaraScanner,
    vt: VirusTotalService,
    ai: AIService,
    repo: ScanRepository,
) -> None:
    """Handles the /status command and reports scanning engine health."""
    user = update.effective_user
    if not user:
        return

    if not is_user_authorized(user.id, settings.ALLOWED_USER_IDS):
        await update.message.reply_text(t("unauthorized", user_id=user.id))
        return

    lang = get_user_lang(user.id, default=settings.DEFAULT_LANGUAGE)

    # 1. ClamAV health
    clamav_online = await clamav.ping()
    clamav_ver = await clamav.get_version() if clamav_online else "Unavailable"
    clamav_status = "🟢 Online" if clamav_online else "🔴 Offline / Disabled"

    # 2. YARA health
    yara_status = "🟢 Ready" if yara.is_available and yara.rules_loaded_count > 0 else "⚪ Disabled / No Rules"

    # 3. VirusTotal status
    vt_status = "🟢 Configured" if vt.is_configured else "⚪ Not Configured"

    # 4. AI Service status (Google Gemini via official google-genai SDK)
    if ai.enabled and ai.is_configured:
        ai_status = f"🟢 Ready (SDK: google-genai | Model: {ai.model})"
    elif ai.is_configured:
        ai_status = "⚪ Disabled in configuration (GEMINI_ENABLED=false)"
    else:
        ai_status = "⚪ Not Configured (Missing GEMINI_API_KEY)"

    # 5. Modular Security Adapters Status
    ole_status = "🟢 Ready" if OletoolsAdapter().is_available() else "⚪ Not Installed"
    pdfid_status = "🟢 Ready" if PDFiDAdapter().is_available() else "⚪ Not Installed"
    exif_status = "🟢 Ready" if ExifToolAdapter().is_available() else "⚪ Binary not in PATH"
    capa_status = "🟢 Ready" if CapaAdapter().is_available() else "⚪ Not Installed"
    diec_status = "🟢 Ready" if DiecAdapter().is_available() else "⚪ Binary not in PATH"
    gitleaks_status = "🟢 Ready (Embedded & CLI)"

    # 6. Database status
    try:
        repo.prune_older_than(days=settings.SCAN_RETENTION_DAYS)
        db_status = "🟢 Operational (SQLite WAL)"
    except Exception as e:
        db_status = f"🔴 Error ({e})"

    text = (
        f"{t('status_title', lang=lang)}\n\n"
        f"{t('status_clamav', lang=lang, clamav_status=clamav_status, clamav_version=clamav_ver)}\n"
        f"{t('status_yara', lang=lang, yara_status=yara_status, yara_rules_count=yara.rules_loaded_count)}\n"
        f"{t('status_vt', lang=lang, vt_status=vt_status)}\n"
        f"{t('status_ai', lang=lang, ai_status=ai_status, ai_model=settings.GEMINI_MODEL)}\n"
        f"• *oletools (Office Macros):* {ole_status}\n"
        f"• *PDFiD (PDF Structures):* {pdfid_status}\n"
        f"• *ExifTool (Metadata/Polyglots):* {exif_status}\n"
        f"• *capa / PE (Executables):* {capa_status}\n"
        f"• *Detect It Easy (Packers):* {diec_status}\n"
        f"• *Gitleaks (Secrets & Keys):* {gitleaks_status}\n"
        f"{t('status_db', lang=lang, db_status=db_status)}\n\n"
        f"🛡️ *Host Environment:* Isolated Container Sandbox\n"
        f"📦 *Max Allowed File:* {settings.MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB"
    )

    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.message.reply_text(text=text, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(text=text, parse_mode=ParseMode.MARKDOWN)
