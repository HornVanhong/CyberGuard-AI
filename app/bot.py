"""CyberGuard AI - Main Telegram Bot Application.

Initializes the modular scanning pipeline, sets up handlers,
and manages bot lifecycle and graceful shutdown.
"""

from __future__ import annotations

import sys
from functools import partial

from telegram import BotCommand
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)

from app.config import settings
from app.database.repository import ScanRepository
from app.handlers.callbacks import callback_router
from app.handlers.help import help_handler
from app.handlers.history import cleardata_handler, history_handler
from app.handlers.privacy import privacy_handler
from app.handlers.scan import document_upload_handler, scan_command_handler
from app.handlers.start import start_handler
from app.handlers.status import status_handler
from app.handlers.ask import ask_handler, ask_text_message_handler, cancel_handler
from app.handlers.explain import explain_handler
from app.handlers.ghidra import ghidra_handler
from app.handlers.report import report_handler
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.yara_scanner import YaraScanner
from app.security.rate_limiter import RateLimiter
from app.services.ai_service import AIService
from app.services.file_service import FileService
from app.services.virustotal_service import VirusTotalService
from app.utils.logger import logger


def build_application() -> Application:
    """Configures and builds the Telegram Application with all registered handlers."""
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not set! Please configure it in your .env file or environment variables."
        )
        sys.exit(1)

    # Initialize shared services & scanners
    repo = ScanRepository(db_path=settings.DATABASE_PATH)
    file_service = FileService(base_temp_dir=settings.TEMP_DIR)
    rate_limiter = RateLimiter(
        max_requests=settings.RATE_LIMIT_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    clamav = ClamAVScanner(
        host=settings.CLAMAV_HOST,
        port=settings.CLAMAV_PORT,
        timeout=settings.CLAMAV_TIMEOUT,
        enabled=settings.CLAMAV_ENABLED,
    )

    yara = YaraScanner(
        rules_dir=settings.YARA_RULES_DIR,
        timeout=settings.YARA_TIMEOUT,
        enabled=settings.YARA_ENABLED,
    )
    # Compile YARA rules at startup
    yara.load_rules()

    vt = VirusTotalService(
        api_key=settings.VIRUSTOTAL_API_KEY,
        cache_ttl_seconds=settings.VIRUSTOTAL_CACHE_TTL,
        timeout=settings.VIRUSTOTAL_TIMEOUT,
        enabled=settings.VIRUSTOTAL_ENABLED,
    )

    ai = AIService(
        api_key=settings.GEMINI_API_KEY,
        model=settings.GEMINI_MODEL,
        timeout=settings.effective_gemini_timeout,
        max_output_tokens=settings.GEMINI_MAX_OUTPUT_TOKENS,
        enabled=settings.is_gemini_enabled,
    )

    async def _post_init(application: Application) -> None:
        """Configures official Telegram Bot Menu commands visible to users."""
        en_commands = [
            BotCommand("start", "🚀 Start bot and show main menu"),
            BotCommand("scan", "🔍 Scan a file for malware & threats"),
            BotCommand("status", "⚙️ Check scanner engines & AI health"),
            BotCommand("ask", "💬 Ask cybersecurity AI assistant"),
            BotCommand("explain", "💡 Explain scan findings with Gemini AI"),
            BotCommand("ghidra", "🔬 Decompile binary with NSA Ghidra SRE"),
            BotCommand("report", "📊 View or download full scan report"),
            BotCommand("history", "📋 View your recent scan history"),
            BotCommand("cleardata", "🗑️ Delete your scan history records"),
            BotCommand("privacy", "🔐 Review zero-retention privacy policy"),
            BotCommand("help", "📚 User guide and risk levels explained"),
        ]

        km_commands = [
            BotCommand("start", "🚀 ចាប់ផ្តើម Bot និងបើកផ្ទាំងមឺនុយមេ"),
            BotCommand("scan", "🔍 ស្កេនឯកសារស្វែងរកមេរោគ"),
            BotCommand("status", "⚙️ ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន និង AI"),
            BotCommand("ask", "💬 សួរសំណួរសន្តិសុខសាយប័រជាមួយ AI"),
            BotCommand("explain", "💡 ពន្យល់លម្អិតពីលទ្ធផលស្កេនឯកសារ"),
            BotCommand("ghidra", "🔬 វិភាគស៊ីជម្រៅ និង Decompile (Ghidra)"),
            BotCommand("report", "📊 ទាញយករបាយការណ៍ស្កេនពេញលេញ"),
            BotCommand("history", "📋 មើលប្រវត្តិឯកសារដែលបានស្កេន"),
            BotCommand("cleardata", "🗑️ លុបប្រវត្តិ និងកំណត់ត្រាទាំងអស់"),
            BotCommand("privacy", "🔐 គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព"),
            BotCommand("help", "📚 ការណែនាំ និងរបៀបប្រើប្រាស់"),
        ]

        try:
            # Register default English commands
            await application.bot.set_my_commands(en_commands)
            # Register localized Khmer commands for Khmer users
            await application.bot.set_my_commands(km_commands, language_code="km")
            logger.info("Registered %d Telegram bot commands (English & Khmer)", len(en_commands))
        except Exception as e:
            logger.warning("Could not set bot commands: %s", e)

    # Build Application
    app = (
        ApplicationBuilder()
        .token(settings.TELEGRAM_BOT_TOKEN)
        .post_init(_post_init)
        .build()
    )

    # Register Command Handlers
    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("scan", scan_command_handler))
    app.add_handler(
        CommandHandler(
            "status",
            partial(
                status_handler,
                clamav=clamav,
                yara=yara,
                vt=vt,
                ai=ai,
                repo=repo,
            ),
        )
    )
    app.add_handler(CommandHandler("history", partial(history_handler, repo=repo)))
    app.add_handler(CommandHandler("cleardata", partial(cleardata_handler, repo=repo)))
    app.add_handler(CommandHandler("privacy", privacy_handler))
    app.add_handler(CommandHandler("ask", partial(ask_handler, ai=ai, repo=repo)))
    app.add_handler(CommandHandler("explain", partial(explain_handler, ai=ai, repo=repo)))
    app.add_handler(CommandHandler("ghidra", partial(ghidra_handler, repo=repo)))
    app.add_handler(CommandHandler("report", partial(report_handler, repo=repo)))
    app.add_handler(CommandHandler("cancel", cancel_handler))

    # Register Interactive Q&A Text Message Handler
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            partial(ask_text_message_handler, ai=ai, repo=repo),
        )
    )

    # Register Document / Media Upload Handler
    doc_filter = filters.Document.ALL | filters.PHOTO | filters.VIDEO | filters.AUDIO
    app.add_handler(
        MessageHandler(
            doc_filter,
            partial(
                document_upload_handler,
                file_service=file_service,
                rate_limiter=rate_limiter,
                clamav=clamav,
                yara=yara,
                vt=vt,
                repo=repo,
            ),
        )
    )

    # Register Callback Query Router
    app.add_handler(
        CallbackQueryHandler(
            partial(
                callback_router,
                ai=ai,
                vt=vt,
                repo=repo,
                clamav=clamav,
                yara=yara,
            )
        )
    )

    return app


def main() -> None:
    """Main execution entry point."""
    logger.info("Starting CyberGuard AI Telegram Malware Scanner Bot...")
    app = build_application()
    logger.info("Bot initialized. Starting long polling...")
    app.run_polling(allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    main()
