"""Handlers package."""
from app.handlers.start import start_handler
from app.handlers.help import help_handler
from app.handlers.status import status_handler
from app.handlers.history import history_handler, cleardata_handler
from app.handlers.privacy import privacy_handler
from app.handlers.scan import scan_command_handler, document_upload_handler
from app.handlers.callbacks import callback_router

__all__ = [
    "start_handler",
    "help_handler",
    "status_handler",
    "history_handler",
    "cleardata_handler",
    "privacy_handler",
    "scan_command_handler",
    "document_upload_handler",
    "callback_router",
]
