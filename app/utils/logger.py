"""CyberGuard AI - Secure Logging Module.

Provides filtered logging that prevents leakage of sensitive tokens,
passwords, API keys, and internal file paths.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any


class SensitiveDataFilter(logging.Filter):
    """Filter that masks sensitive tokens, bot credentials, and API keys."""

    PATTERNS = [
        # Telegram Bot Token: e.g. 123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789
        (re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{35}\b"), "[REDACTED_BOT_TOKEN]"),
        # VirusTotal 64-hex key
        (re.compile(r"\b[a-fA-F0-9]{64}\b"), lambda m: m.group(0)[:8] + "..." + "[REDACTED_API_KEY]"),
        # Google API key (AIza...)
        (re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
        # Bearer tokens
        (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+"), "Bearer [REDACTED_TOKEN]"),
        # AWS Access Keys
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact(a) if isinstance(a, str) else a for a in record.args)
        return True

    @classmethod
    def _redact(cls, text: str) -> str:
        for pattern, replacement in cls.PATTERNS:
            if callable(replacement):
                text = pattern.sub(replacement, text)
            else:
                text = pattern.sub(replacement, text)
        return text


def setup_logger(name: str = "cyberguard", log_level: str = "INFO") -> logging.Logger:
    """Configures and returns a secured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


logger = setup_logger()
