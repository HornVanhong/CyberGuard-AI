"""CyberGuard AI - Application Configuration.

Loads configuration from environment variables and .env file.
Provides safe defaults and typed settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Telegram Bot
    TELEGRAM_BOT_TOKEN: str = Field(default="", description="Telegram Bot API Token")
    ALLOWED_USER_IDS: Any = Field(
        default_factory=list,
        description="List of allowed Telegram User IDs. Empty means open to all.",
    )

    @field_validator("ALLOWED_USER_IDS", mode="before")
    @classmethod
    def parse_allowed_user_ids(cls, v: Any) -> List[int]:
        """Safely parses empty string, comma-separated IDs, or JSON arrays."""
        if not v or v == "":
            return []
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return [int(x) for x in json.loads(v)]
                except Exception:
                    pass
            # Comma-separated format
            items = []
            for part in v.split(","):
                part = part.strip()
                if part.isdigit():
                    items.append(int(part))
            return items
        if isinstance(v, (list, tuple)):
            return [int(x) for x in v]
        return []

    # File and Upload Limits
    MAX_FILE_SIZE_BYTES: int = Field(
        default=20 * 1024 * 1024,  # 20 MB default limit (Telegram bot API max)
        description="Maximum file upload size in bytes",
    )
    TEMP_DIR: Path = Field(
        default=Path("temp_uploads"),
        description="Restricted directory for temporary uploads",
    )

    # Storage and Database
    DATABASE_PATH: Path = Field(
        default=Path("data/cyberguard.db"),
        description="SQLite database path for scan history",
    )
    SCAN_RETENTION_DAYS: int = Field(
        default=30,
        description="Number of days to retain user scan history metadata",
    )

    # ClamAV Configuration
    CLAMAV_ENABLED: bool = Field(default=True, description="Enable ClamAV antivirus scanning")
    CLAMAV_HOST: str = Field(default="127.0.0.1", description="ClamAV daemon host")
    CLAMAV_PORT: int = Field(default=3310, description="ClamAV daemon TCP port")
    CLAMAV_TIMEOUT: float = Field(default=30.0, description="ClamAV scan timeout in seconds")

    # YARA Configuration
    YARA_ENABLED: bool = Field(default=True, description="Enable YARA signature scanning")
    YARA_RULES_DIR: Path = Field(
        default=Path("rules"),
        description="Directory containing compiled/raw .yar rules",
    )
    YARA_TIMEOUT: float = Field(default=15.0, description="YARA rule scan timeout in seconds")

    # VirusTotal Threat Intelligence (Optional)
    VIRUSTOTAL_ENABLED: bool = Field(default=False, description="Enable VirusTotal lookups")
    VIRUSTOTAL_API_KEY: str = Field(default="", description="VirusTotal API v3 key")
    VIRUSTOTAL_CACHE_TTL: int = Field(
        default=3600,  # 1 hour
        description="VirusTotal result cache time-to-live in seconds",
    )
    VIRUSTOTAL_TIMEOUT: float = Field(default=15.0, description="VirusTotal HTTP timeout in seconds")

    # AI Security Explanations (Google Gemini using official google-genai SDK)
    GEMINI_ENABLED: bool = Field(default=False, description="Enable Gemini AI integration")
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API key")
    GEMINI_MODEL: str = Field(default="gemini-3-flash-preview", description="Gemini model identifier")
    GEMINI_TIMEOUT: float = Field(default=25.0, description="Gemini API timeout in seconds")
    GEMINI_MAX_OUTPUT_TOKENS: int = Field(
        default=1500, description="Maximum output tokens for Gemini responses"
    )

    # Backwards compatibility aliases
    AI_ENABLED: bool = Field(default=False, description="Legacy alias for GEMINI_ENABLED")
    AI_TIMEOUT: float = Field(default=25.0, description="Legacy alias for GEMINI_TIMEOUT")

    @property
    def is_gemini_enabled(self) -> bool:
        """Determines if Gemini is enabled and properly configured with an API key."""
        return (self.GEMINI_ENABLED or self.AI_ENABLED) and bool(self.GEMINI_API_KEY.strip())

    @property
    def effective_gemini_timeout(self) -> float:
        """Returns the configured Gemini timeout."""
        return self.GEMINI_TIMEOUT or self.AI_TIMEOUT

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(
        default=5,
        description="Maximum number of scans allowed per user in the sliding window",
    )
    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        description="Rate limiting sliding window in seconds",
    )

    # Localization
    DEFAULT_LANGUAGE: str = Field(default="en", description="Default language (en or km)")

    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Logging level: DEBUG, INFO, WARNING, ERROR")


# Global settings singleton
settings = Settings()
