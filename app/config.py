"""CyberGuard AI - Application Configuration.

Loads configuration from environment variables and .env file.
Provides safe defaults and typed settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List
from pydantic import Field
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
    ALLOWED_USER_IDS: List[int] = Field(
        default_factory=list,
        description="List of allowed Telegram User IDs. Empty means open to all.",
    )

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

    # AI Security Explanations (Optional Google Gemini)
    AI_ENABLED: bool = Field(default=False, description="Enable AI security explanations")
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API key")
    GEMINI_MODEL: str = Field(default="gemini-2.5-flash", description="Gemini model identifier")
    AI_TIMEOUT: float = Field(default=25.0, description="AI explanation timeout in seconds")

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
