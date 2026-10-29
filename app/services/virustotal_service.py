"""CyberGuard AI - VirusTotal Threat Intelligence Integration.

Queries the VirusTotal API v3 via cryptographic SHA-256 hash lookup.
Includes local in-memory caching, quota handling, error resilience,
and strict privacy safeguards (no file content submission without explicit consent).
"""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple

import httpx

from app.utils.logger import logger


class VTStatus(str, Enum):
    """Status of VirusTotal query."""

    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"  # Hash not seen by VirusTotal
    DISABLED = "DISABLED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    ERROR = "ERROR"


@dataclass
class VTResult:
    """Outcome of VirusTotal threat intelligence check (file hash or URL)."""

    status: VTStatus
    sha256: str = ""
    url: Optional[str] = None
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    permalink: Optional[str] = None
    scan_date: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def positives(self) -> int:
        return self.malicious + self.suspicious

    @property
    def has_detections(self) -> bool:
        return self.positives > 0


class VirusTotalService:
    """Client for VirusTotal API v3 hash lookups with TTL caching."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str = "",
        cache_ttl_seconds: int = 3600,
        timeout: float = 15.0,
        enabled: bool = True,
    ) -> None:
        self.api_key = api_key.strip()
        self.cache_ttl = cache_ttl_seconds
        self.timeout = timeout
        self.enabled = enabled and bool(self.api_key)
        self._cache: Dict[str, Tuple[float, VTResult]] = {}
        self._lock = asyncio.Lock()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup_hash(self, sha256: str) -> VTResult:
        """Looks up a file hash on VirusTotal.

        Checks local cache first, then executes HTTP query.
        """
        if not self.enabled:
            return VTResult(
                status=VTStatus.DISABLED,
                sha256=sha256,
                error_message="VirusTotal integration is not configured or disabled.",
            )

        clean_hash = sha256.lower().strip()

        # 1. Check in-memory cache
        async with self._lock:
            if clean_hash in self._cache:
                timestamp, cached_result = self._cache[clean_hash]
                if time.time() - timestamp < self.cache_ttl:
                    logger.debug("VirusTotal cache hit for %s", clean_hash[:16])
                    return cached_result
                else:
                    del self._cache[clean_hash]

        # 2. Query VirusTotal API v3
        url = f"{self.BASE_URL}/files/{clean_hash}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "CyberGuard-AI-Scanner/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    result = self._parse_vt_response(clean_hash, data)
                elif response.status_code == 404:
                    # Hash not found in VirusTotal database
                    result = VTResult(
                        status=VTStatus.NOT_FOUND,
                        sha256=clean_hash,
                        error_message="Hash not present in VirusTotal dataset.",
                    )
                elif response.status_code == 429:
                    logger.warning("VirusTotal API quota exceeded (HTTP 429)")
                    result = VTResult(
                        status=VTStatus.QUOTA_EXCEEDED,
                        sha256=clean_hash,
                        error_message="VirusTotal API rate limit or quota exceeded.",
                    )
                else:
                    logger.warning("VirusTotal HTTP %d: %s", response.status_code, response.text[:100])
                    result = VTResult(
                        status=VTStatus.ERROR,
                        sha256=clean_hash,
                        error_message=f"VirusTotal query failed (HTTP {response.status_code}).",
                    )

        except httpx.TimeoutException:
            logger.warning("VirusTotal request timed out for %s", clean_hash[:16])
            result = VTResult(
                status=VTStatus.ERROR,
                sha256=clean_hash,
                error_message="VirusTotal request timed out.",
            )
        except Exception as e:
            logger.error("VirusTotal connection error: %s", e)
            result = VTResult(
                status=VTStatus.ERROR,
                sha256=clean_hash,
                error_message=str(e),
            )

        # Store valid results in cache
        if result.status in (VTStatus.FOUND, VTStatus.NOT_FOUND):
            async with self._lock:
                self._cache[clean_hash] = (time.time(), result)

        return result

    async def lookup_url(self, target_url: str) -> VTResult:
        """Looks up a URL on VirusTotal API v3.

        Encodes URL to base64url identifier, checks cache, and queries API.
        """
        if not self.enabled:
            return VTResult(
                status=VTStatus.DISABLED,
                url=target_url,
                error_message="VirusTotal integration is not configured or disabled.",
            )

        clean_url = target_url.strip()
        url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        cache_key = f"url_{url_id}"

        # 1. Check in-memory cache
        async with self._lock:
            if cache_key in self._cache:
                timestamp, cached_result = self._cache[cache_key]
                if time.time() - timestamp < self.cache_ttl:
                    logger.debug("VirusTotal cache hit for URL: %s", clean_url[:30])
                    return cached_result
                else:
                    del self._cache[cache_key]

        # 2. Query VirusTotal API v3
        url = f"{self.BASE_URL}/urls/{url_id}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "CyberGuard-AI-Scanner/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    result = self._parse_vt_url_response(clean_url, data)
                elif response.status_code == 404:
                    result = VTResult(
                        status=VTStatus.NOT_FOUND,
                        url=clean_url,
                        error_message="URL not present in VirusTotal dataset.",
                    )
                elif response.status_code == 429:
                    logger.warning("VirusTotal API quota exceeded (HTTP 429)")
                    result = VTResult(
                        status=VTStatus.QUOTA_EXCEEDED,
                        url=clean_url,
                        error_message="VirusTotal API rate limit or quota exceeded.",
                    )
                else:
                    logger.warning("VirusTotal HTTP %d for URL: %s", response.status_code, response.text[:100])
                    result = VTResult(
                        status=VTStatus.ERROR,
                        url=clean_url,
                        error_message=f"VirusTotal query failed (HTTP {response.status_code}).",
                    )

        except httpx.TimeoutException:
            logger.warning("VirusTotal request timed out for URL: %s", clean_url[:30])
            result = VTResult(
                status=VTStatus.ERROR,
                url=clean_url,
                error_message="VirusTotal request timed out.",
            )
        except Exception as e:
            logger.error("VirusTotal connection error for URL: %s", e)
            result = VTResult(
                status=VTStatus.ERROR,
                url=clean_url,
                error_message=str(e),
            )

        # Store valid results in cache
        if result.status in (VTStatus.FOUND, VTStatus.NOT_FOUND):
            async with self._lock:
                self._cache[cache_key] = (time.time(), result)

        return result

    @staticmethod
    def _parse_vt_url_response(url: str, data: Dict[str, Any]) -> VTResult:
        """Parses API v3 URL object response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        harmless = int(stats.get("harmless", 0))
        total = malicious + suspicious + undetected + harmless

        gui_link = f"https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode().strip('=')}"

        return VTResult(
            status=VTStatus.FOUND,
            url=url,
            malicious=malicious,
            suspicious=suspicious,
            undetected=undetected,
            harmless=harmless,
            total_engines=total,
            permalink=gui_link,
            scan_date=str(attributes.get("last_analysis_date", "")),
        )

    @staticmethod
    def _parse_vt_response(sha256: str, data: Dict[str, Any]) -> VTResult:
        """Parses API v3 file object response."""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        harmless = int(stats.get("harmless", 0))
        total = malicious + suspicious + undetected + harmless

        # Generate public permalink
        gui_link = f"https://www.virustotal.com/gui/file/{sha256}"

        return VTResult(
            status=VTStatus.FOUND,
            sha256=sha256,
            malicious=malicious,
            suspicious=suspicious,
            undetected=undetected,
            harmless=harmless,
            total_engines=total,
            permalink=gui_link,
            scan_date=attributes.get("last_analysis_date"),
        )
