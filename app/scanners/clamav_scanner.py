"""CyberGuard AI - ClamAV Antivirus Scanner.

Communicates with the ClamAV daemon (clamd) via the asynchronous TCP socket protocol.
Streams files via zINSTREAM chunks without requiring ClamAV to have direct filesystem access.
Accurately distinguishes detected malware, clean results, unavailable services, and scan errors.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

from app.utils.logger import logger


class ClamAVStatus(str, Enum):
    """Possible outcomes of a ClamAV scan."""

    CLEAN = "CLEAN"
    MALWARE_DETECTED = "MALWARE_DETECTED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ClamAVResult:
    """Detailed ClamAV scan outcome."""

    status: ClamAVStatus
    malware_name: Optional[str] = None
    engine_version: Optional[str] = None
    error_message: Optional[str] = None
    raw_response: Optional[str] = None

    @property
    def is_threat(self) -> bool:
        return self.status == ClamAVStatus.MALWARE_DETECTED


class ClamAVScanner:
    """Asynchronous ClamAV client communicating with clamd daemon over TCP."""

    CHUNK_SIZE = 64 * 1024  # 64 KB per stream chunk

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout: float = 30.0,
        enabled: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.enabled = enabled

    async def ping(self) -> bool:
        """Pings the clamd daemon using 'zPING\\0' or 'PING\\n'."""
        if not self.enabled:
            return False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5.0,
            )
            try:
                writer.write(b"zPING\0")
                await writer.drain()
                response = await asyncio.wait_for(reader.read(128), timeout=5.0)
                return b"PONG" in response
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            logger.debug("ClamAV ping failed (%s:%s): %s", self.host, self.port, e)
            return False

    async def get_version(self) -> Optional[str]:
        """Retrieves engine and signature database version from clamd."""
        if not self.enabled:
            return None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5.0,
            )
            try:
                writer.write(b"zVERSION\0")
                await writer.drain()
                response = await asyncio.wait_for(reader.read(256), timeout=5.0)
                clean_str = response.decode("utf-8", errors="replace").strip("\x00\r\n ")
                return clean_str if clean_str else None
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            logger.debug("ClamAV version check failed: %s", e)
            return None

    async def scan_file(self, file_path: Path | str) -> ClamAVResult:
        """Streams file to clamd using zINSTREAM command and parses result."""
        if not self.enabled:
            return ClamAVResult(
                status=ClamAVStatus.UNAVAILABLE,
                error_message="ClamAV is disabled in configuration.",
            )

        p = Path(file_path)
        if not p.is_file():
            return ClamAVResult(
                status=ClamAVStatus.FAILED,
                error_message=f"File not found: {file_path}",
            )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            logger.warning("ClamAV daemon unreachable (%s:%d): %s", self.host, self.port, e)
            return ClamAVResult(
                status=ClamAVStatus.UNAVAILABLE,
                error_message=f"Antivirus service offline ({type(e).__name__}).",
            )

        try:
            # Start zINSTREAM session: command terminated by null byte
            writer.write(b"zINSTREAM\0")
            await writer.drain()

            # Stream chunks with 4-byte network-endian length prefix
            with open(p, "rb") as f:
                while chunk := f.read(self.CHUNK_SIZE):
                    chunk_len = len(chunk)
                    header = struct.pack(">I", chunk_len)
                    writer.write(header + chunk)
                    await writer.drain()

            # Zero-length chunk indicates EOF
            writer.write(struct.pack(">I", 0))
            await writer.drain()

            # Read clamd reply
            response_bytes = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            raw_response = response_bytes.decode("utf-8", errors="replace").strip("\x00\r\n ")
            logger.info("ClamAV scan completed: %s", raw_response)

            return self._parse_clamd_response(raw_response)

        except asyncio.TimeoutError:
            logger.error("ClamAV scan timed out for %s", p.name)
            return ClamAVResult(
                status=ClamAVStatus.FAILED,
                error_message="Scan timed out.",
            )
        except Exception as e:
            logger.error("ClamAV scan error: %s", e)
            return ClamAVResult(
                status=ClamAVStatus.FAILED,
                error_message=str(e),
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _parse_clamd_response(raw_response: str) -> ClamAVResult:
        """Parses clamd response:
        'stream: OK' -> Clean
        'stream: <signature> FOUND' -> Malware
        'stream: <error> ERROR' -> Failed
        """
        if not raw_response:
            return ClamAVResult(
                status=ClamAVStatus.INCONCLUSIVE,
                raw_response=raw_response,
                error_message="Empty response from antivirus daemon.",
            )

        if "OK" in raw_response:
            return ClamAVResult(
                status=ClamAVStatus.CLEAN,
                raw_response=raw_response,
            )

        if "FOUND" in raw_response:
            # Format: 'stream: Win.Trojan.Agent-123 FOUND'
            parts = raw_response.split(":")
            malware_name = "Detected Threat"
            if len(parts) >= 2:
                sig_part = parts[1].replace("FOUND", "").strip()
                if sig_part:
                    malware_name = sig_part
            return ClamAVResult(
                status=ClamAVStatus.MALWARE_DETECTED,
                malware_name=malware_name,
                raw_response=raw_response,
            )

        if "ERROR" in raw_response:
            return ClamAVResult(
                status=ClamAVStatus.FAILED,
                raw_response=raw_response,
                error_message=raw_response,
            )

        return ClamAVResult(
            status=ClamAVStatus.INCONCLUSIVE,
            raw_response=raw_response,
            error_message="Unrecognized response format.",
        )
