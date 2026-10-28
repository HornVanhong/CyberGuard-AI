"""CyberGuard AI - Hashing Service.

Computes cryptographic hashes (SHA-256, SHA-1, MD5) using streaming chunks
to prevent memory exhaustion on large files.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class FileHashes:
    """Represents calculated cryptographic hashes for a file."""

    sha256: str
    sha1: str
    md5: str
    file_size_bytes: int


class HashingService:
    """Service to compute cryptographic hashes efficiently."""

    CHUNK_SIZE = 64 * 1024  # 64 KB chunks

    @classmethod
    def compute_hashes(cls, file_path: Path | str) -> FileHashes:
        """Synchronously streams file content and computes SHA-256, SHA-1, and MD5."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        h_sha256 = hashlib.sha256()
        h_sha1 = hashlib.sha1()
        h_md5 = hashlib.md5()
        total_bytes = 0

        with open(p, "rb") as f:
            while chunk := f.read(cls.CHUNK_SIZE):
                h_sha256.update(chunk)
                h_sha1.update(chunk)
                h_md5.update(chunk)
                total_bytes += len(chunk)

        return FileHashes(
            sha256=h_sha256.hexdigest().lower(),
            sha1=h_sha1.hexdigest().lower(),
            md5=h_md5.hexdigest().lower(),
            file_size_bytes=total_bytes,
        )

    @classmethod
    async def compute_hashes_async(cls, file_path: Path | str) -> FileHashes:
        """Asynchronously computes hashes in a background worker thread."""
        return await asyncio.to_thread(cls.compute_hashes, file_path)
