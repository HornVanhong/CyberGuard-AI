"""CyberGuard AI - Safe Archive Security Inspector.

Inspects ZIP, TAR, and GZ archives without disk extraction to prevent:
- Zip bombs / Decompression denial of service
- Directory path traversal attacks (../, absolute paths)
- Symlink attacks
- Hidden executable payloads disguised inside archives
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional

from app.utils.logger import logger


class ArchiveSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ArchiveFinding:
    """Represents a threat indicator found inside an archive."""

    category: str
    severity: ArchiveSeverity
    description: str
    target_member: Optional[str] = None
    confidence: str = "High"


class ArchiveAnalyzer:
    """Safe, non-extracting archive analyzer."""

    MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB max uncompressed
    MAX_MEMBER_COUNT = 500  # 500 files max
    MAX_COMPRESSION_RATIO = 100.0  # 100:1 ratio limit (zip bomb defense)

    # Executable extensions that shouldn't typically be hidden in consumer archives
    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps1xml", ".msh", ".mshxml",
        ".hta", ".cpl", ".msi", ".msp", ".jar", ".com"
    }

    @classmethod
    def analyze_file(cls, file_path: Path | str) -> List[ArchiveFinding]:
        """Inspects archive format and members safely."""
        p = Path(file_path)
        if not p.is_file():
            return []

        findings: List[ArchiveFinding] = []

        if zipfile.is_zipfile(p):
            findings.extend(cls._analyze_zip(p))
        elif tarfile.is_tarfile(p):
            findings.extend(cls._analyze_tar(p))

        return findings

    @classmethod
    def _analyze_zip(cls, zip_path: Path) -> List[ArchiveFinding]:
        findings: List[ArchiveFinding] = []
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                infolist = zf.infolist()
                member_count = len(infolist)
                compressed_size = zip_path.stat().st_size or 1

                # 1. Member count check
                if member_count > cls.MAX_MEMBER_COUNT:
                    findings.append(
                        ArchiveFinding(
                            category="Excessive Entries",
                            severity=ArchiveSeverity.HIGH,
                            description=f"Archive contains {member_count} entries, exceeding safe limit ({cls.MAX_MEMBER_COUNT}). Possible resource exhaustion attack.",
                        )
                    )

                total_uncompressed = 0
                has_nested_archive = False

                for member in infolist:
                    total_uncompressed += member.file_size
                    filename = member.filename

                    # 2. Path traversal check (../, absolute, drive letters)
                    if cls._is_path_traversal(filename):
                        findings.append(
                            ArchiveFinding(
                                category="Path Traversal",
                                severity=ArchiveSeverity.CRITICAL,
                                description=f"Archive entry contains dangerous path traversal pattern: {filename}",
                                target_member=filename,
                            )
                        )

                    # 3. Dangerous executable inside archive
                    member_ext = Path(filename).suffix.lower()
                    if member_ext in cls.DANGEROUS_EXTENSIONS:
                        findings.append(
                            ArchiveFinding(
                                category="Executable In Archive",
                                severity=ArchiveSeverity.HIGH,
                                description=f"Archive contains potentially dangerous executable member: {filename}",
                                target_member=filename,
                            )
                        )

                    # Double extension trick (e.g., document.pdf.exe)
                    if cls._has_double_extension(filename):
                        findings.append(
                            ArchiveFinding(
                                category="Extension Spoofing",
                                severity=ArchiveSeverity.CRITICAL,
                                description=f"Archive entry employs double extension masquerading: {filename}",
                                target_member=filename,
                            )
                        )

                    # Nested archive check
                    if member_ext in [".zip", ".tar", ".gz", ".7z", ".rar"]:
                        has_nested_archive = True

                # 4. Total uncompressed size limit
                if total_uncompressed > cls.MAX_UNCOMPRESSED_BYTES:
                    findings.append(
                        ArchiveFinding(
                            category="Zip Bomb / Size Limit",
                            severity=ArchiveSeverity.CRITICAL,
                            description=(
                                f"Total uncompressed size ({total_uncompressed / 1024 / 1024:.1f} MB) "
                                f"exceeds limit ({cls.MAX_UNCOMPRESSED_BYTES / 1024 / 1024:.0f} MB)."
                            ),
                        )
                    )

                # 5. Compression ratio limit (Zip Bomb indicator)
                ratio = total_uncompressed / max(compressed_size, 1)
                if ratio > cls.MAX_COMPRESSION_RATIO:
                    findings.append(
                        ArchiveFinding(
                            category="Zip Bomb / High Ratio",
                            severity=ArchiveSeverity.CRITICAL,
                            description=(
                                f"Suspicious compression ratio ({ratio:.1f}:1) detected. "
                                "Signature matches Zip Bomb denial of service structure."
                            ),
                        )
                    )

                if has_nested_archive:
                    findings.append(
                        ArchiveFinding(
                            category="Nested Archive",
                            severity=ArchiveSeverity.LOW,
                            description="Archive contains nested compressed archives (depth > 1).",
                        )
                    )

        except zipfile.BadZipFile:
            findings.append(
                ArchiveFinding(
                    category="Malformed Archive",
                    severity=ArchiveSeverity.MEDIUM,
                    description="Archive headers are corrupt or malformed.",
                )
            )
        except Exception as e:
            logger.warning("Error inspecting zip %s: %s", zip_path.name, e)

        return findings

    @classmethod
    def _analyze_tar(cls, tar_path: Path) -> List[ArchiveFinding]:
        findings: List[ArchiveFinding] = []
        try:
            with tarfile.open(tar_path, "r:*") as tf:
                members = tf.getmembers()
                member_count = len(members)

                if member_count > cls.MAX_MEMBER_COUNT:
                    findings.append(
                        ArchiveFinding(
                            category="Excessive Entries",
                            severity=ArchiveSeverity.HIGH,
                            description=f"TAR archive contains {member_count} entries, exceeding safe threshold.",
                        )
                    )

                total_uncompressed = 0
                for m in members:
                    total_uncompressed += m.size
                    filename = m.name

                    # Traversal check
                    if cls._is_path_traversal(filename):
                        findings.append(
                            ArchiveFinding(
                                category="Path Traversal",
                                severity=ArchiveSeverity.CRITICAL,
                                description=f"TAR entry contains path traversal sequence: {filename}",
                                target_member=filename,
                            )
                        )

                    # Symlink and hardlink safeguards
                    if m.issym() or m.islnk():
                        link_target = m.linkname
                        if cls._is_path_traversal(link_target):
                            findings.append(
                                ArchiveFinding(
                                    category="Dangerous Symlink",
                                    severity=ArchiveSeverity.CRITICAL,
                                    description=f"TAR link points outside safe extraction path: {filename} -> {link_target}",
                                    target_member=filename,
                                )
                            )

                    # Executable check
                    ext = Path(filename).suffix.lower()
                    if ext in cls.DANGEROUS_EXTENSIONS:
                        findings.append(
                            ArchiveFinding(
                                category="Executable In Archive",
                                severity=ArchiveSeverity.HIGH,
                                description=f"TAR archive contains executable member: {filename}",
                                target_member=filename,
                            )
                        )

                if total_uncompressed > cls.MAX_UNCOMPRESSED_BYTES:
                    findings.append(
                        ArchiveFinding(
                            category="Archive Size Limit",
                            severity=ArchiveSeverity.CRITICAL,
                            description=f"TAR total uncompressed size exceeds safe threshold ({total_uncompressed / 1024 / 1024:.1f} MB).",
                        )
                    )

        except tarfile.TarError as e:
            findings.append(
                ArchiveFinding(
                    category="Malformed Archive",
                    severity=ArchiveSeverity.MEDIUM,
                    description=f"Malformed TAR archive: {e}",
                )
            )
        except Exception as e:
            logger.warning("Error inspecting tar %s: %s", tar_path.name, e)

        return findings

    @staticmethod
    def _is_path_traversal(path_str: str) -> bool:
        """Detects path traversal indicators (../, ..\\, absolute path, drive letters)."""
        clean = path_str.replace("\\", "/")
        if clean.startswith("/") or clean.startswith("~"):
            return True
        if "../" in clean or clean == "..":
            return True
        if len(clean) >= 2 and clean[1] == ":":  # Windows drive letter C:
            return True
        return False

    @classmethod
    def _has_double_extension(cls, filename: str) -> bool:
        """Detects tricks like invoice.pdf.exe or report.docx.scr."""
        parts = Path(filename).name.split(".")
        if len(parts) >= 3:
            first_ext = "." + parts[-2].lower()
            last_ext = "." + parts[-1].lower()
            if first_ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"]:
                if last_ext in cls.DANGEROUS_EXTENSIONS:
                    return True
        return False
