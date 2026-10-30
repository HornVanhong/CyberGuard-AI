"""CyberGuard AI - File Type & Extension Mismatch Analyzer.

Determines the genuine format of a file using binary signature headers (magic bytes),
and compares it with the declared file extension to identify masquerading or disguise tactics.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

from app.utils.logger import logger

try:
    import magic  # type: ignore
    _MAGIC_AVAILABLE = True
except ImportError:
    magic = None
    _MAGIC_AVAILABLE = False

try:
    import puremagic  # type: ignore
    _PUREMAGIC_AVAILABLE = True
except ImportError:
    puremagic = None
    _PUREMAGIC_AVAILABLE = False


class FileCategory(str, Enum):
    """Broad classification of analyzed files."""

    EXECUTABLE = "EXECUTABLE"
    DOCUMENT = "DOCUMENT"
    ARCHIVE = "ARCHIVE"
    SCRIPT = "SCRIPT"
    IMAGE = "IMAGE"
    MEDIA = "MEDIA"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


# Known magic byte signatures for reliable fallback and PE detection
MAGIC_SIGNATURES = [
    # DOS / PE Executables (Windows .exe, .dll, .sys, .ocx)
    (b"MZ", "application/x-dosexec", "Windows Executable/DLL", FileCategory.EXECUTABLE),
    # Linux ELF Executable
    (b"\x7fELF", "application/x-executable", "Linux ELF Executable", FileCategory.EXECUTABLE),
    # macOS Mach-O
    (b"\xfe\xed\xfa\xce", "application/x-mach-binary", "Mach-O 32-bit", FileCategory.EXECUTABLE),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary", "Mach-O 64-bit", FileCategory.EXECUTABLE),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "Mach-O 64-bit LE", FileCategory.EXECUTABLE),
    # PDF Document
    (b"%PDF", "application/pdf", "PDF Document", FileCategory.DOCUMENT),
    # Microsoft Compound Document / Legacy Office OLE (DOC, XLS, PPT)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "Microsoft OLE Document", FileCategory.DOCUMENT),
    # ZIP Archive & Modern Office Open XML (DOCX, XLSX, PPTX, APK, JAR)
    (b"PK\x03\x04", "application/zip", "ZIP Archive / OpenXML", FileCategory.ARCHIVE),
    (b"PK\x05\x06", "application/zip", "Empty ZIP Archive", FileCategory.ARCHIVE),
    # 7-Zip
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive", FileCategory.ARCHIVE),
    # RAR
    (b"Rar!\x1a\x07", "application/x-rar", "RAR Archive", FileCategory.ARCHIVE),
    # GZIP
    (b"\x1f\x8b", "application/gzip", "GZIP Compressed Archive", FileCategory.ARCHIVE),
    # BZIP2
    (b"BZh", "application/x-bzip2", "BZIP2 Archive", FileCategory.ARCHIVE),
    # TAR (posix tar magic at offset 257, checked separately)
    # Images
    (b"\xff\xd8\xff", "image/jpeg", "JPEG Image", FileCategory.IMAGE),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image", FileCategory.IMAGE),
    (b"GIF87a", "image/gif", "GIF Image", FileCategory.IMAGE),
    (b"GIF89a", "image/gif", "GIF Image", FileCategory.IMAGE),
    (b"BM", "image/bmp", "BMP Image", FileCategory.IMAGE),
    (b"RIFF", "image/webp", "WebP/RIFF", FileCategory.IMAGE),
]

# Mapping extensions to expected categories
EXTENSION_CATEGORY_MAP = {
    # Executables
    ".exe": FileCategory.EXECUTABLE,
    ".dll": FileCategory.EXECUTABLE,
    ".sys": FileCategory.EXECUTABLE,
    ".msi": FileCategory.EXECUTABLE,
    ".bin": FileCategory.EXECUTABLE,
    ".apk": FileCategory.EXECUTABLE,
    # Documents
    ".pdf": FileCategory.DOCUMENT,
    ".doc": FileCategory.DOCUMENT,
    ".docx": FileCategory.DOCUMENT,
    ".xls": FileCategory.DOCUMENT,
    ".xlsx": FileCategory.DOCUMENT,
    ".ppt": FileCategory.DOCUMENT,
    ".pptx": FileCategory.DOCUMENT,
    ".rtf": FileCategory.DOCUMENT,
    ".odt": FileCategory.DOCUMENT,
    # Archives
    ".zip": FileCategory.ARCHIVE,
    ".tar": FileCategory.ARCHIVE,
    ".gz": FileCategory.ARCHIVE,
    ".tgz": FileCategory.ARCHIVE,
    ".bz2": FileCategory.ARCHIVE,
    ".7z": FileCategory.ARCHIVE,
    ".rar": FileCategory.ARCHIVE,
    # Scripts
    ".py": FileCategory.SCRIPT,
    ".js": FileCategory.SCRIPT,
    ".mjs": FileCategory.SCRIPT,
    ".php": FileCategory.SCRIPT,
    ".ps1": FileCategory.SCRIPT,
    ".bat": FileCategory.SCRIPT,
    ".cmd": FileCategory.SCRIPT,
    ".sh": FileCategory.SCRIPT,
    ".bash": FileCategory.SCRIPT,
    ".vbs": FileCategory.SCRIPT,
    ".wsf": FileCategory.SCRIPT,
    # Images
    ".jpg": FileCategory.IMAGE,
    ".jpeg": FileCategory.IMAGE,
    ".png": FileCategory.IMAGE,
    ".gif": FileCategory.IMAGE,
    ".bmp": FileCategory.IMAGE,
    ".webp": FileCategory.IMAGE,
    # Text
    ".txt": FileCategory.TEXT,
    ".csv": FileCategory.TEXT,
    ".json": FileCategory.TEXT,
    ".xml": FileCategory.TEXT,
    ".yaml": FileCategory.TEXT,
    ".yml": FileCategory.TEXT,
}


@dataclass
class FileTypeAnalysis:
    """Outcome of file format identification and extension comparison."""

    declared_extension: str
    detected_mime: str
    detected_type_name: str
    category: FileCategory
    is_mismatch: bool
    mismatch_severity: str  # "critical", "high", "medium", "none"
    details: str


class FileAnalyzer:
    """Identifies file formats from byte signatures and detects extension spoofing."""

    @classmethod
    def analyze_bytes(cls, file_bytes: bytes, original_filename: Optional[str] = None) -> FileTypeAnalysis:
        """Identifies file format directly from in-memory bytes without requiring filesystem access."""
        name = original_filename or "unknown.bin"
        declared_ext = Path(name).suffix.lower()
        header = file_bytes[:512]

        detected_mime = "application/octet-stream"
        detected_name = "Binary Data"
        category = FileCategory.UNKNOWN

        # 1. puremagic detection on in-memory bytes
        if _PUREMAGIC_AVAILABLE:
            try:
                matches = puremagic.magic_string(file_bytes)
                if matches:
                    primary = matches[0]
                    detected_mime = primary.mime_type or detected_mime
                    detected_name = primary.name or detected_name
            except Exception as e:
                logger.debug("puremagic bytes detection exception: %s", e)

        # 2. Check explicit signature table for precision
        for sig, mime, type_name, cat in MAGIC_SIGNATURES:
            if header.startswith(sig):
                detected_mime = mime
                detected_name = type_name
                category = cat
                break

        # Check POSIX tar header at offset 257
        if len(header) >= 262 and header[257:262] == b"ustar":
            detected_mime = "application/x-tar"
            detected_name = "POSIX TAR Archive"
            category = FileCategory.ARCHIVE

        # Check if text/script
        if category == FileCategory.UNKNOWN:
            if header.startswith(b"#!"):
                detected_mime = "text/x-script"
                detected_name = "Shell / Interpreter Script"
                category = FileCategory.SCRIPT
            elif b"<?php" in header:
                detected_mime = "text/x-php"
                detected_name = "PHP Script"
                category = FileCategory.SCRIPT
            elif cls._is_plain_text(header):
                detected_mime = "text/plain"
                detected_name = "Plain Text Document"
                category = FileCategory.TEXT

        # If detected as ZIP, refine whether it is modern Office document
        if detected_mime == "application/zip":
            if declared_ext in [".docx", ".xlsx", ".pptx", ".odt", ".apk"]:
                category = FileCategory.DOCUMENT if declared_ext != ".apk" else FileCategory.EXECUTABLE
                detected_name = f"OpenXML/Package ({declared_ext.upper().lstrip('.')})"

        # Evaluate extension mismatch
        expected_category = EXTENSION_CATEGORY_MAP.get(declared_ext, FileCategory.UNKNOWN)
        is_mismatch = False
        mismatch_severity = "none"
        details = "File signature matches declared extension."

        # High-risk: Executable disguised as document or image
        if category == FileCategory.EXECUTABLE and declared_ext not in [".exe", ".dll", ".sys", ".msi", ".apk", ".bin"]:
            is_mismatch = True
            mismatch_severity = "critical"
            details = f"CRITICAL: Executable binary header ({detected_name}) disguised with extension '{declared_ext}'."

        # Medium-risk: Archive disguised as image or document
        elif category == FileCategory.ARCHIVE and declared_ext in [".jpg", ".png", ".pdf", ".txt"]:
            is_mismatch = True
            mismatch_severity = "high"
            details = f"HIGH: Archive payload ({detected_name}) masquerading with extension '{declared_ext}'."

        # Medium-risk: Script disguised as plain image/document
        elif category == FileCategory.SCRIPT and declared_ext in [".jpg", ".png", ".pdf", ".docx", ".xlsx"]:
            is_mismatch = True
            mismatch_severity = "high"
            details = f"HIGH: Script payload disguised with non-executable extension '{declared_ext}'."

        elif expected_category != FileCategory.UNKNOWN and category != FileCategory.UNKNOWN and expected_category != category:
            is_mismatch = True
            mismatch_severity = "medium"
            details = f"Extension '{declared_ext}' ({expected_category.value}) does not match detected content '{detected_name}' ({category.value})."

        return FileTypeAnalysis(
            declared_extension=declared_ext,
            detected_mime=detected_mime,
            detected_type_name=detected_name,
            category=category,
            is_mismatch=is_mismatch,
            mismatch_severity=mismatch_severity,
            details=details,
        )

    @classmethod
    def analyze(cls, file_path: Path | str, original_filename: Optional[str] = None) -> FileTypeAnalysis:
        p = Path(file_path)
        name = original_filename or p.name

        try:
            with open(p, "rb") as f:
                content = f.read()
            return cls.analyze_bytes(content, name)
        except OSError as e:
            logger.warning("Could not read disk file %s (%s). Attempting safe fallback analysis.", p, e)
            declared_ext = Path(name).suffix.lower()
            return FileTypeAnalysis(
                declared_extension=declared_ext,
                detected_mime="application/octet-stream",
                detected_type_name="Host-Locked Binary",
                category=FileCategory.UNKNOWN,
                is_mismatch=False,
                mismatch_severity="none",
                details=f"File was locked or quarantined by host endpoint protection ({e}).",
            )

    @staticmethod
    def _is_plain_text(bytes_prefix: bytes) -> bool:
        """Determines if the first bytes resemble printable text/scripts."""
        if not bytes_prefix:
            return True
        # If there are null bytes, likely binary
        if b"\x00" in bytes_prefix:
            return False
        # Calculate ratio of ASCII/printable characters
        printable = sum(1 for b in bytes_prefix if 32 <= b <= 126 or b in (9, 10, 13))
        return (printable / len(bytes_prefix)) > 0.85
