"""CyberGuard AI - Security Validation & Sanitization Module.

Provides robust file name sanitization, path traversal defense,
permission checks, and input validation.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional


# Disallowed filename characters (Windows & POSIX unsafe)
_INVALID_CHARS_PATTERN = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(filename: Optional[str], default_name: str = "uploaded_file.bin") -> str:
    """Sanitizes an untrusted filename to prevent path traversal and injection.

    - Strips directory paths and traversal sequences (../, ..\\)
    - Removes control characters and unsafe filesystem symbols
    - Prevents hidden file trickery
    - Enforces length limits while preserving extensions
    """
    if not filename or not filename.strip():
        return default_name

    # Take only the basename (strips any leading path components)
    clean = os.path.basename(filename.strip())

    # Remove null bytes and control chars
    clean = _INVALID_CHARS_PATTERN.sub("_", clean)

    # Remove repeated dots or directory traversal attempts
    clean = re.sub(r"\.{2,}", ".", clean)

    # Avoid leading dots which make files hidden on Linux
    clean = clean.lstrip(".")

    if not clean:
        return default_name

    # Separate stem and extension
    p = Path(clean)
    stem, suffix = p.stem, p.suffix

    # Restrict stem length to 80 chars and suffix to 20 chars
    safe_stem = stem[:80]
    safe_suffix = suffix[:20]

    result = f"{safe_stem}{safe_suffix}"
    return result if result else default_name


def is_safe_path(base_dir: Path | str, target_path: Path | str) -> bool:
    """Verifies that target_path resolves strictly within base_dir (anti-traversal)."""
    base = Path(base_dir).resolve()
    target = Path(target_path).resolve()
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def validate_file_size(file_size: int, max_bytes: int) -> bool:
    """Validates that the file size is within limits and non-negative."""
    if file_size < 0:
        return False
    return file_size <= max_bytes


def is_user_authorized(user_id: int, allowed_user_ids: List[int]) -> bool:
    """Checks whether user is authorized. If whitelist is empty, access is public."""
    if not allowed_user_ids:
        return True
    return user_id in allowed_user_ids
