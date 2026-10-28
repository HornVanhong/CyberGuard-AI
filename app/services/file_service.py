"""CyberGuard AI - File Management Service.

Handles isolated temporary sandbox directory creation, restricted file permissions,
safe file writing, and guaranteed post-scan cleanup.
"""

from __future__ import annotations

import os
import shutil
import stat
import uuid
from pathlib import Path
from typing import Optional

from app.security.validation import is_safe_path, sanitize_filename
from app.utils.logger import logger


class FileService:
    """Manages temporary sandbox directories and file lifecycles."""

    def __init__(self, base_temp_dir: Path | str = "temp_uploads") -> None:
        self.base_temp_dir = Path(base_temp_dir).resolve()
        self.base_temp_dir.mkdir(parents=True, exist_ok=True)

    def create_scan_sandbox(self, scan_id: Optional[str] = None) -> Path:
        """Creates an isolated temporary folder for a specific scan.

        Sets restrictive permissions (0o700) where supported.
        """
        scan_id = scan_id or str(uuid.uuid4())
        sandbox_dir = (self.base_temp_dir / scan_id).resolve()

        if not is_safe_path(self.base_temp_dir, sandbox_dir):
            raise ValueError(f"Directory traversal detected in scan sandbox creation: {scan_id}")

        sandbox_dir.mkdir(parents=True, exist_ok=True)

        # Restrict directory access to current process user on POSIX
        if os.name != "nt":
            try:
                os.chmod(sandbox_dir, 0o700)
            except Exception as e:
                logger.warning("Could not set 0o700 permissions on %s: %s", sandbox_dir, e)

        return sandbox_dir

    def prepare_target_path(self, sandbox_dir: Path, raw_filename: Optional[str]) -> Path:
        """Returns a safe, sanitized absolute path inside the sandbox directory."""
        clean_name = sanitize_filename(raw_filename)
        target_path = (sandbox_dir / clean_name).resolve()

        if not is_safe_path(sandbox_dir, target_path):
            raise ValueError(f"Path traversal attempt detected in target path: {raw_filename}")

        return target_path

    def cleanup_scan_dir(self, sandbox_dir: Path | str) -> None:
        """Completely and safely deletes the scan sandbox directory and contents."""
        path = Path(sandbox_dir).resolve()
        if not path.exists():
            return

        # Ensure we don't accidentally wipe root or base_temp_dir
        if not is_safe_path(self.base_temp_dir, path) or path == self.base_temp_dir:
            logger.error("Refusing to delete unsafe directory: %s", path)
            return

        def _remove_readonly(func, target, exc_info):
            # Error handler for Windows read-only files
            try:
                os.chmod(target, stat.S_IWRITE)
                func(target)
            except Exception as e:
                logger.warning("Error clearing read-only flag on %s: %s", target, e)

        try:
            shutil.rmtree(path, onerror=_remove_readonly)
            logger.debug("Successfully cleaned up sandbox directory: %s", path)
        except Exception as e:
            logger.error("Failed to delete sandbox directory %s: %s", path, e)
