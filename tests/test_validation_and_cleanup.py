"""Tests for input validation, sanitization, path security, and file cleanup."""

import os
import pytest
from pathlib import Path
from app.security.validation import (
    sanitize_filename,
    is_safe_path,
    validate_file_size,
    is_user_authorized,
)
from app.services.file_service import FileService


def test_sanitize_filename_traversal():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("safe_document.pdf") == "safe_document.pdf"


def test_sanitize_filename_control_characters():
    dirty = "payload\x00\x1f\n\r.exe"
    clean = sanitize_filename(dirty)
    assert "\x00" not in clean
    assert "\n" not in clean
    assert "\r" not in clean


def test_sanitize_filename_empty():
    assert sanitize_filename("") == "uploaded_file.bin"
    assert sanitize_filename("   ") == "uploaded_file.bin"
    assert sanitize_filename(None) == "uploaded_file.bin"


def test_is_safe_path(temp_dir):
    base = temp_dir / "base"
    base.mkdir()
    inside = base / "child.txt"
    outside = temp_dir / "outside.txt"

    assert is_safe_path(base, inside) is True
    assert is_safe_path(base, outside) is False


def test_validate_file_size():
    max_b = 20 * 1024 * 1024
    assert validate_file_size(100, max_b) is True
    assert validate_file_size(max_b, max_b) is True
    assert validate_file_size(max_b + 1, max_b) is False
    assert validate_file_size(-1, max_b) is False


def test_is_user_authorized():
    # Empty whitelist = public
    assert is_user_authorized(12345, []) is True

    whitelist = [1001, 1002]
    assert is_user_authorized(1001, whitelist) is True
    assert is_user_authorized(9999, whitelist) is False


def test_file_service_sandbox_lifecycle(temp_dir):
    fs = FileService(base_temp_dir=temp_dir)
    sandbox = fs.create_scan_sandbox("test-scan-uuid")
    assert sandbox.is_dir()

    # Create dummy payload inside
    target = fs.prepare_target_path(sandbox, "test_file.bin")
    target.write_bytes(b"temp binary data")
    assert target.is_file()

    # Cleanup sandbox
    fs.cleanup_scan_dir(sandbox)
    assert not sandbox.exists()
    assert not target.exists()
