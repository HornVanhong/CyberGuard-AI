"""Tests for file format identification and extension mismatch detection."""

import pytest
from pathlib import Path
from app.scanners.file_analyzer import FileAnalyzer, FileCategory


def test_detect_pe_executable(temp_dir):
    pe_file = temp_dir / "program.exe"
    pe_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100)

    res = FileAnalyzer.analyze(pe_file, "program.exe")
    assert res.category == FileCategory.EXECUTABLE
    assert not res.is_mismatch
    assert res.mismatch_severity == "none"


def test_detect_pe_disguised_as_pdf(temp_dir):
    # High-risk: Windows executable disguised as a PDF document
    fake_pdf = temp_dir / "invoice.pdf"
    fake_pdf.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100)

    res = FileAnalyzer.analyze(fake_pdf, "invoice.pdf")
    assert res.category == FileCategory.EXECUTABLE
    assert res.is_mismatch is True
    assert res.mismatch_severity == "critical"
    assert "CRITICAL" in res.details


def test_detect_archive_disguised_as_jpg(temp_dir):
    # Zip archive disguised as an image
    fake_jpg = temp_dir / "picture.jpg"
    fake_jpg.write_bytes(b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 50)

    res = FileAnalyzer.analyze(fake_jpg, "picture.jpg")
    assert res.category == FileCategory.ARCHIVE
    assert res.is_mismatch is True
    assert res.mismatch_severity == "high"


def test_detect_genuine_pdf(temp_dir):
    pdf = temp_dir / "document.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%cyberguard test document")

    res = FileAnalyzer.analyze(pdf, "document.pdf")
    assert res.category == FileCategory.DOCUMENT
    assert not res.is_mismatch


def test_detect_plain_text(temp_dir):
    txt = temp_dir / "notes.txt"
    txt.write_text("Hello world, this is a clean regular text document.")

    res = FileAnalyzer.analyze(txt, "notes.txt")
    assert res.category == FileCategory.TEXT
    assert not res.is_mismatch
