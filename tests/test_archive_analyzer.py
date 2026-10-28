"""Tests for safe archive inspection."""

import io
import zipfile
import tarfile
import pytest
from pathlib import Path
from app.scanners.archive_analyzer import ArchiveAnalyzer, ArchiveSeverity


def test_detect_zip_path_traversal(temp_dir):
    zip_path = temp_dir / "traversal.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root")

    findings = ArchiveAnalyzer.analyze_file(zip_path)
    assert any(f.category == "Path Traversal" for f in findings)
    assert any(f.severity == ArchiveSeverity.CRITICAL for f in findings)


def test_detect_zip_dangerous_executable(temp_dir):
    zip_path = temp_dir / "invoice.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("document.pdf.exe", b"MZ fake executable")

    findings = ArchiveAnalyzer.analyze_file(zip_path)
    assert any(f.category == "Executable In Archive" for f in findings)
    assert any(f.category == "Extension Spoofing" for f in findings)


def test_detect_zip_bomb_ratio(temp_dir):
    zip_path = temp_dir / "bomb.zip"
    # Create a zip containing highly compressible zeroes (ratio > 100:1)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 10 MB of zeroes compresses to a few hundred bytes
        zf.writestr("zeroes.bin", b"\x00" * (10 * 1024 * 1024))

    findings = ArchiveAnalyzer.analyze_file(zip_path)
    assert any("Zip Bomb" in f.category for f in findings)


def test_detect_tar_path_traversal(temp_dir):
    tar_path = temp_dir / "traversal.tar"
    with tarfile.open(tar_path, "w") as tf:
        data = b"malicious content"
        ti = tarfile.TarInfo(name="../boot/grub.cfg")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    findings = ArchiveAnalyzer.analyze_file(tar_path)
    assert any(f.category == "Path Traversal" for f in findings)


def test_clean_zip_archive(temp_dir):
    zip_path = temp_dir / "clean.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("notes.txt", "meeting minutes")
        zf.writestr("data/table.csv", "id,name\n1,alice")

    findings = ArchiveAnalyzer.analyze_file(zip_path)
    assert len(findings) == 0
