"""Tests for cryptographic hashing service."""

import hashlib
import pytest
from pathlib import Path
from app.services.hashing_service import HashingService, FileHashes


def test_compute_hashes_sync(temp_dir):
    test_file = temp_dir / "sample.txt"
    content = b"CyberGuard AI Test Content 12345"
    test_file.write_bytes(content)

    hashes = HashingService.compute_hashes(test_file)

    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_sha1 = hashlib.sha1(content).hexdigest()
    expected_md5 = hashlib.md5(content).hexdigest()

    assert hashes.sha256 == expected_sha256
    assert hashes.sha1 == expected_sha1
    assert hashes.md5 == expected_md5
    assert hashes.file_size_bytes == len(content)


@pytest.mark.asyncio
async def test_compute_hashes_async(temp_dir):
    test_file = temp_dir / "async_sample.bin"
    content = b"\x00\x01\x02\x03" * 1024  # 4 KB
    test_file.write_bytes(content)

    hashes = await HashingService.compute_hashes_async(test_file)
    assert hashes.file_size_bytes == 4096
    assert len(hashes.sha256) == 64


def test_compute_hashes_non_existent_file(temp_dir):
    fake_path = temp_dir / "does_not_exist.bin"
    with pytest.raises(FileNotFoundError):
        HashingService.compute_hashes(fake_path)
