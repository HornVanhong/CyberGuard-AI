"""Tests for ClamAV TCP client scanner."""

import asyncio
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.scanners.clamav_scanner import ClamAVScanner, ClamAVStatus, ClamAVResult


def test_parse_clamd_clean():
    res = ClamAVScanner._parse_clamd_response("stream: OK")
    assert res.status == ClamAVStatus.CLEAN
    assert not res.is_threat


def test_parse_clamd_malware():
    res = ClamAVScanner._parse_clamd_response("stream: Win.Trojan.Agent-12345 FOUND")
    assert res.status == ClamAVStatus.MALWARE_DETECTED
    assert res.malware_name == "Win.Trojan.Agent-12345"
    assert res.is_threat


def test_parse_clamd_error():
    res = ClamAVScanner._parse_clamd_response("stream: File size limit exceeded ERROR")
    assert res.status == ClamAVStatus.FAILED
    assert res.error_message is not None


def test_parse_clamd_empty():
    res = ClamAVScanner._parse_clamd_response("")
    assert res.status == ClamAVStatus.INCONCLUSIVE


@pytest.mark.asyncio
async def test_clamav_daemon_offline(temp_dir):
    test_file = temp_dir / "sample.bin"
    test_file.write_bytes(b"hello world")

    # Scanner pointing to unreachable port
    scanner = ClamAVScanner(host="127.0.0.1", port=65530, timeout=1.0)
    result = await scanner.scan_file(test_file)

    assert result.status == ClamAVStatus.UNAVAILABLE
    assert not result.is_threat


@pytest.mark.asyncio
async def test_clamav_disabled(temp_dir):
    test_file = temp_dir / "sample.bin"
    test_file.write_bytes(b"test")

    scanner = ClamAVScanner(enabled=False)
    result = await scanner.scan_file(test_file)
    assert result.status == ClamAVStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_clamav_stream_mock(temp_dir):
    test_file = temp_dir / "sample_test.txt"
    test_file.write_bytes(b"CyberGuard synthetic test stream payload for mocked scan")

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"stream: Eicar-Test-Signature FOUND\0"

    from unittest.mock import MagicMock
    mock_writer = MagicMock()
    mock_writer.write = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.drain = AsyncMock(return_value=None)
    mock_writer.wait_closed = AsyncMock(return_value=None)

    scanner = ClamAVScanner()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        result = await scanner.scan_file(test_file)
        assert result.status == ClamAVStatus.MALWARE_DETECTED
        assert result.malware_name == "Eicar-Test-Signature"
