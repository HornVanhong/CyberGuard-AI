"""Tests for VirusTotal Threat Intelligence integration."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.services.virustotal_service import VirusTotalService, VTStatus, VTResult


@pytest.mark.asyncio
async def test_vt_unconfigured():
    vt = VirusTotalService(api_key="")
    assert not vt.is_configured
    assert not vt.enabled

    res = await vt.lookup_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res.status == VTStatus.DISABLED


@pytest.mark.asyncio
async def test_vt_successful_detection_lookup():
    vt = VirusTotalService(api_key="mock_valid_key_0123456789abcdef0123456789abcdef0123456789abcdef01234567")
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 3,
                    "undetected": 20,
                    "harmless": 2,
                },
                "last_analysis_date": "2026-10-28T12:00:00Z",
            }
        }
    }

    mock_resp = httpx.Response(200, json=mock_payload, request=httpx.Request("GET", "https://example.com"))

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)):
        res = await vt.lookup_hash("test_hash_123")
        assert res.status == VTStatus.FOUND
        assert res.malicious == 45
        assert res.suspicious == 3
        assert res.positives == 48
        assert res.total_engines == 70
        assert res.has_detections is True
        assert res.permalink is not None


@pytest.mark.asyncio
async def test_vt_404_not_found():
    vt = VirusTotalService(api_key="mock_key")
    mock_resp = httpx.Response(404, request=httpx.Request("GET", "https://example.com"))

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)):
        res = await vt.lookup_hash("unknown_hash_123")
        assert res.status == VTStatus.NOT_FOUND
        assert res.positives == 0


@pytest.mark.asyncio
async def test_vt_429_quota_exceeded():
    vt = VirusTotalService(api_key="mock_key")
    mock_resp = httpx.Response(429, request=httpx.Request("GET", "https://example.com"))

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)):
        res = await vt.lookup_hash("hash_quota_test")
        assert res.status == VTStatus.QUOTA_EXCEEDED


@pytest.mark.asyncio
async def test_vt_caching():
    vt = VirusTotalService(api_key="mock_key", cache_ttl_seconds=3600)
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 10}
            }
        }
    }
    mock_resp = httpx.Response(200, json=mock_payload, request=httpx.Request("GET", "https://example.com"))

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)) as mock_get:
        # First call hits mock_get
        res1 = await vt.lookup_hash("cached_hash_123")
        assert res1.status == VTStatus.FOUND
        assert mock_get.call_count == 1

        # Second call hits cache
        res2 = await vt.lookup_hash("cached_hash_123")
        assert res2.status == VTStatus.FOUND
        assert mock_get.call_count == 1  # Not called again
