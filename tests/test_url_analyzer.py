"""Tests for CyberGuard AI - URL & Phishing Threat Analyzer."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from app.scanners.url_analyzer import UrlAnalyzer, UrlAnalysisResult, MessageAnalysisResult
from app.services.virustotal_service import VirusTotalService, VTResult, VTStatus


def test_url_extraction():
    text = (
        "Check this link out: https://t.me-verify.xyz/login immediately! "
        "Also visit http://192.168.1.50:8080/test and www.google.com."
    )
    urls = UrlAnalyzer.extract_urls(text)
    assert len(urls) == 3
    assert "https://t.me-verify.xyz/login" in urls
    assert "http://192.168.1.50:8080/test" in urls
    assert "http://www.google.com" in urls


@pytest.mark.asyncio
async def test_analyze_brand_impersonation_and_high_risk_tld():
    analyzer = UrlAnalyzer(vt_service=None)
    res: UrlAnalysisResult = await analyzer.analyze_url("https://telegram-security-bot.xyz")

    assert res.verdict == "MALICIOUS"
    assert res.risk_score >= 65
    assert any("Impersonation detected" in flag for flag in res.red_flags)
    assert any("Suspicious top-level domain" in flag for flag in res.red_flags)


@pytest.mark.asyncio
async def test_analyze_bare_ip():
    analyzer = UrlAnalyzer(vt_service=None)
    res: UrlAnalysisResult = await analyzer.analyze_url("http://185.220.101.5/payload.exe")

    assert res.is_ip_address is True
    assert res.risk_score >= 40
    assert any("Bare IP address" in flag for flag in res.red_flags)


@pytest.mark.asyncio
async def test_analyze_url_shortener():
    analyzer = UrlAnalyzer(vt_service=None)
    res: UrlAnalysisResult = await analyzer.analyze_url("https://bit.ly/3xYzAbC")

    assert res.is_shortened is True
    assert res.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert any("URL shortener" in flag for flag in res.red_flags)


@pytest.mark.asyncio
async def test_analyze_legitimate_url():
    analyzer = UrlAnalyzer(vt_service=None)
    res: UrlAnalysisResult = await analyzer.analyze_url("https://telegram.org/dl")

    assert res.verdict == "CLEAN"
    assert res.risk_score < 25
    assert len(res.red_flags) == 0


@pytest.mark.asyncio
async def test_analyze_virustotal_positive():
    mock_vt = MagicMock(spec=VirusTotalService)
    mock_vt.enabled = True
    mock_vt.lookup_url = AsyncMock(
        return_value=VTResult(
            status=VTStatus.FOUND,
            total_engines=92,
            malicious=7,
            suspicious=1,
            harmless=80,
            undetected=4,
        )
    )

    analyzer = UrlAnalyzer(vt_service=mock_vt)
    res: UrlAnalysisResult = await analyzer.analyze_url("https://suspicious-domain-target.com")

    assert res.verdict == "MALICIOUS"
    assert res.vt_malicious == 8
    assert res.vt_total == 92
    assert any("VirusTotal alert" in flag for flag in res.red_flags)


@pytest.mark.asyncio
async def test_analyze_message_social_engineering():
    analyzer = UrlAnalyzer(vt_service=None)
    msg = (
        "URGENT: Your bank account will be suspended within 24 hours! "
        "You won a cash prize lottery! Send me your password and OTP code to claim reward: "
        "https://aba-secure-login.top/verify"
    )
    res: MessageAnalysisResult = await analyzer.analyze_message(msg)

    assert res.verdict == "MALICIOUS"
    assert len(res.social_engineering_tactics) >= 2
    assert any("Urgency & Fear" in tactic for tactic in res.social_engineering_tactics)
    assert any("Credential Harvesting" in tactic for tactic in res.social_engineering_tactics)
    assert len(res.urls_found) == 1
    assert res.risk_score >= 80
