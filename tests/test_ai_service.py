"""Tests for AI Security Explanation Service."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from app.services.ai_service import AIService
from app.security.risk_engine import AssessmentResult, Verdict, RiskLevel


@pytest.mark.asyncio
async def test_ai_disabled():
    ai = AIService(api_key="", enabled=False)
    assessment = AssessmentResult(
        verdict=Verdict.SUSPICIOUS,
        risk_level=RiskLevel.MEDIUM,
        score=25,
        confidence="Moderate",
    )

    res = await ai.generate_explanation(assessment, "file.pdf", "PDF Document")
    assert res.success is False
    assert "disabled" in res.summary.lower()


@pytest.mark.asyncio
async def test_ai_successful_explanation():
    ai = AIService(api_key="mock_ai_key", enabled=True)
    assessment = AssessmentResult(
        verdict=Verdict.MALICIOUS,
        risk_level=RiskLevel.CRITICAL,
        score=90,
        confidence="High",
        findings=["Ransomware payment note detected."],
        recommendations=["Do not execute."],
    )

    mock_gemini_reply = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": (
                                '{"summary": "This file contains ransomware indicators.", '
                                '"risk_explanation": "If run, it could lock your personal files.", '
                                '"actionable_steps": ["Immediately delete this file.", "Disconnect from network."]}'
                            )
                        }
                    ]
                }
            }
        ]
    }

    mock_resp = httpx.Response(200, json=mock_gemini_reply, request=httpx.Request("POST", "https://example.com"))

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)):
        res = await ai.generate_explanation(assessment, "ransom.exe", "Windows Executable")
        assert res.success is True
        assert "ransomware" in res.summary.lower()
        assert len(res.actionable_steps) >= 2
        assert "AI Explanatory Assessment" in res.disclaimer


@pytest.mark.asyncio
async def test_ai_api_failure_fallback():
    ai = AIService(api_key="mock_key", enabled=True)
    assessment = AssessmentResult(
        verdict=Verdict.SUSPICIOUS,
        risk_level=RiskLevel.LOW,
        score=10,
        confidence="Moderate",
    )

    mock_resp = httpx.Response(500, request=httpx.Request("POST", "https://example.com"))

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)):
        res = await ai.generate_explanation(assessment, "test.doc", "Word Doc")
        assert res.success is False
        assert "unavailable" in res.summary.lower()
