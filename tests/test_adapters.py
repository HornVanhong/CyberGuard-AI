"""CyberGuard AI - Automated Tests for Modular Security Scanner Adapters."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanners.base import (
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.scanners.oletools_analyzer import OletoolsAdapter
from app.scanners.pdfid_analyzer import PDFiDAdapter
from app.scanners.exiftool_analyzer import ExifToolAdapter
from app.scanners.executable_analyzer import CapaAdapter, DiecAdapter
from app.scanners.gitleaks_analyzer import GitleaksAdapter
from app.scanners.orchestrator import ScannerOrchestrator
from app.scanners.file_analyzer import FileCategory, FileTypeAnalysis
from app.security.risk_engine import RiskEngine, Verdict, RiskLevel


# 1. Oletools Adapter Tests
@pytest.mark.asyncio
async def test_oletools_nonexistent_file():
    adapter = OletoolsAdapter()
    res = await adapter.scan(Path("nonexistent_office_file.docm"))
    assert res.status == ScanStatus.ERROR
    assert "File not found" in res.error_message


@pytest.mark.asyncio
async def test_oletools_plain_text_not_ole(tmp_path):
    f = tmp_path / "plain.docx"
    f.write_text("Hello world plain text", encoding="utf-8")
    adapter = OletoolsAdapter()
    res = await adapter.scan(f)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity == Severity.CLEAN


# 2. PDFiD Adapter Tests
@pytest.mark.asyncio
async def test_pdfid_clean_pdf(tmp_path):
    pdf_file = tmp_path / "clean.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<<>>\n%%EOF")
    adapter = PDFiDAdapter()
    res = await adapter.scan(pdf_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity == Severity.CLEAN
    assert len(res.findings) == 0


@pytest.mark.asyncio
async def test_pdfid_javascript_and_openaction(tmp_path):
    pdf_file = tmp_path / "weaponized.pdf"
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /JavaScript (app.alert('SAFE_ALERT')) >>\nendobj\n"
        b"trailer\n<<>>\n%%EOF"
    )
    pdf_file.write_bytes(content)
    adapter = PDFiDAdapter()
    res = await adapter.scan(pdf_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity in (Severity.CRITICAL, Severity.HIGH)
    assert any("JavaScript" in f.title or "OpenAction" in f.title for f in res.findings)


@pytest.mark.asyncio
async def test_pdfid_hex_obfuscation(tmp_path):
    pdf_file = tmp_path / "obfuscated.pdf"
    content = b"%PDF-1.4\n1 0 obj\n<< /J#61vaScript 2 0 R >>\nendobj\ntrailer\n<<>>\n%%EOF"
    pdf_file.write_bytes(content)
    adapter = PDFiDAdapter()
    res = await adapter.scan(pdf_file)
    assert res.status == ScanStatus.COMPLETED
    assert any("Hexadecimal Obfuscation" in f.title for f in res.findings)


# 3. ExifTool Adapter Tests
@pytest.mark.asyncio
async def test_exiftool_unavailable_fallback():
    adapter = ExifToolAdapter(exiftool_path="/nonexistent/bin/exiftool")
    assert not adapter.is_available()
    res = await adapter.scan(Path("test.jpg"))
    assert res.status == ScanStatus.UNAVAILABLE
    assert "ExifTool binary not found" in res.error_message


@pytest.mark.asyncio
async def test_exiftool_polyglot_detection(tmp_path):
    img = tmp_path / "polyglot.jpg"
    img.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00\xff\xfe\x00\x1cCyberGuard_Synthetic_Exif_Test")
    adapter = ExifToolAdapter()
    adapter.is_available = MagicMock(return_value=True)
    # Construct mock comment at runtime without static signature triggers
    php_tag = "<" + "?php"
    mock_json = json.dumps([{"FileType": "JPEG", "Comment": f"{php_tag} echo 1;"}])
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_json
        mock_run.return_value = mock_proc
        adapter.exiftool_path = "mock_exiftool"

        res = await adapter.scan(img)
        assert res.status == ScanStatus.COMPLETED
        assert res.severity == Severity.HIGH
        assert any("Suspicious Metadata" in f.title for f in res.findings)


# 4. Gitleaks / Secret Detection Tests
@pytest.mark.asyncio
async def test_gitleaks_aws_key_masked(tmp_path):
    code_file = tmp_path / "config.py"
    raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
    code_file.write_text(f'AWS_KEY = "{raw_key}"\n', encoding="utf-8")
    adapter = GitleaksAdapter()
    res = await adapter.scan(code_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity in (Severity.HIGH, Severity.CRITICAL)
    finding = next(f for f in res.findings if "AWS Access Key" in f.title)
    assert raw_key not in finding.evidence
    assert "****" in finding.evidence


@pytest.mark.asyncio
async def test_gitleaks_github_pat_masked(tmp_path):
    code_file = tmp_path / "deploy.sh"
    raw_pat = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    code_file.write_text(f'export GITHUB_TOKEN="{raw_pat}"\n', encoding="utf-8")
    adapter = GitleaksAdapter()
    res = await adapter.scan(code_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity == Severity.CRITICAL
    finding = next(f for f in res.findings if "GitHub Personal Access Token" in f.title)
    assert raw_pat not in finding.evidence
    assert "****" in finding.evidence


@pytest.mark.asyncio
async def test_gitleaks_private_key_detection(tmp_path):
    key_file = tmp_path / "id_rsa"
    header = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
    footer = "-----" + "END RSA PRIVATE KEY" + "-----"
    key_file.write_text(f"{header}\nMIIEowIBAAKCAQEA...\n{footer}", encoding="utf-8")
    adapter = GitleaksAdapter()
    res = await adapter.scan(key_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity == Severity.CRITICAL
    assert any("Private Cryptographic Key" in f.title for f in res.findings)


@pytest.mark.asyncio
async def test_gitleaks_clean_code(tmp_path):
    code_file = tmp_path / "main.py"
    code_file.write_text("print('Hello World')\nx = 10\n", encoding="utf-8")
    adapter = GitleaksAdapter()
    res = await adapter.scan(code_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity == Severity.CLEAN
    assert len(res.findings) == 0


# 5. Executable (capa / diec) Adapter Tests
@pytest.mark.asyncio
async def test_capa_non_pe_file(tmp_path):
    txt_file = tmp_path / "document.txt"
    txt_file.write_text("Not a PE file", encoding="utf-8")
    adapter = CapaAdapter()
    res = await adapter.scan(txt_file)
    assert res.status == ScanStatus.SKIPPED
    assert res.severity == Severity.CLEAN


@pytest.mark.asyncio
async def test_diec_unavailable_fallback():
    with patch("app.scanners.executable_analyzer._PEFILE_AVAILABLE", False):
        adapter = DiecAdapter(diec_path="/nonexistent/diec")
        assert not adapter.is_available()
        res = await adapter.scan(Path("test.exe"))
        assert res.status == ScanStatus.UNAVAILABLE
        assert "diec binary not found" in res.error_message


@pytest.mark.asyncio
async def test_diec_embedded_engine_non_pe(tmp_path):
    txt_file = tmp_path / "sample.txt"
    txt_file.write_text("Hello world", encoding="utf-8")
    adapter = DiecAdapter(diec_path="/nonexistent/diec")
    assert adapter.is_available()  # Available via embedded pefile
    res = await adapter.scan(txt_file)
    assert res.status == ScanStatus.COMPLETED
    assert res.severity == Severity.CLEAN


# 6. Ghidra SRE & Decompiler Adapter Tests
from app.scanners.ghidra_analyzer import GhidraAdapter


@pytest.mark.asyncio
async def test_ghidra_unavailable_fallback():
    adapter = GhidraAdapter(ghidra_path="/nonexistent/analyzeHeadless")
    # If Java or Ghidra is not installed, it safely returns UNAVAILABLE
    assert not adapter.is_available()
    res = await adapter.scan(Path("sample.exe"))
    assert res.status == ScanStatus.UNAVAILABLE
    assert "not found" in res.error_message.lower()


@pytest.mark.asyncio
async def test_ghidra_mock_successful_analysis(tmp_path):
    target_bin = tmp_path / "trojan_sim.bin"
    target_bin.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

    adapter = GhidraAdapter(ghidra_path="/mock/analyzeHeadless")
    adapter.is_available = MagicMock(return_value=True)

    mock_report = {
        "program_name": "trojan_sim.bin",
        "language_id": "x86:LE:64:default",
        "compiler": "gcc",
        "image_base": "0x400000",
        "function_count": 42,
        "dangerous_apis": [
            {"api": "VirtualAllocEx", "address": "0x401020", "callers": ["inject_code"]},
            {"api": "CreateRemoteThread", "address": "0x401050", "callers": ["main"]},
            {"api": "WriteProcessMemory", "address": "0x401080", "callers": ["inject_code"]},
        ],
        "entry_function": "main",
        "decompiled_code": "int main() {\n    VirtualAllocEx(...);\n    return 0;\n}",
    }

    async def fake_proc(*args, **kwargs):
        # Write report_file
        report_file_path = args[-1]
        with open(report_file_path, "w", encoding="utf-8") as f:
            json.dump(mock_report, f)
        mock_p = MagicMock()
        mock_p.returncode = 0
        mock_p.communicate = AsyncMock(return_value=(b"Success", b""))
        return mock_p

    with patch("asyncio.create_subprocess_exec", side_effect=fake_proc):
        res = await adapter.scan(target_bin)
        assert res.status == ScanStatus.COMPLETED
        assert res.severity == Severity.HIGH
        assert any("High-Risk API" in f.title for f in res.findings)
        assert getattr(res, "metadata", {}).get("function_count") == 42


# 7. Scanner Orchestrator Integration Tests
@pytest.mark.asyncio
async def test_orchestrator_selective_execution_on_python_script(tmp_path):
    py_file = tmp_path / "test_secret.py"
    token = "123456789:" + "abcdefghijklmnopqrstuvwxyz123456789"
    py_file.write_text(f'#!/usr/bin/env python\nTELEGRAM_BOT_TOKEN = "{token}"\n', encoding="utf-8")

    orchestrator = ScannerOrchestrator()
    orchestrator.clamav.scan_file = AsyncMock(return_value=MagicMock(status="CLEAN"))
    orchestrator.yara.scan_file = AsyncMock(return_value=MagicMock(status="NO_MATCH"))

    orch_res = await orchestrator.execute_scan(py_file, "test_secret.py")
    assert orch_res.file_analysis.category in (FileCategory.SCRIPT, FileCategory.TEXT)

    gitleaks_res = orch_res.get_result_by_scanner("Gitleaks")
    assert gitleaks_res is not None
    assert gitleaks_res.status == ScanStatus.COMPLETED
    assert gitleaks_res.severity in (Severity.HIGH, Severity.MEDIUM)

    capa_res = orch_res.get_result_by_scanner("capa")
    assert capa_res is None


@pytest.mark.asyncio
async def test_risk_engine_correlates_adapter_results():
    file_analysis = FileTypeAnalysis(
        declared_extension=".pdf",
        detected_mime="application/pdf",
        detected_type_name="PDF Document",
        category=FileCategory.DOCUMENT,
        is_mismatch=False,
        mismatch_severity="none",
        details="Standard PDF",
    )

    pdfid_result = ScannerResult(
        scanner_name="PDFiD",
        scanner_version="1.1.3",
        status=ScanStatus.COMPLETED,
        findings=[
            Finding(
                title="PDF Structural Indicator: /Launch",
                description="Contains 1 Launch action capable of triggering external commands.",
                severity=Severity.CRITICAL,
                confidence="High",
            )
        ],
        severity=Severity.CRITICAL,
        confidence="High",
    )

    assessment = RiskEngine.evaluate(
        file_analysis=file_analysis,
        adapter_results=[pdfid_result],
    )

    assert "PDFiD" in assessment.engines_checked
    assert assessment.score >= 35
    assert assessment.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
    assert any("PDFiD" in f for f in assessment.findings)
