"""Tests for static PDF security analysis."""

import pytest
from pathlib import Path
from app.scanners.pdf_analyzer import PDFAnalyzer, PDFSeverity


def test_detect_pdf_javascript(temp_dir):
    pdf = temp_dir / "invoice_js.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /OpenAction 2 0 R >>\n"
        b"2 0 obj\n"
        b"<< /S /JavaScript /JS (app.alert('malicious payload')) >>\n"
        b"endobj\n"
    )

    findings = PDFAnalyzer.analyze_file(pdf)
    assert len(findings) >= 2
    categories = [f.category for f in findings]
    assert "Embedded JavaScript" in categories
    assert "Automatic Action" in categories


def test_detect_pdf_launch_action(temp_dir):
    pdf = temp_dir / "launch.pdf"
    pdf.write_bytes(
        b"%PDF-1.5\n"
        b"<< /Type /Action /S /Launch /F (powershell.exe) >>\n"
    )

    findings = PDFAnalyzer.analyze_file(pdf)
    assert any(f.category == "Launch Action" for f in findings)
    assert any(f.severity == PDFSeverity.CRITICAL for f in findings)


def test_clean_pdf(temp_dir):
    pdf = temp_dir / "clean.pdf"
    pdf.write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
    )

    findings = PDFAnalyzer.analyze_file(pdf)
    assert len(findings) == 0
