"""Tests for static Microsoft Office document analysis."""

import zipfile
import pytest
from pathlib import Path
from app.scanners.office_analyzer import OfficeAnalyzer, OfficeSeverity


def test_detect_macro_in_docx(temp_dir):
    # A .docx file should not contain a vbaProject.bin (that's reserved for .docm)
    docx_path = temp_dir / "disguised_contract.docx"
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/vbaProject.bin", b"VBA binary stream with AutoOpen and Shell('cmd.exe')")

    findings = OfficeAnalyzer.analyze_file(docx_path)
    assert len(findings) >= 2
    categories = [f.category for f in findings]
    assert "Hidden Macro in Non-Macro Doc" in categories
    assert "Auto-Executing Macro" in categories


def test_detect_docm_suspicious_apis(temp_dir):
    docm_path = temp_dir / "macro_doc.docm"
    with zipfile.ZipFile(docm_path, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"Sub Document_Open()\nCreateObject(\"WScript.Shell\").Run\nEnd Sub")

    findings = OfficeAnalyzer.analyze_file(docm_path)
    assert any(f.category == "Auto-Executing Macro" for f in findings)
    assert any("Suspicious Macro API" in f.category for f in findings)


def test_clean_docx_document(temp_dir):
    clean_docx = temp_dir / "clean_report.docx"
    with zipfile.ZipFile(clean_docx, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:p/></w:body></w:document>")

    findings = OfficeAnalyzer.analyze_file(clean_docx)
    assert len(findings) == 0
