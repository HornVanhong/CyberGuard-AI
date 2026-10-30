"""CyberGuard AI - Static Office Document Security Analyzer.

Inspects Microsoft Office files (DOCX, XLSX, PPTX, DOCM, XLSM, and legacy OLE documents)
without executing or rendering them. Detects VBA macros, auto-exec hooks, embedded OLE objects,
and suspicious API calls.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional

from app.utils.logger import logger


class OfficeSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class OfficeFinding:
    """Represents a threat indicator found in an Office document."""

    category: str
    severity: OfficeSeverity
    description: str
    target_stream: Optional[str] = None
    confidence: str = "High"


class OfficeAnalyzer:
    """Safe, static inspector for Microsoft Office documents."""

    # Auto-executing macro routines often abused by weaponized documents
    AUTO_EXEC_PATTERNS = [
        re.compile(rb"(?i)\bAutoOpen\b"),
        re.compile(rb"(?i)\bAutoClose\b"),
        re.compile(rb"(?i)\bDocument_Open\b"),
        re.compile(rb"(?i)\bDocument_Close\b"),
        re.compile(rb"(?i)\bWorkbook_Open\b"),
        re.compile(rb"(?i)\bWorkbook_BeforeClose\b"),
        re.compile(rb"(?i)\bAuto_Open\b"),
        re.compile(rb"(?i)\bAutoExec\b"),
    ]

    # Suspicious execution/download APIs inside VBA streams
    SUSPICIOUS_MACRO_APIS = [
        (re.compile(rb"(?i)\bShell\b"), "Process Execution (Shell)"),
        (re.compile(rb"(?i)\bWScript\.Shell\b"), "WScript Shell Object"),
        (re.compile(rb"(?i)\bCreateObject\b"), "Dynamic COM Object Creation"),
        (re.compile(rb"(?i)\bURLDownloadToFile\b"), "Binary Download (URLDownloadToFile)"),
        (re.compile(rb"(?i)\bpowershell\b"), "PowerShell Invocation"),
        (re.compile(rb"(?i)\bcmd\.exe\b"), "Command Prompt Invocation"),
    ]

    @classmethod
    def analyze_file(cls, file_path: Path | str) -> List[OfficeFinding]:
        """Safely inspects modern OpenXML (ZIP) or legacy OLE documents."""
        try:
            p = Path(file_path)
            if not p.is_file():
                return []

            findings: List[OfficeFinding] = []

            if zipfile.is_zipfile(p):
                findings.extend(cls._analyze_openxml(p))
            else:
                findings.extend(cls._analyze_legacy_ole(p))

            return findings
        except (OSError, Exception) as e:
            logger.debug("OfficeAnalyzer skipped (%s): %s", file_path, e)
            return []

    @classmethod
    def _analyze_openxml(cls, file_path: Path) -> List[OfficeFinding]:
        """Inspects OpenXML packages (DOCX, XLSX, PPTX, DOCM, XLSM)."""
        findings: List[OfficeFinding] = []
        ext = file_path.suffix.lower()

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                members = zf.namelist()

                # 1. Identify VBA project binary streams
                vba_streams = [
                    m for m in members
                    if "vbaProject.bin" in m.lower() or "vba" in m.lower()
                ]

                # 2. Check for macros in standard (macro-free) extensions (.docx, .xlsx, .pptx)
                if vba_streams and ext in [".docx", ".xlsx", ".pptx"]:
                    findings.append(
                        OfficeFinding(
                            category="Hidden Macro in Non-Macro Doc",
                            severity=OfficeSeverity.CRITICAL,
                            description=(
                                f"Document declares non-macro extension '{ext}' but contains "
                                f"embedded VBA macro binary stream: {vba_streams[0]}."
                            ),
                            target_stream=vba_streams[0],
                        )
                    )
                elif vba_streams:
                    findings.append(
                        OfficeFinding(
                            category="VBA Macros Present",
                            severity=OfficeSeverity.MEDIUM,
                            description=f"Document contains VBA macro project ({vba_streams[0]}).",
                            target_stream=vba_streams[0],
                        )
                    )

                # 3. Inspect VBA stream contents for auto-exec hooks and suspicious APIs
                for vba_name in vba_streams:
                    try:
                        vba_data = zf.read(vba_name)

                        # Check auto-exec triggers
                        auto_hooks = []
                        for pat in cls.AUTO_EXEC_PATTERNS:
                            if pat.search(vba_data):
                                auto_hooks.append(pat.pattern.decode("ascii", errors="replace"))

                        if auto_hooks:
                            findings.append(
                                OfficeFinding(
                                    category="Auto-Executing Macro",
                                    severity=OfficeSeverity.HIGH,
                                    description=(
                                        f"Macro contains automatic execution routines ({', '.join(auto_hooks)}) "
                                        "that launch without user consent upon opening the file."
                                    ),
                                    target_stream=vba_name,
                                )
                            )

                        # Check suspicious APIs
                        for api_pat, api_desc in cls.SUSPICIOUS_MACRO_APIS:
                            if api_pat.search(vba_data):
                                findings.append(
                                    OfficeFinding(
                                        category="Suspicious Macro API",
                                        severity=OfficeSeverity.HIGH,
                                        description=f"Macro invokes high-risk system capability: {api_desc}.",
                                        target_stream=vba_name,
                                    )
                                )

                    except Exception as e:
                        logger.warning("Error reading VBA stream %s: %s", vba_name, e)

                # 4. Check for embedded OLE objects or executables
                embedded_objects = [
                    m for m in members
                    if m.startswith("word/embeddings/") or m.startswith("xl/embeddings/")
                ]
                for emb in embedded_objects:
                    emb_ext = Path(emb).suffix.lower()
                    severity = OfficeSeverity.CRITICAL if emb_ext in [".exe", ".bat", ".scr", ".ps1"] else OfficeSeverity.MEDIUM
                    findings.append(
                        OfficeFinding(
                            category="Embedded OLE Object",
                            severity=severity,
                            description=f"Document contains embedded external object: {emb}",
                            target_stream=emb,
                        )
                    )

        except zipfile.BadZipFile:
            pass
        except Exception as e:
            logger.warning("Error in OpenXML analysis for %s: %s", file_path.name, e)

        return findings

    @classmethod
    def _analyze_legacy_ole(cls, file_path: Path) -> List[OfficeFinding]:
        """Safely scans legacy OLE documents (DOC, XLS, PPT) for macro signatures."""
        findings: List[OfficeFinding] = []
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)

            # Check OLE compound document magic: \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1
            if not header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                return findings

            with open(file_path, "rb") as f:
                full_bytes = f.read(10 * 1024 * 1024)

            # Check for VBA stream markers
            if b"VBA" in full_bytes or b"_VBA_PROJECT" in full_bytes:
                findings.append(
                    OfficeFinding(
                        category="Legacy VBA Macro",
                        severity=OfficeSeverity.HIGH,
                        description="Legacy Microsoft OLE document contains VBA macro stream.",
                    )
                )

                for pat in cls.AUTO_EXEC_PATTERNS:
                    if pat.search(full_bytes):
                        findings.append(
                            OfficeFinding(
                                category="Auto-Executing Macro",
                                severity=OfficeSeverity.HIGH,
                                description=f"Legacy document contains auto-executing hook: {pat.pattern.decode('ascii', errors='replace')}",
                            )
                        )
                        break

        except Exception as e:
            logger.warning("Error in legacy OLE analysis for %s: %s", file_path.name, e)

        return findings
