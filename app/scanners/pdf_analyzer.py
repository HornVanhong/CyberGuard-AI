"""CyberGuard AI - Static PDF Security Analyzer.

Inspects PDF documents for embedded JavaScript, launch actions, automatic open actions,
embedded binary payloads, and abnormal structure without executing or rendering them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional

from app.utils.logger import logger


class PDFSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PDFFinding:
    """Finding identified in PDF document."""

    category: str
    severity: PDFSeverity
    description: str
    matched_element: str
    confidence: str


class PDFAnalyzer:
    """Safe, static byte-level PDF structure and stream analyzer."""

    # Key PDF malicious indicator tokens
    SUSPICIOUS_TOKENS = [
        (
            re.compile(rb"/Launch\b"),
            "Launch Action",
            PDFSeverity.CRITICAL,
            "Document contains /Launch action to execute an external application or process.",
            "High",
        ),
        (
            re.compile(rb"/(?:JavaScript|JS)\b"),
            "Embedded JavaScript",
            PDFSeverity.HIGH,
            "Document contains embedded JavaScript code (/JavaScript or /JS).",
            "High",
        ),
        (
            re.compile(rb"/OpenAction\b"),
            "Automatic Action",
            PDFSeverity.MEDIUM,
            "Document contains /OpenAction which executes automatically upon viewing.",
            "High",
        ),
        (
            re.compile(rb"/AA\b"),
            "Additional Action",
            PDFSeverity.MEDIUM,
            "Document contains /AA (Additional Action) triggered by user interactions/page events.",
            "Medium",
        ),
        (
            re.compile(rb"/(?:EmbeddedFiles|EF|Filespec)\b"),
            "Embedded Files",
            PDFSeverity.HIGH,
            "Document contains embedded file attachments (/EmbeddedFiles or /EF).",
            "High",
        ),
        (
            re.compile(rb"/RichMedia\b"),
            "Rich Media Content",
            PDFSeverity.MEDIUM,
            "Document contains /RichMedia content (e.g. Flash/3D streams).",
            "Medium",
        ),
        (
            re.compile(rb"/AcroForm\b"),
            "Interactive Form",
            PDFSeverity.LOW,
            "Document contains /AcroForm interactive fields.",
            "Low",
        ),
        (
            re.compile(rb"/(?:ASCIIHexDecode|ASCII85Decode|FlateDecode|RunLengthDecode)\b"),
            "Encoded Streams",
            PDFSeverity.INFO,
            "Document utilizes compressed or encoded stream filters.",
            "Low",
        ),
    ]

    @classmethod
    def analyze_file(cls, file_path: Path | str) -> List[PDFFinding]:
        """Safely scans raw bytes of a PDF file for malicious indicators."""
        p = Path(file_path)
        if not p.is_file():
            return []

        findings: List[PDFFinding] = []
        try:
            with open(p, "rb") as f:
                content = f.read(10 * 1024 * 1024)  # Read up to 10 MB for inspection

            # Check if valid PDF header
            if not content.startswith(b"%PDF"):
                return findings

            for pattern, category, severity, description, confidence in cls.SUSPICIOUS_TOKENS:
                matches = pattern.findall(content)
                if matches:
                    count = len(matches)
                    findings.append(
                        PDFFinding(
                            category=category,
                            severity=severity,
                            description=f"{description} (Occurrences: {count})",
                            matched_element=pattern.pattern.decode("ascii", errors="replace"),
                            confidence=confidence,
                        )
                    )

            # Check for hex-obfuscated names (e.g., /#4a#61#76#61#53#63#72#69#70#74 for /JavaScript)
            if re.search(rb"/#[0-9a-fA-F]{2}", content):
                findings.append(
                    PDFFinding(
                        category="Name Obfuscation",
                        severity=PDFSeverity.HIGH,
                        description="PDF uses hexadecimal character escaping in dictionary keys to evade scanners.",
                        matched_element="/#xx",
                        confidence="Medium",
                    )
                )

        except Exception as e:
            logger.warning("PDF analysis error on %s: %s", p.name, e)

        return findings
