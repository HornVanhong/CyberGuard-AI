"""CyberGuard AI - Unified Scanner Adapter Base & Result Models.

Defines standardized data contracts for all cybersecurity scanning adapters.
Every tool (ClamAV, YARA, oletools, PDFiD, ExifTool, capa, DIE, Gitleaks)
implements this interface to return consistent, structured security findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class ScanStatus(str, Enum):
    """Execution status of a scanner adapter."""

    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class Severity(str, Enum):
    """Standardized finding severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    CLEAN = "CLEAN"


@dataclass
class Finding:
    """Represents an individual security indicator or observation."""

    title: str
    description: str
    severity: Severity = Severity.INFO
    evidence: Optional[str] = None
    confidence: str = "Moderate"  # "High", "Moderate", "Low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class ScannerResult:
    """Consistent structured outcome from any security scanning tool."""

    scanner_name: str
    scanner_version: str
    status: ScanStatus
    findings: List[Finding] = field(default_factory=list)
    severity: Severity = Severity.CLEAN
    confidence: str = "Moderate"
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0

    @property
    def is_positive(self) -> bool:
        """Indicates if suspicious or malicious content was identified."""
        return self.status == ScanStatus.COMPLETED and self.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "status": self.status.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "severity": self.severity.value,
            "confidence": self.confidence,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }


class BaseScannerAdapter(ABC):
    """Abstract interface that all security scanning adapters must implement."""

    name: str = "BaseScanner"
    version: str = "1.0.0"

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the tool is installed and operational."""
        ...

    @abstractmethod
    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        """Executes passive security analysis on the target file."""
        ...
