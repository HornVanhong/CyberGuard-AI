"""CyberGuard AI - Database Models.

Data structures for scan history, audit records, and user preferences.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ScanRecord:
    """Represents a persisted scan audit record."""

    scan_id: str
    user_id: int
    user_name: Optional[str]
    filename_sanitized: str
    file_size: int
    sha256: str
    created_at: str
    verdict: str
    risk_level: str
    score: int
    findings_count: int
    scanner_summary: str  # JSON-encoded summary of findings
    ai_explanation: Optional[str] = None  # JSON-encoded AI explanation

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def create(
        cls,
        scan_id: str,
        user_id: int,
        filename_sanitized: str,
        file_size: int,
        sha256: str,
        verdict: str,
        risk_level: str,
        score: int = 0,
        findings_count: int = 0,
        scanner_summary: str = "{}",
        ai_explanation: Optional[str] = None,
        user_name: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> ScanRecord:
        return cls(
            scan_id=scan_id,
            user_id=user_id,
            user_name=user_name,
            filename_sanitized=filename_sanitized,
            file_size=file_size,
            sha256=sha256,
            created_at=created_at or datetime.utcnow().isoformat() + "Z",
            verdict=verdict,
            risk_level=risk_level,
            score=score,
            findings_count=findings_count,
            scanner_summary=scanner_summary,
            ai_explanation=ai_explanation,
        )
