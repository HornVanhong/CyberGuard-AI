"""CyberGuard AI - SQLite Database Repository.

Provides persistent audit history, user data isolation, retention policies,
and data erasure compliant with privacy requirements.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, List, Optional

from app.database.models import ScanRecord
from app.utils.logger import logger


class ScanRepository:
    """Thread-safe SQLite repository for scan records."""

    def __init__(self, db_path: Path | str = "data/cyberguard.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Creates an SQLite connection and ensures it is properly closed."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes tables and indexes."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    user_name TEXT,
                    filename_sanitized TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    scanner_summary TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id, created_at DESC);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans (sha256);
                """
            )
            conn.commit()

    def save_scan(self, record: ScanRecord) -> None:
        """Persists a new scan record."""
        query = """
            INSERT INTO scans (
                scan_id, user_id, user_name, filename_sanitized, file_size,
                sha256, created_at, verdict, risk_level, score,
                findings_count, scanner_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            conn.execute(
                query,
                (
                    record.scan_id,
                    record.user_id,
                    record.user_name,
                    record.filename_sanitized,
                    record.file_size,
                    record.sha256,
                    record.created_at,
                    record.verdict,
                    record.risk_level,
                    record.score,
                    record.findings_count,
                    record.scanner_summary,
                ),
            )
            conn.commit()

    def get_user_history(self, user_id: int, limit: int = 10, offset: int = 0) -> List[ScanRecord]:
        """Retrieves scan history strictly isolated to the specified user_id."""
        query = """
            SELECT scan_id, user_id, user_name, filename_sanitized, file_size,
                   sha256, created_at, verdict, risk_level, score,
                   findings_count, scanner_summary
            FROM scans
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?;
        """
        with self._get_connection() as conn:
            rows = conn.execute(query, (user_id, limit, offset)).fetchall()
            return [self._row_to_record(row) for row in rows]

    def get_scan(self, scan_id: str, user_id: int) -> Optional[ScanRecord]:
        """Retrieves a single scan record, enforcing user isolation."""
        query = """
            SELECT scan_id, user_id, user_name, filename_sanitized, file_size,
                   sha256, created_at, verdict, risk_level, score,
                   findings_count, scanner_summary
            FROM scans
            WHERE scan_id = ? AND user_id = ?;
        """
        with self._get_connection() as conn:
            row = conn.execute(query, (scan_id, user_id)).fetchone()
            if row:
                return self._row_to_record(row)
            return None

    def find_cached_hash(self, sha256: str) -> Optional[ScanRecord]:
        """Looks up a previously completed scan by SHA-256 hash."""
        query = """
            SELECT scan_id, user_id, user_name, filename_sanitized, file_size,
                   sha256, created_at, verdict, risk_level, score,
                   findings_count, scanner_summary
            FROM scans
            WHERE sha256 = ?
            ORDER BY created_at DESC
            LIMIT 1;
        """
        with self._get_connection() as conn:
            row = conn.execute(query, (sha256,)).fetchone()
            if row:
                return self._row_to_record(row)
            return None

    def delete_user_history(self, user_id: int) -> int:
        """Deletes all scan records belonging to a user for privacy compliance."""
        query = "DELETE FROM scans WHERE user_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (user_id,))
            conn.commit()
            deleted = cursor.rowcount
            logger.info("Deleted %d scan records for user_id=%d", deleted, user_id)
            return deleted

    def prune_older_than(self, days: int = 30) -> int:
        """Deletes records older than retention period."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        query = "DELETE FROM scans WHERE created_at < ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (cutoff,))
            conn.commit()
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info("Pruned %d records older than %s", deleted, cutoff)
            return deleted

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            scan_id=row["scan_id"],
            user_id=row["user_id"],
            user_name=row["user_name"],
            filename_sanitized=row["filename_sanitized"],
            file_size=row["file_size"],
            sha256=row["sha256"],
            created_at=row["created_at"],
            verdict=row["verdict"],
            risk_level=row["risk_level"],
            score=row["score"],
            findings_count=row["findings_count"],
            scanner_summary=row["scanner_summary"],
        )
