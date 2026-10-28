"""Tests for SQLite database repository and user data isolation."""

import pytest
from pathlib import Path
from app.database.models import ScanRecord
from app.database.repository import ScanRepository


def test_save_and_retrieve_scan(test_db_path):
    repo = ScanRepository(db_path=test_db_path)

    rec = ScanRecord.create(
        scan_id="scan-001",
        user_id=111,
        filename_sanitized="test_invoice.pdf",
        file_size=1024,
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        verdict="CLEAN",
        risk_level="LOW",
    )
    repo.save_scan(rec)

    history = repo.get_user_history(user_id=111)
    assert len(history) == 1
    assert history[0].scan_id == "scan-001"
    assert history[0].filename_sanitized == "test_invoice.pdf"


def test_user_history_isolation(test_db_path):
    # CRITICAL: User A must never access User B's scan history
    repo = ScanRepository(db_path=test_db_path)

    rec_a = ScanRecord.create(
        scan_id="scan-user-a",
        user_id=100,
        filename_sanitized="confidential_a.pdf",
        file_size=5000,
        sha256="11" * 32,
        verdict="CLEAN",
        risk_level="LOW",
    )
    rec_b = ScanRecord.create(
        scan_id="scan-user-b",
        user_id=200,
        filename_sanitized="confidential_b.pdf",
        file_size=6000,
        sha256="22" * 32,
        verdict="MALICIOUS",
        risk_level="CRITICAL",
    )
    repo.save_scan(rec_a)
    repo.save_scan(rec_b)

    # User 100 history should contain ONLY User 100 records
    history_100 = repo.get_user_history(user_id=100)
    assert len(history_100) == 1
    assert history_100[0].filename_sanitized == "confidential_a.pdf"

    # User 200 history should contain ONLY User 200 records
    history_200 = repo.get_user_history(user_id=200)
    assert len(history_200) == 1
    assert history_200[0].filename_sanitized == "confidential_b.pdf"

    # Individual scan lookup enforces user_id check
    assert repo.get_scan("scan-user-b", user_id=100) is None
    assert repo.get_scan("scan-user-b", user_id=200) is not None


def test_delete_user_history(test_db_path):
    repo = ScanRepository(db_path=test_db_path)

    rec1 = ScanRecord.create(scan_id="s1", user_id=300, filename_sanitized="f1.pdf", file_size=10, sha256="aa"*32, verdict="CLEAN", risk_level="LOW")
    rec2 = ScanRecord.create(scan_id="s2", user_id=300, filename_sanitized="f2.pdf", file_size=20, sha256="bb"*32, verdict="CLEAN", risk_level="LOW")
    rec3 = ScanRecord.create(scan_id="s3", user_id=400, filename_sanitized="f3.pdf", file_size=30, sha256="cc"*32, verdict="CLEAN", risk_level="LOW")
    repo.save_scan(rec1)
    repo.save_scan(rec2)
    repo.save_scan(rec3)

    # User 300 deletes their data
    deleted = repo.delete_user_history(user_id=300)
    assert deleted == 2

    assert len(repo.get_user_history(user_id=300)) == 0
    # User 400 data remains unaffected
    assert len(repo.get_user_history(user_id=400)) == 1
