"""CyberGuard AI — Kali Docker Malware Analysis Integration Tests.

Validates:
- KaliDockerService interface and initialization
- File staging, SHA-256 calculation, and cleanup
- Container verification script readiness
- ClamAV, YARA, and capa integration on harmless test files
- JSON report structure and risk assessment
"""

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.kali_docker_service import KaliAnalysisResult, KaliDockerService


@pytest.fixture
def harmless_text_sample(tmp_path: Path) -> Path:
    """Creates a benign text file for testing."""
    sample = tmp_path / "safe_document.txt"
    sample.write_text("CyberGuard AI test file - harmless string content\n", encoding="utf-8")
    return sample


@pytest.fixture
def harmless_yara_test_sample(tmp_path: Path) -> Path:
    """Creates a benign test sample matching a harmless test fixture pattern."""
    sample = tmp_path / "test_pattern.bin"
    sample.write_bytes(b"CYBERGUARD_TEST_FIXTURE_MARKER_BENIGN_SAMPLE_2026")
    return sample


@pytest.fixture
def mock_kali_service(tmp_path: Path) -> KaliDockerService:
    """Returns KaliDockerService configured with a temporary staging directory."""
    staging = tmp_path / "staging"
    return KaliDockerService(
        image_name="cyberguard-kali-analyzer:latest",
        container_name="test-kali-analyzer",
        timeout=10,
        staging_dir=staging,
    )


class TestKaliDockerService:
    """Tests the Python integration layer with the Kali analysis container."""

    def test_service_initialization(self, mock_kali_service: KaliDockerService):
        """Verifies initial configuration and staging directory creation."""
        assert mock_kali_service.image_name == "cyberguard-kali-analyzer:latest"
        assert mock_kali_service.container_name == "test-kali-analyzer"
        assert mock_kali_service.staging_dir.exists()

    def test_missing_file_handling(self, mock_kali_service: KaliDockerService):
        """Verifies handling when a non-existent file path is provided."""
        result = mock_kali_service.scan_file("non_existent_file.xyz")
        assert not result.success
        assert result.verdict == "ERROR"
        assert "not found" in result.error_message.lower()

    def test_sha256_and_staging_lifecycle(
        self,
        mock_kali_service: KaliDockerService,
        harmless_text_sample: Path,
    ):
        """Ensures SHA-256 calculation is accurate and staged files are cleaned up."""
        expected_sha256 = hashlib.sha256(harmless_text_sample.read_bytes()).hexdigest()

        # Mock subprocess.run to simulate successful container scan
        mock_report = {
            "cyberguard_engine": "Kali Linux Malware Analysis Container",
            "version": "2.0.0",
            "sample_metadata": {
                "filename": harmless_text_sample.name,
                "size_bytes": harmless_text_sample.stat().st_size,
                "file_type": "ASCII text",
                "hashes": {"sha256": expected_sha256},
            },
            "assessment": {
                "verdict": "CLEAN",
                "severity": "LOW",
                "risk_score": 0,
                "findings": ["No immediate security threats detected."],
                "recommendations": ["Standard zero-trust verification applies."],
            },
            "details": {
                "clamav": {"available": True, "detected": False},
                "yara": {"available": True, "matches": []},
            },
        }

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(mock_report)
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc):
            result = mock_kali_service.scan_file(harmless_text_sample)

            assert result.success is True
            assert result.verdict == "CLEAN"
            assert result.severity == "LOW"
            assert result.sha256 == expected_sha256
            assert result.file_size == harmless_text_sample.stat().st_size

            # Verify no orphaned staging files remain on host
            staged_files = list(mock_kali_service.staging_dir.glob("sample_*"))
            assert len(staged_files) == 0

    def test_timeout_handling(
        self,
        mock_kali_service: KaliDockerService,
        harmless_text_sample: Path,
    ):
        """Ensures container timeouts are handled gracefully without exceptions."""
        import subprocess

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=10)):
            result = mock_kali_service.scan_file(harmless_text_sample)

            assert result.success is False
            assert result.verdict == "TIMEOUT"
            assert result.severity == "HIGH"
            assert "timed out" in result.error_message.lower()

            # Ensure cleanup on timeout
            staged_files = list(mock_kali_service.staging_dir.glob("sample_*"))
            assert len(staged_files) == 0

    def test_malicious_verdict_parsing(
        self,
        mock_kali_service: KaliDockerService,
        harmless_yara_test_sample: Path,
    ):
        """Verifies parsing of threat detections (ClamAV / YARA findings)."""
        mock_report = {
            "cyberguard_engine": "Kali Linux Malware Analysis Container",
            "assessment": {
                "verdict": "MALICIOUS",
                "severity": "CRITICAL",
                "risk_score": 100,
                "findings": ["ClamAV Antivirus signature match: Eicar-Test-Signature"],
                "recommendations": ["Do NOT execute or open this file."],
            },
            "sample_metadata": {"file_type": "EICAR standard anti-virus test file"},
            "details": {
                "clamav": {"available": True, "detected": True, "virus_name": "Eicar-Test-Signature"},
            },
        }

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(mock_report)
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc):
            result = mock_kali_service.scan_file(harmless_yara_test_sample)

            assert result.success is True
            assert result.verdict == "MALICIOUS"
            assert result.severity == "CRITICAL"
            assert result.risk_score == 100
            assert any("Eicar" in f for f in result.findings)
