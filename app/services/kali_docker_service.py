"""CyberGuard AI — Kali Docker Malware Analysis Service.

Integration layer between the CyberGuard AI backend and the dedicated
Kali Linux Malware Analysis container.

Ensures strict separation of concerns:
- Validates file & calculates SHA-256 on host
- Passes sample into isolated Kali container via read-only mount
- Obtains comprehensive multi-tool JSON analysis report
- Decoupled from Telegram and UI layers
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.utils.logger import logger


@dataclass
class KaliAnalysisResult:
    """Structured report returned from Kali analysis container."""

    success: bool
    verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS
    severity: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int  # 0 to 100
    sha256: str
    sha1: str
    md5: str
    file_size: int
    file_type: str
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    raw_report: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    execution_duration: float = 0.0


class KaliDockerService:
    """Manages execution of malware analysis inside the Kali container."""

    def __init__(
        self,
        image_name: str = "cyberguard-kali-analyzer:latest",
        container_name: str = "cyberguard-kali-analyzer",
        timeout: int = 60,
        staging_dir: Optional[Path | str] = None,
    ) -> None:
        self.image_name = image_name
        self.container_name = container_name
        self.timeout = timeout
        self.staging_dir = Path(staging_dir or "docker/kali-analyzer/samples").resolve()
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    def is_docker_available(self) -> bool:
        """Verifies if docker CLI is accessible on host."""
        return shutil.which("docker") is not None

    def is_container_running(self) -> bool:
        """Checks if the persistent analyzer container daemon is currently running."""
        if not self.is_docker_available():
            return False
        try:
            res = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.container_name}", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return self.container_name in res.stdout.strip().splitlines()
        except Exception as e:
            logger.debug("Failed checking container status: %s", e)
            return False

    def is_image_available(self) -> bool:
        """Checks if the Kali analyzer image is built and available locally."""
        if not self.is_docker_available():
            return False
        try:
            res = subprocess.run(
                ["docker", "images", "-q", self.image_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return bool(res.stdout.strip())
        except Exception:
            return False

    def scan_file(
        self,
        file_path: Path | str,
        original_filename: Optional[str] = None,
    ) -> KaliAnalysisResult:
        """Executes multi-engine analysis on a sample inside the Kali container."""
        start_time = time.time()
        p = Path(file_path).resolve()

        if not p.is_file():
            return KaliAnalysisResult(
                success=False,
                verdict="ERROR",
                severity="HIGH",
                risk_score=0,
                sha256="",
                sha1="",
                md5="",
                file_size=0,
                file_type="Unknown",
                error_message=f"Target sample not found: {p}",
            )

        file_bytes = p.read_bytes()
        file_size = len(file_bytes)
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()

        # Create isolated ephemeral staging copy
        staging_token = uuid.uuid4().hex[:8]
        safe_ext = "".join(Path(original_filename or p.name).suffixes[-2:]) or ".bin"
        staged_name = f"sample_{staging_token}{safe_ext}"
        staged_file = self.staging_dir / staged_name

        try:
            staged_file.write_bytes(file_bytes)

            # Choose execution mode:
            # Mode A: If container is running, use 'docker exec'
            # Mode B: If container is not running, use ephemeral 'docker run'
            if self.is_container_running():
                cmd = [
                    "docker", "exec",
                    self.container_name,
                    "python3", "/usr/local/bin/kali_scanner.py",
                    f"/samples/{staged_name}",
                ]
            else:
                abs_staging = str(self.staging_dir.resolve()).replace("\\", "/")
                # Ensure Windows path translation if running on Windows Docker
                if ":" in abs_staging:
                    drive, rest = abs_staging.split(":", 1)
                    abs_staging = f"/{drive.lower()}{rest}"

                cmd = [
                    "docker", "run", "--rm",
                    "--user", "10002:10002",
                    "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true",
                    "--read-only",
                    "--tmpfs", "/tmp:rw,exec,nosuid,size=300m",
                    "--tmpfs", "/tmp/analysis:rw,noexec,nosuid,size=500m,uid=10002,gid=10002,mode=0770",
                    "--tmpfs", "/home/analyzer:rw,nosuid,size=100m,uid=10002,gid=10002,mode=0770",
                    "--pids-limit", "150",
                    "--cpus", "2.0",
                    "--memory", "3000M",
                    "-v", f"{str(self.staging_dir.resolve())}:/samples:ro",
                    self.image_name,
                    "python3", "/usr/local/bin/kali_scanner.py",
                    f"/samples/{staged_name}",
                ]

            logger.info("Executing Kali container malware analysis on '%s' (SHA-256: %s)...", p.name, sha256[:12])
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

            duration = round(time.time() - start_time, 2)

            if res.returncode != 0 and not res.stdout.strip():
                err_msg = res.stderr.strip() or f"Process exited with code {res.returncode}"
                logger.error("Kali container scan failed: %s", err_msg)
                return KaliAnalysisResult(
                    success=False,
                    verdict="ERROR",
                    severity="MEDIUM",
                    risk_score=0,
                    sha256=sha256,
                    sha1=sha1,
                    md5=md5,
                    file_size=file_size,
                    file_type="Unknown",
                    error_message=err_msg,
                    execution_duration=duration,
                )

            # Parse JSON report
            report_text = res.stdout.strip()
            # If stdout contains any leading lines before the JSON opening brace, slice them
            brace_idx = report_text.find("{")
            if brace_idx != -1:
                report_text = report_text[brace_idx:]

            data = json.loads(report_text)
            assessment = data.get("assessment", {})
            metadata = data.get("sample_metadata", {})

            return KaliAnalysisResult(
                success=True,
                verdict=assessment.get("verdict", "INCONCLUSIVE"),
                severity=assessment.get("severity", "LOW"),
                risk_score=assessment.get("risk_score", 0),
                sha256=sha256,
                sha1=sha1,
                md5=md5,
                file_size=file_size,
                file_type=metadata.get("file_type", "Unknown"),
                findings=assessment.get("findings", ["Analysis completed successfully."]),
                recommendations=assessment.get("recommendations", []),
                raw_report=data,
                execution_duration=duration,
            )

        except subprocess.TimeoutExpired:
            duration = round(time.time() - start_time, 2)
            logger.error("Kali container scan timed out after %ds on %s", self.timeout, p.name)
            return KaliAnalysisResult(
                success=False,
                verdict="TIMEOUT",
                severity="HIGH",
                risk_score=50,
                sha256=sha256,
                sha1=sha1,
                md5=md5,
                file_size=file_size,
                file_type="Unknown",
                error_message=f"Malware analysis timed out after {self.timeout}s in sandbox",
                execution_duration=duration,
            )
        except Exception as e:
            duration = round(time.time() - start_time, 2)
            logger.error("Error communicating with Kali container: %s", e, exc_info=True)
            return KaliAnalysisResult(
                success=False,
                verdict="ERROR",
                severity="HIGH",
                risk_score=0,
                sha256=sha256,
                sha1=sha1,
                md5=md5,
                file_size=file_size,
                file_type="Unknown",
                error_message=str(e),
                execution_duration=duration,
            )
        finally:
            # Guaranteed cleanup of staged sample
            if staged_file.exists():
                try:
                    staged_file.unlink()
                except Exception as e:
                    logger.warning("Could not delete staged sample %s: %s", staged_file, e)
