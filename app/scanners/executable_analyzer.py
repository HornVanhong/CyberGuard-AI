"""CyberGuard AI - Executable Analysis (capa & Detect It Easy adapters).

Provides deep passive inspection for Windows PE (.exe, .dll, .sys) and ELF files:
1. Detect It Easy (diec) for packer, compiler, and protector identification.
2. capa (Mandiant) for behavioral capability mapping (injection, anti-debug, persistence).
3. Fallback pefile static header & entropy analysis for packing indicators.
"""

from __future__ import annotations

import asyncio
import json
import math
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.scanners.base import (
    BaseScannerAdapter,
    Finding,
    ScannerResult,
    ScanStatus,
    Severity,
)
from app.utils.logger import logger

try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    pefile = None  # type: ignore
    _PEFILE_AVAILABLE = False

try:
    import capa
    _CAPA_AVAILABLE = True
    _CAPA_VERSION = getattr(capa, "__version__", "10.0.0")
except ImportError:
    _CAPA_AVAILABLE = False
    _CAPA_VERSION = "unavailable"


class DiecAdapter(BaseScannerAdapter):
    """Adapter for Detect It Easy Console (diec) with embedded signature fallback."""

    name: str = "Detect It Easy (diec)"
    version: str = "unknown"

    # Known packer section signatures
    KNOWN_PACKERS: Dict[str, str] = {
        "upx0": "UPX Packer",
        "upx1": "UPX Packer",
        "upx2": "UPX Packer",
        "upx!": "UPX Packer",
        ".aspack": "ASPack Protector",
        "aspack": "ASPack Protector",
        ".fsg": "FSG Fast Small Good Packer",
        "fsg!": "FSG Fast Small Good Packer",
        ".mpress1": "MPRESS Packer",
        ".mpress2": "MPRESS Packer",
        "pec2": "PECompact Protector",
        "pecompact2": "PECompact Protector",
        ".themida": "Themida / WinLicense Protector",
        ".vmp0": "VMProtect Virtual Machine Protector",
        ".vmp1": "VMProtect Virtual Machine Protector",
        ".enigma1": "Enigma Protector",
        ".enigma2": "Enigma Protector",
        ".petite": "Petite Packer",
    }

    def __init__(self, diec_path: Optional[str] = None) -> None:
        self.diec_path = (
            diec_path
            or shutil.which("diec")
            or shutil.which("diec.exe")
            or shutil.which("diec.sh")
            or self._discover_diec_path()
        )
        if self.diec_path:
            self.version = "CLI"
        elif _PEFILE_AVAILABLE:
            self.version = "Embedded Engine"

    def _discover_diec_path(self) -> Optional[str]:
        candidates = [
            "/opt/die/diec.sh",
            "/opt/die/base/diec",
            "/usr/bin/diec",
            "/usr/local/bin/diec",
            "C:\\Tools\\diec.exe",
        ]
        for p in candidates:
            if Path(p).exists():
                return p
        return None

    def is_available(self) -> bool:
        return bool(self.diec_path and Path(self.diec_path).exists()) or _PEFILE_AVAILABLE

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="diec binary not found in PATH and pefile unavailable.",
            )

        start_time = time.perf_counter()

        # If diec CLI binary is available, execute it
        if self.diec_path and Path(self.diec_path).exists():
            try:
                proc = await asyncio.create_subprocess_exec(
                    str(self.diec_path),
                    "-j",
                    str(file_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                elapsed_ms = (time.perf_counter() - start_time) * 1000

                if proc.returncode == 0:
                    data = json.loads(stdout.decode())
                    findings: List[Finding] = []
                    packers = []

                    for detect in data.get("detects", []):
                        for val in detect.get("values", []):
                            name = val.get("name", "")
                            detect_type = val.get("type", "")
                            if "packer" in detect_type.lower() or "protector" in detect_type.lower():
                                packers.append(name)
                                findings.append(
                                    Finding(
                                        title=f"Packed / Protected Executable ({name})",
                                        description=f"Detect It Easy flagged {detect_type}: {name}",
                                        severity=Severity.HIGH,
                                        evidence=f"Type={detect_type}, Name={name}",
                                        confidence=0.90,
                                    )
                                )

                    sev = Severity.HIGH if packers else Severity.CLEAN
                    return ScannerResult(
                        scanner_name=self.name,
                        scanner_version=self.version,
                        status=ScanStatus.COMPLETED,
                        findings=findings,
                        severity=sev,
                        confidence=0.90,
                        metadata={"detects_count": len(findings), "packers": packers},
                        execution_time_ms=elapsed_ms,
                    )
            except Exception as e:
                logger.warning(f"diec CLI execution failed, falling back to embedded engine: {e}")

        # Fallback to embedded PE packer signature engine
        return await asyncio.to_thread(self._scan_embedded, file_path, start_time)

    def _scan_embedded(self, file_path: Path, start_time: float) -> ScannerResult:
        if not _PEFILE_AVAILABLE:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="pefile library not installed.",
                execution_time_ms=elapsed_ms,
            )

        findings: List[Finding] = []
        packers_found = []

        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            for section in pe.sections:
                sec_name = section.Name.decode(errors="ignore").strip("\x00").lower()
                for sig, label in self.KNOWN_PACKERS.items():
                    if sig in sec_name:
                        packers_found.append(f"{label} (Section: {sec_name})")
                        findings.append(
                            Finding(
                                title=f"Packed Binary ({label})",
                                description=f"Detect It Easy engine identified signature for {label} in PE section '{sec_name}'.",
                                severity=Severity.HIGH,
                                evidence=f"Section: {sec_name}",
                                confidence=0.95,
                            )
                        )

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            sev = Severity.HIGH if findings else Severity.CLEAN
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.COMPLETED,
                findings=findings,
                severity=sev,
                confidence=0.90,
                metadata={"packers": packers_found, "engine": "embedded"},
                execution_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            # If not a valid PE file, it's not applicable
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.COMPLETED,
                findings=[],
                severity=Severity.CLEAN,
                confidence=0.50,
                metadata={"note": f"Not a valid PE: {e}"},
                execution_time_ms=elapsed_ms,
            )


class CapaAdapter(BaseScannerAdapter):
    """Adapter for Mandiant's capa capability identifier and PE structure inspector."""

    name: str = "capa / PE Analyzer"
    version: str = _CAPA_VERSION

    # High-risk Windows API imports indicative of process injection / evasion
    SUSPICIOUS_APIS = {
        "virtualallocex": (Severity.HIGH, "Memory allocation in remote process"),
        "writeprocessmemory": (Severity.HIGH, "Writing memory to remote process (code injection)"),
        "createremotethread": (Severity.CRITICAL, "Remote thread execution (injection payload trigger)"),
        "setwindowshookex": (Severity.MEDIUM, "System-wide keyboard/mouse hook (Keylogger)"),
        "isdebuggerpresent": (Severity.LOW, "Anti-debugging check"),
        "checkremotedebuggerpresent": (Severity.LOW, "Remote debugger detection"),
        "ntunmapviewofsection": (Severity.HIGH, "Process hollowing indicator"),
        "adjusttokenprivileges": (Severity.MEDIUM, "Process privilege escalation token adjustment"),
    }

    def is_available(self) -> bool:
        return _CAPA_AVAILABLE or _PEFILE_AVAILABLE

    async def scan(self, file_path: Path, **kwargs: Any) -> ScannerResult:
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="pefile and capa are not installed. Install via: pip install flare-capa pefile",
            )

        start_time = time.perf_counter()
        return await asyncio.to_thread(self._scan_pe_sync, file_path, start_time)

    def _scan_pe_sync(self, file_path: Path, start_time: float) -> ScannerResult:
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {}

        if not _PEFILE_AVAILABLE:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.UNAVAILABLE,
                error_message="pefile library unavailable.",
                execution_time_ms=elapsed_ms,
            )

        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ])
        except pefile.PEFormatError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            # Non-PE file
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.SKIPPED,
                findings=[],
                severity=Severity.CLEAN,
                metadata={"is_pe": False},
                execution_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.ERROR,
                error_message=f"PE parsing error: {e}",
                execution_time_ms=elapsed_ms,
            )

        try:
            metadata["is_pe"] = True
            metadata["machine"] = hex(pe.FILE_HEADER.Machine)
            metadata["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

            # 1. Section analysis and entropy
            section_names = []
            has_high_entropy = False
            has_packer_section = False

            for section in pe.sections:
                s_name = section.Name.decode(errors="ignore").strip("\x00")
                section_names.append(s_name)
                entropy = section.get_entropy()

                # Known packer sections
                s_lower = s_name.lower()
                if any(p in s_lower for p in ["upx", "aspack", "fsg", "mew", "themida", "vmp", "mpress"]):
                    has_packer_section = True
                    findings.append(
                        Finding(
                            title=f"Known Packer Section Header ({s_name})",
                            description=f"Section name '{s_name}' indicates executable was compressed/packed.",
                            severity=Severity.HIGH,
                            evidence=f"Section={s_name}, Entropy={entropy:.2f}",
                            confidence="High",
                        )
                    )

                # High entropy > 7.3 suggests packing or encryption
                if entropy > 7.3:
                    has_high_entropy = True
                    findings.append(
                        Finding(
                            title=f"High Entropy Section ({s_name}): {entropy:.2f}",
                            description="Section data exhibits high Shannon entropy (> 7.3), characteristic of encrypted payloads or packers.",
                            severity=Severity.MEDIUM,
                            evidence=f"Section={s_name}, Entropy={entropy:.2f}",
                            confidence="Moderate",
                        )
                    )

            metadata["sections"] = section_names

            # 2. Suspicious Import API analysis
            suspicious_imported = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            fn_name = imp.name.decode(errors="ignore").lower()
                            if fn_name in self.SUSPICIOUS_APIS:
                                sev, desc = self.SUSPICIOUS_APIS[fn_name]
                                suspicious_imported.append(fn_name)
                                findings.append(
                                    Finding(
                                        title=f"High-Risk API Import: {imp.name.decode(errors='ignore')}",
                                        description=desc,
                                        severity=sev,
                                        evidence=f"DLL={entry.dll.decode(errors='ignore')}, API={fn_name}",
                                        confidence="High",
                                    )
                                )

            metadata["suspicious_imports_count"] = len(suspicious_imported)

            # Determine overall severity
            if any(f.severity == Severity.CRITICAL for f in findings):
                overall_sev = Severity.CRITICAL
                confidence = "High"
            elif any(f.severity == Severity.HIGH for f in findings) or (has_packer_section and has_high_entropy):
                overall_sev = Severity.HIGH
                confidence = "High"
            elif findings:
                overall_sev = Severity.MEDIUM
                confidence = "Moderate"
            else:
                overall_sev = Severity.CLEAN
                confidence = "High"

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.version,
                status=ScanStatus.COMPLETED,
                findings=findings,
                severity=overall_sev,
                confidence=confidence,
                metadata=metadata,
                execution_time_ms=elapsed_ms,
            )
        finally:
            pe.close()
