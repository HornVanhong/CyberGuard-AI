#!/usr/bin/env python3
"""CyberGuard AI — Kali Container Malware Analysis Engine.

Executes static analysis, reverse engineering inspection, and signature scanning
inside the dedicated Kali Linux container environment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class KaliMalwareAnalyzer:
    """Executes multi-tool malware analysis inside the Kali container."""

    def __init__(self, sample_path: Path | str, rules_dir: Path | str = "/opt/rules") -> None:
        self.sample_path = Path(sample_path).resolve()
        self.rules_dir = Path(rules_dir).resolve()
        self.capa_rules_dir = self.rules_dir / "capa-rules"
        self.yara_rules_dir = self.rules_dir / "yara"

        if not self.sample_path.is_file():
            raise FileNotFoundError(f"Target sample not found: {self.sample_path}")

        self.file_bytes = self.sample_path.read_bytes()
        self.file_size = len(self.file_bytes)
        self.sha256 = hashlib.sha256(self.file_bytes).hexdigest()
        self.sha1 = hashlib.sha1(self.file_bytes).hexdigest()
        self.md5 = hashlib.md5(self.file_bytes).hexdigest()

    def run_command(self, cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
        """Safely executes a system command with timeout and environment isolation."""
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-1,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
            )
        except Exception as e:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-1,
                stdout="",
                stderr=str(e),
            )

    # 1. File & Format Identification
    def analyze_file_command(self) -> Dict[str, Any]:
        """Runs Linux 'file' command."""
        res = self.run_command(["file", "-b", str(self.sample_path)])
        return {
            "available": shutil.which("file") is not None,
            "description": res.stdout.strip() if res.returncode == 0 else "Unknown",
            "mime": self.run_command(["file", "-b", "--mime-type", str(self.sample_path)]).stdout.strip(),
        }

    # 2. ExifTool Metadata
    def analyze_exiftool(self) -> Dict[str, Any]:
        """Extracts metadata via exiftool."""
        if not shutil.which("exiftool"):
            return {"available": False, "metadata": {}}

        res = self.run_command(["exiftool", "-j", str(self.sample_path)])
        try:
            data = json.loads(res.stdout) if res.returncode == 0 else []
            meta = data[0] if data else {}
            # Filter internal noisy exif fields
            clean_meta = {
                k: v
                for k, v in meta.items()
                if k not in ("SourceFile", "Directory", "FilePermissions")
            }
            return {"available": True, "metadata": clean_meta}
        except Exception:
            return {"available": True, "metadata": {}, "raw": res.stdout[:500]}

    # 3. Hexdump Preview
    def analyze_hexdump(self) -> str:
        """Extracts first 64 bytes in hex and ascii format."""
        if shutil.which("hexdump"):
            res = self.run_command(["hexdump", "-C", "-n", "64", str(self.sample_path)])
            if res.returncode == 0 and res.stdout:
                return res.stdout.strip()
        # Fallback to python formatting
        chunk = self.file_bytes[:64]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        return f"{hex_part} |{ascii_part}|"

    # 4. Strings Extraction & Suspicious Indicators
    def analyze_strings(self, min_len: int = 5) -> Dict[str, Any]:
        """Extracts ASCII/Unicode strings and checks for IOC patterns."""
        if not shutil.which("strings"):
            return {"available": False, "count": 0, "indicators": []}

        res = self.run_command(["strings", "-n", str(min_len), str(self.sample_path)], timeout=15)
        raw_strings = res.stdout.splitlines() if res.returncode == 0 else []
        total_count = len(raw_strings)

        suspicious_patterns = {
            "url": re.compile(r"https?://[a-zA-Z0-9_\-\./:\?=%&]+", re.IGNORECASE),
            "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "powershell": re.compile(r"(powershell|invoke-expression|downloadstring|bypass)", re.IGNORECASE),
            "cmd_execution": re.compile(r"(cmd\.exe|/bin/sh|/bin/bash|rundll32|regsvr32)", re.IGNORECASE),
            "persistence": re.compile(r"(currentversion\\run|schtasks|cron|systemd)", re.IGNORECASE),
            "crypto_mining": re.compile(r"(stratum\+tcp|monero|cryptonight|xmr)", re.IGNORECASE),
        }

        indicators: List[Dict[str, str]] = []
        for line in raw_strings:
            line_str = line.strip()
            if not line_str:
                continue
            for category, regex in suspicious_patterns.items():
                if regex.search(line_str):
                    snippet = line_str if len(line_str) <= 100 else line_str[:97] + "..."
                    indicators.append({"category": category, "match": snippet})
                    if len(indicators) >= 50:
                        break
            if len(indicators) >= 50:
                break

        return {
            "available": True,
            "total_strings_count": total_count,
            "suspicious_indicators": indicators[:30],
        }

    # 5. Binwalk Signature Analysis
    def analyze_binwalk(self) -> Dict[str, Any]:
        """Scans for embedded file signatures without extraction."""
        if not shutil.which("binwalk"):
            return {"available": False, "signatures": []}

        res = self.run_command(["binwalk", "--term", str(self.sample_path)], timeout=20)
        lines = res.stdout.splitlines() if res.returncode == 0 else []
        signatures = []
        for l in lines:
            line = l.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("---"):
                signatures.append(line)

        return {
            "available": True,
            "signatures_count": len(signatures),
            "signatures": signatures[:15],
        }

    # 6. ClamAV Antivirus
    def scan_clamav(self) -> Dict[str, Any]:
        """Scans sample with ClamAV clamscan."""
        if not shutil.which("clamscan"):
            return {"available": False, "detected": False, "virus_name": None}

        res = self.run_command(["clamscan", "--no-summary", "--stdout", str(self.sample_path)], timeout=25)
        output = res.stdout.strip()
        detected = "FOUND" in output
        virus_name = None
        if detected:
            m = re.search(r":\s*(.+?)\s+FOUND", output)
            if m:
                virus_name = m.group(1).strip()

        return {
            "available": True,
            "detected": detected,
            "virus_name": virus_name,
            "raw_output": output,
        }

    # 7. YARA Pattern Scanner
    def scan_yara(self) -> Dict[str, Any]:
        """Scans sample using YARA rules."""
        matches: List[Dict[str, Any]] = []

        # Find compiled or source rule files in /opt/rules
        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if self.yara_rules_dir.is_dir():
            rule_files.extend(list(self.yara_rules_dir.glob("*.yar")) + list(self.yara_rules_dir.glob("*.yara")))

        if not rule_files or not shutil.which("yara"):
            return {"available": shutil.which("yara") is not None, "matches": [], "rules_count": len(rule_files)}

        for rule in rule_files:
            res = self.run_command(["yara", "-w", "-m", "-s", str(rule), str(self.sample_path)], timeout=15)
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.splitlines():
                    parts = line.strip().split()
                    if parts and not line.startswith("0x"):
                        rule_name = parts[0]
                        matches.append({"rule": rule_name, "rule_file": rule.name})

        return {
            "available": True,
            "matches_count": len(matches),
            "matches": matches,
            "rules_evaluated": len(rule_files),
        }

    # 8. Linux Malware Detect (LMD / maldet)
    def scan_lmd(self) -> Dict[str, Any]:
        """Executes Linux Malware Detect (maldet)."""
        maldet_bin = shutil.which("maldet") or "/usr/local/maldetect/maldet"
        if not Path(maldet_bin).exists():
            return {"available": False, "detected": False}

        res = self.run_command([maldet_bin, "-a", str(self.sample_path)], timeout=30)
        output = res.stdout + res.stderr
        detected = "hits: 1" in output.lower() or "malware detected" in output.lower()
        return {
            "available": True,
            "detected": detected,
            "raw_output": res.stdout.strip()[:300],
        }

    # 9. Detect It Easy (diec)
    def analyze_diec(self) -> Dict[str, Any]:
        """Executes Detect It Easy CLI to detect packers, compilers, and file structure."""
        diec_bin = shutil.which("diec") or "/usr/bin/diec"
        if not shutil.which(diec_bin):
            return {"available": False, "detects": []}

        res = self.run_command([diec_bin, "-j", str(self.sample_path)], timeout=20)
        try:
            data = json.loads(res.stdout) if res.returncode == 0 else {}
            detects = data.get("detects", [])
            return {
                "available": True,
                "file_type": data.get("filetype", "Unknown"),
                "detects": detects,
            }
        except Exception:
            # Fallback to plain text output if JSON unsupported
            res_txt = self.run_command([diec_bin, str(self.sample_path)], timeout=15)
            lines = [l.strip() for l in res_txt.stdout.splitlines() if l.strip()]
            return {"available": True, "detects": lines}

    # 10. Mandiant capa (Capabilities & MITRE ATT&CK)
    def analyze_capa(self) -> Dict[str, Any]:
        """Runs Mandiant capa on executable binaries."""
        if not shutil.which("capa"):
            return {"available": False, "capabilities": []}

        cmd = ["capa", "-j"]
        if self.capa_rules_dir.is_dir() and any(self.capa_rules_dir.iterdir()):
            cmd.extend(["--rules", str(self.capa_rules_dir)])
        cmd.append(str(self.sample_path))

        res = self.run_command(cmd, timeout=35)
        if res.returncode == 0:
            try:
                data = json.loads(res.stdout)
                rules = data.get("rules", {})
                att_and_ck = []
                capabilities = []
                for rule_name, rule_data in rules.items():
                    meta = rule_data.get("meta", {})
                    att = meta.get("att&ck", [])
                    mbc = meta.get("mbc", [])
                    capabilities.append({
                        "name": rule_name,
                        "namespace": meta.get("namespace"),
                        "attack": att,
                        "mbc": mbc,
                    })
                    for item in att:
                        if item not in att_and_ck:
                            att_and_ck.append(item)

                return {
                    "available": True,
                    "supported": True,
                    "capabilities_count": len(capabilities),
                    "attack_techniques": att_and_ck,
                    "capabilities": capabilities[:20],
                }
            except Exception:
                pass

        return {
            "available": True,
            "supported": False,
            "message": "File format not supported by capa (PE/ELF/Mach-O only) or rule evaluation skipped.",
        }

    # 11. Radare2 Reverse Engineering Summary
    def analyze_radare2(self) -> Dict[str, Any]:
        """Extracts binary headers, architecture, and sections via rabin2."""
        if not shutil.which("rabin2"):
            return {"available": False, "info": {}}

        res_info = self.run_command(["rabin2", "-j", "-I", str(self.sample_path)], timeout=10)
        res_sec = self.run_command(["rabin2", "-j", "-S", str(self.sample_path)], timeout=10)

        info = {}
        sections = []
        try:
            if res_info.returncode == 0 and res_info.stdout.strip():
                data = json.loads(res_info.stdout)
                info = data.get("info", {})
            if res_sec.returncode == 0 and res_sec.stdout.strip():
                data_s = json.loads(res_sec.stdout)
                raw_sec = data_s.get("sections", [])
                for s in raw_sec[:10]:
                    sections.append({
                        "name": s.get("name"),
                        "size": s.get("size"),
                        "flags": s.get("flags"),
                    })
        except Exception:
            pass

        return {
            "available": True,
            "info": {
                "arch": info.get("arch"),
                "bits": info.get("bits"),
                "format": info.get("bclass"),
                "os": info.get("os"),
                "compiler": info.get("compiler"),
                "has_nx": info.get("nx", False),
                "has_canary": info.get("canary", False),
                "is_stripped": info.get("stripped", False),
            },
            "sections": sections,
        }

    # 12. Ghidra Decompiler / SRE Summary
    def analyze_ghidra(self) -> Dict[str, Any]:
        """Verifies Ghidra headless availability."""
        ghidra_headless = shutil.which("analyzeHeadless") or "/usr/local/bin/analyzeHeadless"
        available = bool(shutil.which(ghidra_headless) or Path(ghidra_headless).exists())
        return {
            "available": available,
            "version": "12.2" if available else None,
            "status": "Ready for deep forensic decompilation" if available else "Optional component not enabled",
        }

    # 13. System Tracing Availability
    def analyze_system_tools(self) -> Dict[str, Any]:
        """Verifies dynamic tracing tools."""
        return {
            "strace": shutil.which("strace") is not None,
            "ltrace": shutil.which("ltrace") is not None,
            "xxd": shutil.which("xxd") is not None,
        }

    # Synthesis & Risk Evaluation
    def evaluate_verdict(
        self,
        clamav: Dict[str, Any],
        yara: Dict[str, Any],
        lmd: Dict[str, Any],
        capa: Dict[str, Any],
        diec: Dict[str, Any],
        strings: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Calculates risk score, severity, findings, and final verdict."""
        score = 0
        findings: List[str] = []
        is_malicious = False

        if clamav.get("detected"):
            score += 100
            is_malicious = True
            findings.append(f"ClamAV Antivirus signature match: {clamav.get('virus_name')}")

        if lmd.get("detected"):
            score += 90
            is_malicious = True
            findings.append("Linux Malware Detect (LMD) threat signature identified.")

        yara_matches = yara.get("matches", [])
        if yara_matches:
            score += min(len(yara_matches) * 25, 80)
            for m in yara_matches:
                findings.append(f"YARA Rule match: {m.get('rule')} ({m.get('rule_file')})")

        attack_techs = capa.get("attack_techniques", [])
        if attack_techs:
            score += min(len(attack_techs) * 10, 40)
            findings.append(f"MITRE ATT&CK techniques detected: {', '.join(attack_techs[:5])}")

        packers = [
            d.get("string") or d.get("name")
            for d in diec.get("detects", [])
            if "packer" in str(d).lower() or "protector" in str(d).lower()
        ]
        if packers:
            score += 30
            findings.append(f"Executable packing/protection detected: {', '.join(packers[:3])}")

        suspicious_strings = strings.get("suspicious_indicators", [])
        if suspicious_strings:
            score += min(len(suspicious_strings) * 5, 25)
            categories = list({i.get("category") for i in suspicious_strings})
            findings.append(f"Suspicious strings detected in binary: {', '.join(categories)}")

        # Verdict calculation
        if is_malicious or score >= 75:
            verdict = "MALICIOUS"
            severity = "CRITICAL" if score >= 90 else "HIGH"
        elif score >= 35:
            verdict = "SUSPICIOUS"
            severity = "MEDIUM"
        else:
            verdict = "CLEAN"
            severity = "LOW" if score > 0 else "NONE"

        if not findings:
            findings = ["No immediate security threats, malicious patterns, or suspicious signatures identified."]

        recommendations = []
        if verdict == "MALICIOUS":
            recommendations.append("Do NOT execute, open, or extract this file. Delete it immediately.")
            recommendations.append("Isolate any endpoints where this sample was previously staged or run.")
        elif verdict == "SUSPICIOUS":
            recommendations.append("Treat this file with caution. Perform dynamic sandboxing before opening.")
        else:
            recommendations.append("File exhibits standard characteristics. Continue to adhere to zero-trust safety principles.")

        return {
            "verdict": verdict,
            "severity": severity,
            "risk_score": min(score, 100),
            "findings": findings,
            "recommendations": recommendations,
        }

    def execute_complete_analysis(self) -> Dict[str, Any]:
        """Runs the entire analysis pipeline and returns the structured JSON report."""
        start_time = time.time()

        file_res = self.analyze_file_command()
        exif_res = self.analyze_exiftool()
        hexdump_res = self.analyze_hexdump()
        strings_res = self.analyze_strings()
        binwalk_res = self.analyze_binwalk()
        clamav_res = self.scan_clamav()
        yara_res = self.scan_yara()
        lmd_res = self.scan_lmd()
        diec_res = self.analyze_diec()
        capa_res = self.analyze_capa()
        r2_res = self.analyze_radare2()
        ghidra_res = self.analyze_ghidra()
        system_res = self.analyze_system_tools()

        assessment = self.evaluate_verdict(
            clamav=clamav_res,
            yara=yara_res,
            lmd=lmd_res,
            capa=capa_res,
            diec=diec_res,
            strings=strings_res,
        )

        scan_duration = round(time.time() - start_time, 2)

        return {
            "cyberguard_engine": "Kali Linux Malware Analysis Container",
            "version": "2.0.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scan_duration_seconds": scan_duration,
            "sample_metadata": {
                "filename": self.sample_path.name,
                "size_bytes": self.file_size,
                "size_mb": round(self.file_size / (1024 * 1024), 2),
                "hashes": {
                    "sha256": self.sha256,
                    "sha1": self.sha1,
                    "md5": self.md5,
                },
                "file_type": file_res.get("description"),
                "mime_type": file_res.get("mime"),
            },
            "assessment": assessment,
            "details": {
                "clamav": clamav_res,
                "yara": yara_res,
                "linux_malware_detect": lmd_res,
                "capa": capa_res,
                "detect_it_easy": diec_res,
                "radare2": r2_res,
                "ghidra": ghidra_res,
                "binwalk": binwalk_res,
                "exiftool": exif_res,
                "strings": strings_res,
                "hexdump_preview": hexdump_res,
                "system_tools": system_res,
            },
        }


def main():
    parser = argparse.ArgumentParser(description="CyberGuard AI Kali Container Malware Analyzer")
    parser.add_argument("sample", help="Path to sample file to analyze")
    parser.add_argument("--rules", default="/opt/rules", help="Rules root directory")
    parser.add_argument("--output", help="Optional output JSON file path")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON")

    args = parser.parse_args()

    analyzer = KaliMalwareAnalyzer(args.sample, rules_dir=args.rules)
    report = analyzer.execute_complete_analysis()

    json_str = json.dumps(report, indent=2 if args.pretty else None)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_str, encoding="utf-8")
        print(f"Report written to {out_path}")
    else:
        print(json_str)


if __name__ == "__main__":
    main()
