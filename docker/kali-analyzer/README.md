# CyberGuard AI — Kali Docker Malware Analysis Engine

Dedicated, high-security Kali Linux Docker container designed for safe static malware analysis, signature detection, and reverse engineering.

---

## 1. Architecture Overview

CyberGuard AI employs a strict **Host vs. Container separation of concerns** (Zero-Trust sandbox boundary):

```text
 Telegram User
      ↓
 CyberGuard AI Backend (Kali Host)
      ↓
 File Validation & SHA-256 Calculation
      ↓
 Kali Docker Malware Analysis Container (Isolated Sandbox)
 ┌─────────────────────────────────────────────────────────────┐
 │ • ClamAV Antivirus       • YARA Signature Rules             │
 │ • Linux Malware Detect   • Mandiant capa (MITRE ATT&CK)     │
 │ • Detect It Easy (diec)  • Radare2 / rabin2 Binary SRE      │
 │ • Ghidra Decompiler      • ExifTool Metadata & Polyglots    │
 │ • file & strings         • Binwalk Firmware/Carving         │
 │ • strace & ltrace        • Safe Non-Root Execution          │
 └─────────────────────────────────────────────────────────────┘
      ↓
 Structured JSON Analysis Report
      ↓
 AI Security Assessment (Google Gemini)
      ↓
 Telegram Security Report
```

---

## 2. Host vs. Container Responsibilities

| Responsibility | Kali Host System | Kali Docker Container |
| :--- | :--- | :--- |
| **Role** | Management, Webhooks & Orchestration | Safe Malware Analysis Sandbox |
| **Software Installed** | Docker Engine, Compose, Python 3, Git | 14+ Malware Analysis & SRE Tools |
| **Network Access** | Full internet connectivity | Restricted sandbox network |
| **Sample Execution** | Never executes untrusted samples | Static analysis only, non-root user |
| **Filesystem Access** | Project codebase, DB, environment | Read-Only sample mount (`/samples:ro`) |
| **Privileges** | Standard user with docker group | `cap-drop: ALL`, `no-new-privileges` |

> [!IMPORTANT]
> **No malware analysis tools are installed directly on the Kali host.** All tools, rules, decompilers, and signature engines execute exclusively within the container to keep the host clean and immune from contamination.

---

## 3. Tool Inventory

### Malware Scanning
- **ClamAV (`clamscan`)**: Antivirus engine matching known malware, worms, and trojans.
- **YARA (`yara`)**: Custom pattern-matching rule engine evaluating rules in `/opt/rules/yara`.
- **Linux Malware Detect (`maldet`)**: R-FX Networks LMD signature engine.

### Static Analysis
- **file (`file`)**: Magic byte identification and MIME classification.
- **strings (`strings`)**: Extraction of ASCII/Unicode strings with automated IOC detection (URLs, IPs, PowerShell, commands, crypto miners).
- **Binwalk (`binwalk`)**: Firmware, archive, and embedded payload signature carving detection.
- **ExifTool (`exiftool`)**: File metadata, compiler tags, camera metadata, and polyglot detection.
- **Hexdump / xxd (`hexdump`, `xxd`)**: Binary header preview and raw offset inspection.
- **Mandiant capa (`capa`)**: Automated capability identification and MITRE ATT&CK / MBC mapping for executables.
- **Detect It Easy (`diec`)**: Heuristic packer, protector, compiler, and entropy identification.

### Reverse Engineering & Forensics
- **Radare2 (`r2`, `rabin2`)**: Binary architecture, sections, imports, exports, and headers.
- **Ghidra Headless (`analyzeHeadless`)**: Deep forensic software reverse engineering and decompilation.

### System Analysis & Supporting
- **strace & ltrace**: System call and library call inspection.
- **Python 3, pip, venv**: Isolated virtual environment (`/opt/venv`) with `yara-python`, `puremagic`, and `oletools`.

---

## 4. Container Security Controls

1. **Non-Root User**: Runs under dedicated unprivileged user `analyzer:analyzer` (UID: `10002`, GID: `10002`).
2. **Privilege Restriction**: `privileged: false`, `cap_drop: [ALL]`, and `security_opt: [no-new-privileges:true]`.
3. **Read-Only Root Filesystem**: Root filesystem is locked down read-only (`read_only: true`).
4. **Ephemeral Memory Workspaces**: `/tmp` and `/tmp/analysis` are mounted via RAM-backed `tmpfs` with `noexec` flags to prevent execution.
5. **Read-Only Sample Ingestion**: Untrusted samples are mounted as `:ro` (`/samples:ro`). The container cannot alter or delete host files.
6. **Strict Resource Quotas**: Hard CPU limits (`2.0 CPUs`), RAM limits (`3000 MB`), and process limits (`pids_limit: 150`) to defend against zip bombs and denial-of-service.
7. **No Docker Socket Access**: The Docker socket (`docker.sock`) is never mounted inside the container.

---

## 5. Build & Startup Commands

### Build Image
```bash
# From project root
docker compose -f docker/kali-analyzer/docker-compose.yml build

# Or directly with Docker CLI
docker build -f docker/kali-analyzer/Dockerfile -t cyberguard-kali-analyzer:latest .
```

### Start Persistent Daemon
```bash
docker compose -f docker/kali-analyzer/docker-compose.yml up -d
```

### Stop Container
```bash
docker compose -f docker/kali-analyzer/docker-compose.yml down
```

---

## 6. Verification & Health Checks

Run the automated verification script:

```bash
# Verify inside the container
docker compose -f docker/kali-analyzer/docker-compose.yml exec kali-analyzer check_tools.sh

# Or directly from host
bash scripts/check_tools.sh
```

Example verification output:
```text
=== 1. Malware Scanning Engines ===
  Checking ClamAV Scanner (clamscan)... ✓ Ready (ClamAV 1.4.6)
  Checking YARA Pattern Scanner (yara)... ✓ Ready (4.5.8)
  Checking Linux Malware Detect (maldet)... ✓ Ready
=== 2. Static Analysis & File Inspection ===
  Checking file utility (file)... ✓ Ready
  Checking strings utility (strings)... ✓ Ready
  Checking Detect It Easy (diec)... ✓ Ready
  Checking Mandiant capa (capa)... ✓ Ready (v10.0.0)
=== Verification Summary ===
  Total Checks: 17
  Passed:       17
  ✓ ALL REQUIRED SECURITY TOOLS ARE INSTALLED AND OPERATIONAL!
```

---

## 7. Running Malware Scans

### CLI Execution
```bash
# Run complete scan on a sample
docker compose -f docker/kali-analyzer/docker-compose.yml exec kali-analyzer \
    python3 /usr/local/bin/kali_scanner.py /samples/target_file.bin --pretty

# Or write output directly to reports directory
docker compose -f docker/kali-analyzer/docker-compose.yml exec kali-analyzer \
    python3 /usr/local/bin/kali_scanner.py /samples/target_file.bin --output /reports/scan_result.json
```

---

## 8. CyberGuard AI Integration Layer

The Python backend connects to the analysis container through [`app/services/kali_docker_service.py`](file:///d:/Personal%20Project/CyberGuard%20AI/app/services/kali_docker_service.py):

```python
from app.services.kali_docker_service import KaliDockerService

service = KaliDockerService()
result = service.scan_file("temp_uploads/incoming_sample.bin", original_filename="document.pdf.exe")

print(f"Verdict: {result.verdict}")
print(f"Severity: {result.severity}")
print(f"Findings: {result.findings}")
```

---

## 9. Troubleshooting & FAQ

### Issue: Permission denied when accessing samples
Ensure samples directory permissions allow UID `10002` to read:
```bash
chmod -R o+r docker/kali-analyzer/samples
```

### Issue: ClamAV database shows empty
Update ClamAV signatures inside container:
```bash
docker compose -f docker/kali-analyzer/docker-compose.yml exec kali-analyzer freshclam
```

### Issue: capa reports file format not supported
`capa` specializes in Windows PE, Linux ELF, and macOS Mach-O executable formats. Non-executable files (e.g. plain text or images) will be analyzed by ClamAV, YARA, ExifTool, Binwalk, and strings instead.
