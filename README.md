# 🛡️ CyberGuard AI — Hybrid Edge & Kali Docker Malware Analysis Platform

[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Tests: 117 Passed](https://img.shields.io/badge/Tests-117%20Passed-brightgreen.svg)]()
[![Sandbox: Kali Linux Rolling](https://img.shields.io/badge/Sandbox-Kali%20Linux%20Rolling-557C94.svg)]()
[![Edge: Cloudflare Workers](https://img.shields.io/badge/Edge-Cloudflare%20Workers-F38020.svg)]()
[![AI: Google Gemini](https://img.shields.io/badge/AI-Google%20Gemini-4285F4.svg)]()
[![Security: Zero--Trust Sandbox](https://img.shields.io/badge/Security-Non--Root%20%7C%20Read--Only-red.svg)]()
[![Bilingual: English & Khmer](https://img.shields.io/badge/Language-English%20%7C%20%E1%9E%97%E1%9E%BFeature-000000.svg)]()

**CyberGuard AI** is an enterprise-grade, hybrid edge malware scanning and threat intelligence platform powered by Telegram. It pairs a high-speed **Cloudflare Worker edge gateway** with an isolated **Kali Linux Docker static analysis sandbox** and **Google Gemini AI**, delivering real-time, bilingual (English & Khmer) forensic assessments without ever executing untrusted files on the host system.

---

## 🌟 Key Capabilities

### 1. Hybrid Edge-to-Sandbox Architecture
- **Cloudflare Worker Global Gateway (`worker/worker.js`)**: Edge webhook router operating across 300+ cities with sub-second response times. Handles slash commands, URL phishing inspection, and user authorization before dispatching to analysis nodes.
- **Encrypted Cloudflare Tunnel (`cloudflared`)**: Bi-directional TLS tunnel connecting Cloudflare Workers to the local Scanner API without opening router ports or exposing static public IP addresses.
- **Dedicated Kali Linux Docker Sandbox (`docker/kali-analyzer/`)**: Zero-Trust container running the official `kalilinux/kali-rolling` base with 14+ FOSS security tools, unprivileged execution (`UID 10002`), read-only rootfs, and non-executable ephemeral storage.

### 2. Multi-Engine Inspection Pipeline
- **ClamAV Antivirus Daemon (TCP/zINSTREAM)**: High-speed streaming antivirus inspection with automated signature updates (`freshclam`). Correctly distinguishes `MALWARE_DETECTED`, `CLEAN`, `UNAVAILABLE`, and `FAILED`.
- **YARA Signature Matching**: Modular rule engine for identifying webshells, obfuscated PowerShell, ransomware indicators, and weaponized macros (`rules/*.yar`).
- **Mandiant capa (1,054 rules)**: Automated binary capability identification and mapping against the **MITRE ATT&CK** matrix.
- **Detect It Easy (DIE / diec)**: Advanced compiler, packer, protector (UPX, VMProtect, Themida), and section entropy analysis.
- **NSA Ghidra Headless (v12.2) & Radare2**: Automated software reverse engineering (SRE) extracting function counts, compiler info, dangerous API cross-references (injection, memory modification), and decompiled pseudo-C code.
- **Static Format Parsers**:
  - `oletools` (`olevba`): Microsoft Office macro analysis and AutoExec trigger extraction.
  - `PDFiD`: Structural indicator scanner for `/JavaScript`, `/Launch`, `/OpenAction`, and hex obfuscation.
  - `ExifTool`: Comprehensive metadata and polyglot attack detection (PHP concealed in images).
  - `Gitleaks`: High-speed token and credential leak scanner with mandatory token redaction (`AKIA****`).
  - `Binwalk` & `hexdump` / `xxd`: Firmware header, payload carving, and raw offset inspection.
  - `strace` & `ltrace`: System call and library call inspection capabilities.

### 3. AI-Powered Security Explanations (Google Gemini)
- Structured threat analysis using schema-validated Google Gemini models (`gemini-2.5-flash` / `gemini-3-flash-preview`).
- Context-aware explanations via `/explain [scan_id]` and interactive threat Q&A via `/ask`.
- Anti-prompt-injection validation and deterministic supremacy: **AI is strictly forbidden from overriding signature or antivirus verdicts**.
- Full bilingual output in **English** and **Khmer (ភាសាខ្មែរ)**.

### 4. Privacy & Zero-Trace Guarantee
- **Zero File Persistence**: Samples are downloaded into ephemeral staging directories with guaranteed deletion in a `finally` block immediately post-scan.
- **Isolated SQLite WAL Database**: Audit trails (`scan_id`, sanitized filename, SHA-256, verdict) are partitioned per user ID with `/history` and 1-click `/cleardata` purge.
- **VirusTotal Zero-Disclosure**: Queries hash values only; raw files are never uploaded to third parties.

---

## 🏗️ Architecture & Data Flow

```text
 👤 Telegram User
      │
      ▼ (HTTPS Webhook)
 ⚡ Cloudflare Worker Gateway (worker/worker.js)
      │
      ├─► URL & Text Phishing Check ──► VirusTotal API v3 / Gemini AI
      │
      ▼ (Large File Scan via Cloudflare Tunnel)
 🌐 Encrypted Cloudflare Tunnel (cloudflared.exe)
      │
      ▼ (HTTP POST /scan :8000)
 🖥️ CyberGuard Scanner API (app/api.py)
      │
      ├─► Streaming Progress Bar to Telegram (⚡ 10% ──► 40% ──► 70%)
      ├─► SHA-256 / SHA-1 / MD5 Cryptographic Hashing
      ├─► Magic Byte & Disguised Extension Verification
      │
      ▼ (Read-Only Mount: /samples/sample.bin:ro)
 🛡️ Kali Linux Docker Analysis Sandbox (docker/kali-analyzer/)
 ┌────────────────────────────────────────────────────────────────────────┐
 │  • ClamAV Antivirus (clamscan)     • YARA Pattern Matcher (yara)       │
 │  • Linux Malware Detect (maldet)   • Mandiant capa (MITRE ATT&CK)      │
 │  • Detect It Easy (diec)           • Radare2 & rabin2 Binary Inspector │
 │  • NSA Ghidra Headless SRE         • ExifTool Metadata & Polyglot      │
 │  • file, strings & binwalk         • strace & ltrace System Tracing    │
 └────────────────────────────────────────────────────────────────────────┘
      │
      ▼ (Structured JSON Analysis Report)
 ⚖️ Risk Engine Correlation (Objective Scoring & Verdict: CLEAN / SUSPICIOUS / MALICIOUS)
      │
      ▼ (Findings & Indicators)
 🤖 Google Gemini AI (Bilingual Threat Explanation & Defensive Steps)
      │
      ▼
 📱 Final Security Report Delivered to Telegram Chat
      │
      ▼
 🧹 Guaranteed File Unlink & Sandbox Cleanup (Zero-Persistence)
```

---

## 📁 Repository Directory Structure

```text
CyberGuard-AI/
├── app/
│   ├── api.py                    # Scanner API HTTP/JSON server & background orchestrator
│   ├── bot.py                    # Standalone Telegram polling bot application
│   ├── config.py                 # Pydantic v2 Settings & environment validator
│   ├── i18n.py                   # Bilingual localization dictionary (EN & KM)
│   ├── handlers/                 # Telegram command & interaction handlers
│   │   ├── start.py              # /start handler & persistent quick-reply keyboard
│   │   ├── scan.py               # Asynchronous file ingestion & pipeline dispatch
│   │   ├── ask.py                # /ask AI assistant with automatic scan context
│   │   ├── explain.py            # /explain [scan_id] deep dive analysis
│   │   ├── report.py             # /report [scan_id] downloadable audit document
│   │   ├── status.py             # Multi-engine diagnostic health checker
│   │   ├── history.py            # /history and /cleardata audit handlers
│   │   ├── privacy.py            # /privacy data retention notice
│   │   └── callbacks.py          # Interactive inline keyboard callback router
│   ├── scanners/                 # Modular tool adapters
│   │   ├── base.py               # BaseScannerAdapter & ScannerResult dataclass
│   │   ├── orchestrator.py       # Selective MIME-type routing orchestrator
│   │   ├── clamav_scanner.py     # Asynchronous TCP streaming ClamAV client
│   │   ├── yara_scanner.py       # Modular YARA signature evaluator
│   │   ├── file_analyzer.py      # Magic byte validator & extension mismatch detector
│   │   ├── oletools_analyzer.py  # Office VBA macro & autoexec extractor
│   │   ├── pdfid_analyzer.py     # PDF structural element & exploit checker
│   │   ├── exiftool_analyzer.py  # ExifTool metadata & polyglot webshell scanner
│   │   ├── executable_analyzer.py# capa & Detect It Easy (DIE) PE/ELF analyzers
│   │   ├── gitleaks_analyzer.py  # Credential & token leak detector (with masking)
│   │   ├── ghidra_analyzer.py    # Headless Ghidra decompilation & API xref extractor
│   │   ├── script_analyzer.py    # Static script analyzer (PS1, Bash, JS, PHP)
│   │   ├── pdf_analyzer.py       # PDF stream and payload inspector
│   │   └── archive_analyzer.py   # Zip bomb and path traversal archive inspector
│   ├── services/                 # Business logic and integrations
│   │   ├── kali_docker_service.py# Kali container staging, execution & JSON parser
│   │   ├── file_service.py       # Ephemeral sandbox creation and cleanup
│   │   ├── hashing_service.py    # Streaming cryptographic hash calculator
│   │   ├── virustotal_service.py # VirusTotal v3 API hash lookup with memory cache
│   │   ├── ai_service.py         # Google Gemini structured security analysis
│   │   └── report_service.py     # Telegram message card & keyboard formatter
│   ├── security/                 # Risk and perimeter defense
│   │   ├── risk_engine.py        # Multi-engine verdict and severity correlator
│   │   ├── validation.py         # Filename sanitization and path traversal guard
│   │   ├── rate_limiter.py       # Sliding-window token bucket rate limiter
│   │   └── endpoint_protection.py# Host Defender/AV quarantine interceptor
│   ├── database/                 # Audit persistence
│   │   ├── models.py             # Audit log dataclasses
│   │   └── repository.py         # SQLite WAL repository with per-user data isolation
│   └── utils/
│       └── logger.py             # Redaction logger (masks tokens and credentials)
├── docker/
│   └── kali-analyzer/            # Dedicated Kali Linux Analysis Sandbox
│       ├── Dockerfile            # Hardened Kali rolling container definition
│       ├── docker-compose.yml    # Sandboxed service with non-root & resource quotas
│       ├── kali_scanner.py       # Multi-engine containerized CLI scanner
│       ├── entrypoint.sh         # Ephemeral workspace permissions initializer
│       ├── .dockerignore
│       ├── .env.example
│       └── README.md             # Dedicated container architecture & tool guide
├── worker/
│   ├── worker.js                 # Cloudflare Worker edge webhook gateway
│   └── wrangler.toml             # Cloudflare Workers deployment configuration
├── rules/                        # Modular YARA signature rule sets
│   ├── webshells.yar             # PHP/ASP webshell and backdoor patterns
│   ├── malicious_scripts.yar     # Suspicious PowerShell, Bash & downloaders
│   ├── suspicious_pe.yar         # Packer markers & ransomware signatures
│   ├── suspicious_office.yar     # Weaponized VBA macro signatures
│   └── test_fixtures.yar         # Benign test signatures for automated tests
├── scripts/
│   ├── check_tools.sh            # 20-point container tool verification script
│   └── update_clamav.sh          # Automated ClamAV signature update script
├── tests/                        # Comprehensive test suite (117 tests passing)
│   ├── test_kali_docker.py       # Container integration and staging tests
│   ├── test_adapters.py          # Modular scanner adapter unit tests
│   ├── test_ai_service.py        # Gemini prompt injection and schema tests
│   ├── test_clamav_scanner.py    # ClamAV streaming protocol tests
│   ├── test_yara_scanner.py      # YARA match and compilation tests
│   ├── test_risk_engine.py       # Multi-engine correlation tests
│   └── ...                       # Additional unit & integration tests
├── docker-compose.yml            # Root Compose defining bot, ClamAV, and kali-analyzer
├── Dockerfile                    # Production bot container definition
├── requirements.txt              # Production Python dependencies
├── pyproject.toml                # pytest configuration and metadata
└── README.md
```

---

## 🧰 Verified Tool Inventory (Container)

Running `scripts/check_tools.sh` verifies all **20/20 checks passing**:

| Tool | Executable | Version | Category | Role |
| :--- | :--- | :--- | :--- | :--- |
| **ClamAV** | `clamscan` | 1.4.6 | Malware Scanning | Signature detection for trojans, worms, viruses |
| **Freshclam** | `freshclam` | 1.4.6 | Malware Scanning | Automated antivirus signature definition updates |
| **YARA** | `yara` | 4.5.8 | Malware Scanning | Modular pattern matching across custom rulesets |
| **Linux Malware Detect** | `maldet` | 1.6.6 | Malware Scanning | R-FX Networks malware and webshell signatures |
| **file** | `file` | 5.47 | Static Analysis | Magic byte identification and MIME classification |
| **strings** | `strings` | 2.47 | Static Analysis | ASCII/Unicode extraction & automated IOC detection |
| **Binwalk** | `binwalk` | 2.4.3 | Static Analysis | Firmware header and embedded signature carving |
| **ExifTool** | `exiftool` | 13.55 | Static Analysis | Metadata leakage and polyglot attack detection |
| **Hexdump / xxd** | `hexdump`, `xxd` | 2.42.4 | Static Analysis | Raw byte offset preview and binary structure |
| **Detect It Easy** | `diec` | 3.21 | Static Analysis | Packer (UPX, Themida), compiler, and entropy |
| **Mandiant capa** | `capa` | 10.0.0 | Static Analysis | 1,054 rules mapped to **MITRE ATT&CK** |
| **Radare2** | `r2`, `rabin2` | 6.0.5 | Reverse Eng. | Binary architecture, sections, imports, and exports |
| **NSA Ghidra SRE** | `analyzeHeadless`| 12.2 | Reverse Eng. | Decompilation to pseudo-C and API cross-references |
| **strace** | `strace` | 7.2 | System Forensics | Linux system call monitoring |
| **ltrace** | `ltrace` | 0.7.91 | System Forensics | Dynamic library call monitoring |
| **Python 3 Runtime** | `python3` | 3.14.8 | Supporting | Container scripting environment |
| **yara-python** | Native Binding | 4.5.8 | Supporting | High-speed C-binding for YARA |
| **Isolated Virtualenv** | `/opt/venv` | — | Supporting | Host for `puremagic` and `oletools` |

---

## 🔒 Container Security & Hardening Controls

To prevent malicious execution and host escape, the Kali Docker container enforces strict defenses:

1. **Unprivileged Non-Root User**: Runs strictly under `analyzer:analyzer` (`UID: 10002`, `GID: 10002`).
2. **Linux Capability Stripping**: All kernel capabilities are dropped (`cap_drop: ALL`).
3. **Privilege Escalation Prevention**: `security_opt: [no-new-privileges:true]` and `privileged: false`.
4. **Locked Read-Only Root Filesystem**: `read_only: true` prevents malware from tampering with system files.
5. **Read-Only Sample Mount**: Suspicious samples are mounted strictly as `:ro` (`/samples:ro`).
6. **Execution-Blocked Scratch Workspaces**: Ephemeral workspace `/tmp/analysis` is mounted as RAM-backed `tmpfs` with `noexec,nosuid` flags.
7. **Strict Resource Hardening**:
   - CPU Quota: Max `2.0 CPUs`
   - Memory Quota: Max `3000 MB`
   - PID Quota: Max `150 PIDs` (prevents fork bombs and archive decompression exhaustion)
8. **Network Isolation**: Placed on an internal sandbox bridge network with no inbound ingress.
9. **No Docker Socket Exposure**: The host Docker socket (`docker.sock`) is never mounted.

---

## ⚙️ Environment Configuration

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

| Variable | Type | Default | Description |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | string | *required* | Telegram bot token from [@BotFather](https://t.me/BotFather) |
| `ALLOWED_USER_IDS` | list[int] | `[]` | Authorized Telegram User IDs (empty allows all users) |
| `MAX_FILE_SIZE_BYTES` | int | `20971520` (20 MB)| Maximum upload threshold (Telegram Bot API limit) |
| `CLAMAV_ENABLED` | bool | `true` | Enable ClamAV antivirus scanning |
| `CLAMAV_HOST` | string | `127.0.0.1` | ClamAV host (`clamav` when running via Docker Compose) |
| `CLAMAV_PORT` | int | `3310` | ClamAV TCP daemon port |
| `CLAMAV_TIMEOUT` | float | `30.0` | ClamAV scan timeout in seconds |
| `YARA_ENABLED` | bool | `true` | Enable modular YARA signature inspection |
| `YARA_RULES_DIR` | path | `rules` | Path to directory containing `.yar` rule files |
| `VIRUSTOTAL_ENABLED` | bool | `false` | Enable VirusTotal cryptographic hash lookup |
| `VIRUSTOTAL_API_KEY` | string | `""` | VirusTotal API v3 key |
| `VIRUSTOTAL_CACHE_TTL` | int | `3600` | In-memory cache time-to-live in seconds |
| `GEMINI_ENABLED` | bool | `true` | Enable Google Gemini security assessment |
| `GEMINI_API_KEY` | string | *required* | Google Gemini API key |
| `GEMINI_MODEL` | string | `gemini-2.5-flash` | Gemini model ID (`gemini-2.5-flash`, `gemini-1.5-pro`) |
| `RATE_LIMIT_REQUESTS` | int | `5` | Scans allowed per user within the sliding window |
| `RATE_LIMIT_WINDOW_SECONDS` | int | `60` | Sliding window duration in seconds |
| `DEFAULT_LANGUAGE` | string | `en` | Default UI localization (`en` or `km`) |
| `SCAN_RETENTION_DAYS` | int | `30` | SQLite audit history retention duration |
| `LOG_LEVEL` | string | `INFO` | Console and file log verbosity |

---

## 🚀 Deployment Options

### Option 1: Hybrid Edge Architecture (Production Recommended)

Combines the Cloudflare Worker global gateway with the local Scanner API and Kali Docker sandbox.

#### 1. Start the Kali Linux Analysis Sandbox:
```bash
docker compose -f docker/kali-analyzer/docker-compose.yml up -d
```

#### 2. Start the Local Scanner API:
```bash
.venv\Scripts\python -m app.api
# (Linux: python3 -m app.api)
```

#### 3. Establish the Secure Cloudflare Tunnel:
```bash
cloudflared tunnel --url http://localhost:8000
```

#### 4. Deploy the Cloudflare Worker:
```bash
cd worker
npm install -g wrangler
wrangler deploy
```

---

### Option 2: Docker Compose (All-in-One Deployment)

Runs `cyberguard-bot`, `clamav`, and `kali-analyzer` together in an isolated bridge network:

```bash
docker compose up -d --build
```

- Verify containers:
  ```bash
  docker compose ps
  ```
- View real-time logs:
  ```bash
  docker compose logs -f
  ```

---

### Option 3: Local Development (Python 3.12+)

Direct development and testing using local Python virtual environment:

```bash
# 1. Setup virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run full automated test suite
pytest -v

# 4. Run standalone polling bot
python -m app.bot
```

---

## 🧪 Automated Test Suite (117 Tests Passing)

The project includes 117 automated unit and integration tests with **100% pass rate**:

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\Personal Project\CyberGuard AI
configfile: pyproject.toml
plugins: anyio-4.15.1, asyncio-1.4.1
asyncio: mode=Mode.AUTO, debug=False
collected 117 items

tests/test_adapters.py ..................                                [ 15%]
tests/test_ai_service.py ..........                                      [ 23%]
tests/test_archive_analyzer.py .....                                     [ 28%]
tests/test_bot_handlers.py ........                                      [ 35%]
tests/test_clamav_scanner.py .......                                     [ 41%]
tests/test_database.py ...                                               [ 43%]
tests/test_file_analyzer.py .....                                        [ 47%]
tests/test_hashing.py ...                                                [ 50%]
tests/test_kali_docker.py .....                                          [ 54%]
tests/test_office_analyzer.py ...                                        [ 57%]
tests/test_pdf_analyzer.py ...                                           [ 59%]
tests/test_rate_limiter.py ...                                           [ 62%]
tests/test_report_service.py ....                                        [ 65%]
tests/test_risk_engine.py .....                                          [ 70%]
tests/test_script_analyzer.py .....                                      [ 74%]
tests/test_validation_and_cleanup.py .......                             [ 80%]
tests/test_virustotal_service.py .....                                   [ 84%]
tests/test_yara_scanner.py ....                                          [ 88%]
tests/test_url_analyzer.py ..............                                [100%]

============================= 117 passed in 54.68s ============================
```

---

## 🛠️ Verification & CLI Commands

### 1. Run Container Tool Verification:
```bash
docker compose -f docker/kali-analyzer/docker-compose.yml exec kali-analyzer check_tools.sh
```

### 2. Run Container CLI Scan on a Sample:
```bash
docker compose -f docker/kali-analyzer/docker-compose.yml exec kali-analyzer \
  python3 /usr/local/bin/kali_scanner.py /samples/sample.bin --pretty
```

### 3. Update ClamAV Signatures:
```bash
bash scripts/update_clamav.sh
```

---

## ⚠️ Security Principles & Limitations

1. **Zero-Execution Static Sandbox**: CyberGuard AI is built strictly for passive static analysis, disassembly, and signature matching. It **never executes or detonates untrusted binaries**.
2. **Deterministic Primacy**: Antivirus and YARA detections take strict precedence over AI interpretations. AI cannot alter a confirmed malware verdict.
3. **Telegram 20 MB Threshold**: Telegram bots receive files up to 20 MB via the standard Telegram Bot API. To scan larger archives (up to 2 GB), deploy a local Telegram Bot API server.
4. **Defense in Depth**: A `CLEAN` verdict signifies that no known malicious patterns or suspicious indicators were detected by the enabled engines. Always adhere to zero-trust principles when handling untrusted files.

---

## 📄 License & Attribution

This project is licensed under the [Apache License 2.0](LICENSE).
YARA rules in `rules/` are attributed in [`rules/README.md`](rules/README.md).
Tool integrations utilize official distributions of ClamAV, Mandiant capa, Detect It Easy, NSA Ghidra, Radare2, ExifTool, Binwalk, and Gitleaks.
