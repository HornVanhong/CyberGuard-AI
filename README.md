# 🛡️ CyberGuard AI — Telegram Malware Scanner Bot

[![Python 3.12](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Tests: 80 Passed](https://img.shields.io/badge/Tests-80%20Passed-brightgreen.svg)]()
[![Security: Isolated Container](https://img.shields.io/badge/Security-Non--Root%20%7C%20Read--Only-red.svg)]()

**CyberGuard AI** is a production-grade, secure, multi-engine Telegram bot designed to inspect uploaded files for malware, viruses, suspicious payloads, malicious scripts, phishing indicators, and dangerous macros **without ever executing untrusted files on the host system**.

---

## 🌟 Key Features

### 1. Multi-Engine Security Pipeline
- **ClamAV Antivirus Daemon (TCP/zINSTREAM)**: High-speed streaming antivirus inspection without host disk sharing. Correctly distinguishes `MALWARE_DETECTED`, `CLEAN`, `UNAVAILABLE`, `FAILED`, and `INCONCLUSIVE` (network or service errors are never masked as clean).
- **YARA Signature Matching**: Modular rule sets for identifying webshells, obfuscated PowerShell, ransomware indicators, and weaponized documents.
- **Magic Byte & Extension Mismatch Detection**: Validates true file signatures (`MZ`, `PK`, `%PDF`, `ELF`, etc.) against declared extensions to detect disguised threats (e.g. an executable disguised as `.pdf` or an archive disguised as `.jpg`).
- **Safe Static Script Analysis**: Inspects scripts (`.py`, `.js`, `.php`, `.ps1`, `.bat`, `.sh`, `.vbs`) for obfuscated Base64, reverse shells, download-and-execute triggers, credential dumping (`mimikatz`), persistence hooks, and hardcoded API tokens without executing them.
- **Static PDF Structure Analysis**: Identifies embedded JavaScript (`/JavaScript`, `/JS`), launch actions (`/Launch`), automatic triggers (`/OpenAction`, `/AA`), embedded file attachments, and hexadecimal name obfuscation.
- **Decompression Bomb & Safe Archive Inspection**: Inspects ZIP, TAR, and GZ archives strictly in memory. Enforces 100:1 ratio limits (Zip Bomb defense), max entry limits, max uncompressed byte limits, double-extension trick detection (`document.pdf.exe`), and strict path traversal protection (`../`, absolute paths, symlinks).
- **Microsoft Office Analysis**: Inspects modern OpenXML packages (`.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`) and legacy OLE files. Detects hidden VBA macros in declared macro-free files, auto-exec hooks (`AutoOpen`, `Workbook_Open`), embedded OLE objects, and suspicious system API invocations (`Shell`, `WScript.Shell`).
- **VirusTotal Threat Intelligence (Optional)**: Performs zero-disclosure cryptographic SHA-256 hash queries. Respects rate limits, includes local TTL caching, and **never uploads raw files without explicit user consent**.
- **AI-Powered Explanations & Assistant (Google Gemini via official `google-genai` SDK)**:
  - Generates schema-validated structured security analysis (`SecurityExplanationSchema`: indicators, severity, confidence, defensive actions, uncertainties, and scope).
  - Interactive cybersecurity assistant via `/ask` with automatic latest scan context awareness.
  - Deep-dive scan explanations on demand via `/explain [scan_id]`.
  - Exportable, downloadable plain-text forensic scan reports via `/report [scan_id]`.
  - Bilingual support in **English** and **Khmer (ភាសាខ្មែរ)**.
  - Implements anti-prompt-injection safeguards (input truncation, schema enforcement) and **strictly prevents AI from overturning deterministic scanner verdicts**.

### 2. Privacy & User Experience
- **Zero File Persistence**: Uploads are downloaded into an isolated sandbox directory (`temp_uploads/{scan_id}`) and guaranteed deleted in a `finally` block immediately upon scan completion.
- **Audit Data Isolation**: SQLite audit records (`scan_id`, `user_id`, sanitized filename, size, SHA-256, verdict) are strictly isolated per user. Users can inspect their history via `/history` and completely purge their records via `/cleardata`.
- **Bilingual Interface**: Native support for **English** and **Khmer (ភាសាខ្មែរ)** with instant in-chat language switching.
- **Sliding Window Rate Limiting**: In-memory token bucket limiter preventing spam and denial of service per user ID.
- **Sensitive Log Redaction**: Filters mask bot tokens, API keys, and sensitive tokens from console and container logs.

---

## 📁 Project Folder Structure

```
cyberguard-ai/
├── app/
│   ├── __init__.py
│   ├── config.py                 # Pydantic Settings & environment config
│   ├── bot.py                    # Application builder & lifecycle entry point
│   ├── i18n.py                   # Bilingual localization (English & Khmer)
│   ├── handlers/
│   │   ├── __init__.py
│   │   ├── start.py              # /start handler & welcome quick-action keyboard
│   │   ├── help.py               # /help guide & risk explanation
│   │   ├── scan.py               # Full asynchronous file scanning pipeline
│   │   ├── ask.py                # /ask AI cybersecurity assistant (with scan context)
│   │   ├── explain.py            # /explain [scan_id] deep-dive analysis
│   │   ├── report.py             # /report [scan_id] downloadable text report
│   │   ├── status.py             # Engine health, Gemini & signature status
│   │   ├── history.py            # /history and /cleardata handlers
│   │   ├── privacy.py            # /privacy transparency notice
│   │   └── callbacks.py          # Inline button callback router
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── clamav_scanner.py     # Asynchronous ClamAV TCP client
│   │   ├── yara_scanner.py       # Modular YARA signature compiler & runner
│   │   ├── file_analyzer.py      # Magic byte validator & extension mismatch
│   │   ├── script_analyzer.py    # Static script analyzer (PS, Bash, JS, PHP)
│   │   ├── pdf_analyzer.py       # Static PDF object & stream analyzer
│   │   ├── archive_analyzer.py   # Zip bomb & traversal archive inspector
│   │   └── office_analyzer.py    # VBA macro & OLE inspector
│   ├── services/
│   │   ├── __init__.py
│   │   ├── file_service.py       # Sandbox creation & guaranteed cleanup
│   │   ├── hashing_service.py    # Streaming SHA-256/SHA-1/MD5 calculator
│   │   ├── virustotal_service.py # VirusTotal API v3 hash lookup & cache
│   │   ├── ai_service.py         # Google Gemini security explainer
│   │   └── report_service.py     # Telegram report & keyboard generator
│   ├── security/
│   │   ├── __init__.py
│   │   ├── risk_engine.py        # Multi-engine score & verdict correlator
│   │   ├── validation.py         # Filename sanitization & path bounds check
│   │   └── rate_limiter.py       # Sliding window rate limiter
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py             # SQLite dataclass audit models
│   │   └── repository.py         # Isolated query repository with WAL mode
│   └── utils/
│       ├── __init__.py
│       └── logger.py             # Sensitive token redaction logger
├── rules/
│   ├── README.md                 # Rules attribution and licensing
│   ├── webshells.yar             # PHP webshells and backdoors
│   ├── malicious_scripts.yar     # Suspicious PowerShell & reverse shells
│   ├── suspicious_pe.yar         # UPX packers & ransomware indicators
│   ├── suspicious_office.yar     # Weaponized VBA macro signatures
│   └── test_fixtures.yar         # Synthetic test fixture rules
├── tests/
│   ├── conftest.py               # Temporary directory & database fixtures
│   ├── test_hashing.py           # Cryptographic hash tests
│   ├── test_file_analyzer.py     # Format & mismatch tests
│   ├── test_clamav_scanner.py    # ClamAV streaming protocol tests
│   ├── test_yara_scanner.py      # YARA match & compilation tests
│   ├── test_script_analyzer.py   # Script static detection tests
│   ├── test_pdf_analyzer.py      # PDF embedded script tests
│   ├── test_archive_analyzer.py  # Zip bomb & path traversal tests
│   ├── test_office_analyzer.py   # Office macro & disguise tests
│   ├── test_virustotal_service.py# VirusTotal quota, cache, and error tests
│   ├── test_risk_engine.py       # Scoring, deduplication, and verdicts
│   ├── test_rate_limiter.py      # User rate limiting tests
│   ├── test_database.py          # Isolation & data erasure tests
│   ├── test_validation_and_cleanup.py # Path traversal & cleanup tests
│   ├── test_ai_service.py        # Prompt injection & AI failure tests
│   ├── test_report_service.py    # Bilingual report layout tests
│   └── test_bot_handlers.py      # Telegram command handler tests
├── scripts/
│   └── update_clamav.sh          # Script to update ClamAV virus signatures
├── .env.example                  # Environment configuration template
├── .gitignore
├── Dockerfile                    # Non-root multi-stage container
├── docker-compose.yml            # Isolated deployment with ClamAV daemon
├── requirements.txt              # Production dependencies
├── pyproject.toml                # Project packaging & pytest config
└── README.md
```

---

## ⚙️ Environment Configuration

Create a `.env` file in the root directory based on `.env.example`:

```bash
cp .env.example .env
```

| Variable | Type | Default | Description |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | string | *required* | Telegram bot token from [@BotFather](https://t.me/BotFather) |
| `ALLOWED_USER_IDS` | list[int] | `[]` | Authorized Telegram User IDs (empty allows all users) |
| `MAX_FILE_SIZE_BYTES`| int | `20971520` (20 MB) | Maximum upload size (Telegram bot API max is 20MB) |
| `CLAMAV_ENABLED` | bool | `true` | Enable ClamAV antivirus scanning |
| `CLAMAV_HOST` | string | `127.0.0.1` | ClamAV daemon hostname (`clamav` in Docker Compose) |
| `CLAMAV_PORT` | int | `3310` | ClamAV TCP port |
| `CLAMAV_TIMEOUT` | float | `30.0` | ClamAV scan timeout in seconds |
| `YARA_ENABLED` | bool | `true` | Enable YARA signature inspection |
| `YARA_RULES_DIR` | path | `rules` | Path to directory containing `.yar` files |
| `VIRUSTOTAL_ENABLED`| bool | `false` | Enable VirusTotal threat intelligence lookup |
| `VIRUSTOTAL_API_KEY`| string | `""` | VirusTotal API v3 key |
| `VIRUSTOTAL_CACHE_TTL`| int | `3600` | In-memory cache time-to-live in seconds |
| `GEMINI_ENABLED` / `AI_ENABLED` | bool | `false` | Enable Google Gemini security explanations & assistant |
| `GEMINI_API_KEY` | string | `""` | Google Gemini API key (via official `google-genai` SDK) |
| `GEMINI_MODEL` | string | `gemini-2.5-flash`| Gemini model identifier (e.g. `gemini-2.5-flash`, `gemini-1.5-pro`) |
| `GEMINI_TIMEOUT` / `AI_TIMEOUT` | float | `30.0` | Request timeout in seconds for Gemini API calls |
| `GEMINI_MAX_OUTPUT_TOKENS` | int | `1024` | Maximum output tokens generated per request |
| `RATE_LIMIT_REQUESTS`| int | `5` | Maximum scans allowed per user in the time window |
| `RATE_LIMIT_WINDOW_SECONDS`| int | `60` | Time window in seconds |
| `DEFAULT_LANGUAGE` | string | `en` | Default UI language (`en` or `km`) |
| `SCAN_RETENTION_DAYS`| int | `30` | Audit history retention period in days |
| `LOG_LEVEL` | string | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## 🤖 Telegram Bot Setup Instructions

1. Open Telegram and search for [@BotFather](https://t.me/BotFather).
2. Send `/newbot` and follow the prompts to choose a bot name and username (e.g., `CyberGuardMalwareBot`).
3. Copy the HTTP API token provided by BotFather.
4. Set the bot commands in BotFather by sending `/setcommands` and pasting:
   ```text
   start - Introduce the bot and quick actions
   scan - Prompt to upload a file for analysis
   ask - Ask cybersecurity questions (with latest scan context)
   explain - Get AI deep-dive explanation for a scan ID
   report - Download plain-text audit report for a scan ID
   cancel - Cancel active question or session
   status - Check scanning engine health, Gemini & signatures
   history - View your recent scan records
   cleardata - Permanently erase your scan history
   privacy - Review data retention and privacy policies
   help - Explain commands and risk levels
   ```
5. Paste the token into your `.env` file under `TELEGRAM_BOT_TOKEN`.

---

## 🚀 Installation & Running

### Option 1: Local Development (Python 3.12+)

1. **Clone and enter repository:**
   ```bash
   git clone <repo-url> cyberguard-ai
   cd cyberguard-ai
   ```

2. **Create and activate virtual environment:**
   ```bash
   # Linux/macOS
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows (PowerShell)
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the automated test suite:**
   ```bash
   pytest -v
   ```

5. **Start the bot:**
   ```bash
   python -m app.bot
   ```

*(Note: If ClamAV daemon is not running locally, the bot starts cleanly and reports ClamAV as unavailable without crashing).*

---

### Option 2: Production Deployment with Docker Compose (Recommended)

Docker Compose deploys the complete architecture in isolated containers:
- **`cyberguard-bot`**: Runs as a non-privileged user (`cyberguard`, UID 10001) with a **read-only root filesystem**, all Linux capabilities dropped (`cap_drop: ALL`), `no-new-privileges: true`, resource limits, and an isolated `tmpfs` sandbox.
- **`clamav`**: Official ClamAV daemon with automated `freshclam` signature definition updates on an internal Docker bridge network.

1. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env and paste your TELEGRAM_BOT_TOKEN
   ```

2. **Build and launch containers:**
   ```bash
   docker compose up -d --build
   ```

3. **Verify status and logs:**
   ```bash
   docker compose ps
   docker compose logs -f cyberguard-bot
   ```

4. **Update ClamAV signatures inside container:**
   ```bash
   bash scripts/update_clamav.sh
   ```

---

## 🧪 Automated Test Results

The automated test suite covers all 17 required scenarios:
- Cryptographic hash calculations (SHA-256, SHA-1, MD5)
- Magic byte identification and extension mismatch masquerading
- ClamAV streaming protocol (`OK`, `FOUND`, `ERROR`, and offline resilience)
- YARA compilation and pattern matching against synthetic harmless fixtures
- Static script inspection (PowerShell, Bash, reverse shells, Base64 embedded PEs)
- PDF static inspection (JavaScript, `/Launch`, `/OpenAction`, name obfuscation)
- Safe archive analysis (Zip bomb ratio, entry counts, path traversal `../`, symlinks)
- Office analysis (hidden macros, auto-exec routines, shell APIs)
- VirusTotal error handling (200, 404, 429, timeouts, caching)
- Risk Engine scoring, deduplication, and unavailable scanner handling
- Sliding window rate limiting
- Telegram authorization whitelist
- SQLite database user data isolation and `/cleardata` erasure
- Sandbox creation and guaranteed post-scan cleanup
- AI service structured schema validation (`google-genai`), prompt injection defense, quota (429) & timeout resilience, and general/scan-context Q&A in English and Khmer
- Telegram handlers for `/start`, `/scan`, `/ask`, `/explain`, `/report`, `/cancel`, `/status`, `/history`, and `/cleardata`

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\Personal Project\CyberGuard AI
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1, asyncio-1.4.1
asyncio: mode=Mode.AUTO, debug=False
collected 80 items

tests\test_ai_service.py ..........                                      [ 12%]
tests\test_archive_analyzer.py .....                                     [ 18%]
tests\test_bot_handlers.py ........                                      [ 28%]
tests\test_clamav_scanner.py .......                                     [ 37%]
tests\test_database.py ...                                               [ 41%]
tests\test_file_analyzer.py .....                                        [ 47%]
tests\test_hashing.py ...                                                [ 51%]
tests\test_office_analyzer.py ...                                        [ 55%]
tests\test_pdf_analyzer.py ...                                           [ 58%]
tests\test_rate_limiter.py ...                                           [ 62%]
tests\test_report_service.py ....                                        [ 67%]
tests\test_risk_engine.py .....                                          [ 73%]
tests\test_script_analyzer.py .....                                      [ 80%]
tests\test_validation_and_cleanup.py .......                             [ 88%]
tests\test_virustotal_service.py .....                                   [ 95%]
tests\test_yara_scanner.py ....                                          [100%]

============================= 80 passed in 14.76s =============================
```

---

## 🔒 Security Architecture & Isolation Model

```
                    ┌─────────────────────────┐
                    │   Telegram Bot Client   │
                    └────────────┬────────────┘
                                 │ Document Upload
                                 ▼
                    ┌─────────────────────────┐
                    │  1. Rate Limit & Auth   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ 2. Pre-Download Validate│ (Reject > 20MB)
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  3. Isolated Sandbox    │ (tmpfs / 0o700 / unique UUID)
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┼────────────────────────┐
         ▼                       ▼                        ▼
  ┌───────────────┐      ┌───────────────┐       ┌────────────────┐
  │ 4. SHA-256    │      │ 5. File Magic │       │ 6. ClamAV TCP  │
  │    Hashing    │      │    Mismatch   │       │    (Streaming) │
  └───────────────┘      └───────────────┘       └────────────────┘
         │                       │                        │
         └───────────────────────┼────────────────────────┘
                                 │
         ┌───────────────────────┼────────────────────────┐
         ▼                       ▼                        ▼
  ┌───────────────┐      ┌───────────────┐       ┌────────────────┐
  │ 7. YARA Rules │      │ 8. Static AST │       │ 9. VirusTotal  │
  │    Compiler   │      │    (PDF/Doc/  │       │    (Hash Only  │
  │               │      │     Script)   │       │     Cached)    │
  └───────────────┘      └───────────────┘       └────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ 10. Risk Engine         │
                    │   - Objective Scoring   │
                    │   - AV vs Heuristic     │
                    │   - Verdict Calculation │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┴────────────────────────┐
         ▼                                                ▼
  ┌───────────────┐                                ┌───────────────┐
  │ 11. Optional  │                                │ 12. SQLite DB │
  │     Gemini AI │                                │     Audit     │
  │  Explanation  │                                │   (Isolated)  │
  └───────┬───────┘                                └───────────────┘
          │
          ▼
  ┌────────────────────────────────────────────────────────┐
  │ 13. Telegram Security Report Delivered to User         │
  └────────────────────────────────────────────────────────┘
          │
          ▼
  ┌────────────────────────────────────────────────────────┐
  │ 14. Guaranteed Temporary File Deletion (finally block) │
  └────────────────────────────────────────────────────────┘
```

### Defense in Depth Measures:
1. **Host Execution Ban**: The scanner never executes or renders uploaded payloads. Documents and archives are parsed solely as passive binary byte streams and structures.
2. **Container Confinement**: Non-root container (`UID 10001`), read-only rootfs, `cap_drop: ALL`, `no-new-privileges: true`, resource limits (CPU: 1.5, Memory: 1GB).
3. **Prompt Injection Hardening**: Gemini AI receives only sanitized structural findings (no raw binaries or unchecked script bodies). Instructions strictly forbid overriding scanner verdicts.
4. **Third-Party Privacy Guarantee**: VirusTotal receives strictly the 64-character SHA-256 hash. Uploaded files are never transmitted to third parties without explicit user confirmation.
5. **Deterministic Primacy**: Antivirus and YARA detections take precedence; AI or heuristic modules are never allowed to soften a confirmed malware verdict.

---

## ⚠️ Known Limitations

1. **Static Analysis Limitations**: Static analysis cannot detect payloads that are heavily encrypted or downloaded at runtime via uninspected stagers.
2. **Docker is Not a Full Sandbox**: Docker isolation protects the host server from direct container escape, but is not a replacement for a multi-stage dynamic analysis hypervisor (e.g. Cuckoo / CAPE Sandbox).
3. **Telegram Bot API Size Limit**: Standard Telegram bots can receive files up to 20 MB. Files exceeding 20 MB must be analyzed via a local Telegram Bot API server.
4. **Zero Detection Disclaimer**: No antivirus or automated tool can guarantee 100% safety. A verdict of `NO_KNOWN_THREAT_DETECTED` means no known signatures matched, not that the file is inherently harmless.

---

## 🚀 Recommended Next Steps

1. **Local Telegram Bot API Server**: Deploy a local Telegram Bot API container to raise the file upload threshold from 20 MB to 2 GB.
2. **Dynamic Analysis Sandbox (CAPE/Cuckoo)**: Add an optional asynchronous worker queue to dispatch high-risk executables to an air-gapped Windows/Linux QEMU sandbox for behavioral execution analysis.
3. **Automated Signature Feed**: Implement a cron worker that periodically synchronizes community YARA rules (e.g. Neo23x0 signature-base) with automated validation.
4. **Redis Task Queue**: For massive concurrency (>1,000 daily users), separate the Telegram listener and scanning workers via Celery / Redis.
