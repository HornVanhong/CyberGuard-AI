"""CyberGuard AI - Lightweight HTTPS/HTTP Malware Scanner Service API.

Exposes a REST API for Cloudflare Workers (or any edge webhook gateway) to:
1. Check health/status of all 12 security scanning engines (GET /status).
2. Scan uploaded files through ClamAV, YARA, Ghidra, DIE, oletools, capa, etc. (POST /scan).
"""

from __future__ import annotations

import asyncio
import cgi
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from app.config import settings
from app.services.file_service import FileService
from app.scanners.orchestrator import ScannerOrchestrator
from app.scanners.clamav_scanner import ClamAVScanner
from app.scanners.yara_scanner import YaraScanner
from app.scanners.oletools_analyzer import OletoolsAdapter
from app.scanners.pdfid_analyzer import PDFiDAdapter
from app.scanners.exiftool_analyzer import ExifToolAdapter
from app.scanners.executable_analyzer import CapaAdapter, DiecAdapter
from app.scanners.ghidra_analyzer import GhidraAdapter
from app.scanners.gitleaks_analyzer import GitleaksAdapter
from app.scanners.url_analyzer import UrlAnalyzer
from app.services.virustotal_service import VirusTotalService
from app.database.repository import ScanRepository
from app.security.risk_engine import RiskEngine, Verdict
from app.utils.logger import logger
from dataclasses import asdict


def get_active_tunnel_url() -> str:
    """Reads the current active Cloudflare tunnel URL."""
    root = Path(__file__).parent.parent
    p = root / "tunnel_url.txt"
    if p.exists():
        try:
            url = p.read_text(encoding="utf-8-sig").strip()
            if url.startswith("http"):
                return url
        except Exception:
            pass
    w = root / "worker" / "worker.js"
    if w.exists():
        try:
            import re
            m = re.search(r'DEFAULT_SCANNER_URL\s*=\s*["\'](https://[^"\']+)["\']', w.read_text(encoding="utf-8"))
            if m:
                return m.group(1)
        except Exception:
            pass
    return "https://warning-gallery-rss-autos.trycloudflare.com"


class ScannerAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Cloudflare Worker scanner integration & Web Dashboard."""

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def _verify_auth(self) -> bool:
        token = os.getenv("SCANNER_API_TOKEN")
        if not token:
            return True  # If no token configured, allow connection (e.g. private network)
        auth_header = self.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        return auth_header.strip() == expected

    def do_GET(self):
        """GET router for Dashboard, Tunnel info, worker.js, and health/status checks."""
        accept_header = self.headers.get("Accept", "")
        is_html_request = "text/html" in accept_header

        # 1. Web Dashboard (GET /dashboard or browser visiting GET /)
        if self.path in ("/dashboard", "/dashboard/") or (self.path == "/" and is_html_request):
            template_path = Path(__file__).parent / "templates" / "dashboard.html"
            if template_path.exists():
                html_content = template_path.read_text(encoding="utf-8")
                self._set_headers(200, "text/html; charset=utf-8")
                self.wfile.write(html_content.encode("utf-8"))
                return

        # 2. Dynamic Tunnel URL info (GET /api/tunnel)
        if self.path == "/api/tunnel":
            self._set_headers(200)
            self.wfile.write(json.dumps({
                "tunnel_url": get_active_tunnel_url(),
                "status": "online"
            }).encode("utf-8"))
            return

        # 3. Serve raw worker.js for 1-click clipboard copying (GET /worker.js)
        if self.path == "/worker.js":
            worker_path = Path(__file__).parent.parent / "worker" / "worker.js"
            if worker_path.exists():
                worker_code = worker_path.read_text(encoding="utf-8")
                self._set_headers(200, "text/javascript; charset=utf-8")
                self.wfile.write(worker_code.encode("utf-8"))
                return

        # 4. JSON Health / Status endpoint (GET /status or GET /health)
        if self.path in ("/", "/health", "/status"):
            if not self._verify_auth():
                self._set_headers(401)
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                return

            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                status_data = loop.run_until_complete(self._collect_engine_status())
                loop.close()

                self._set_headers(200)
                self.wfile.write(json.dumps(status_data, indent=2).encode())
            except Exception as e:
                logger.error(f"Error checking engine status: {e}")
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Not Found"}).encode())

    def do_POST(self):
        """POST /scan (multipart file scan) or POST /check_url (JSON URL & message analysis)."""
        if self.path not in ("/scan", "/check_url"):
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode())
            return

        if not self._verify_auth():
            self._set_headers(401)
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
            return

        if self.path == "/check_url":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_len).decode("utf-8")
                payload = json.loads(raw_body) if raw_body else {}

                url = payload.get("url", "").strip()
                text = payload.get("text", "").strip()

                vt = VirusTotalService(
                    api_key=settings.VIRUSTOTAL_API_KEY,
                    enabled=settings.VIRUSTOTAL_ENABLED,
                )
                analyzer = UrlAnalyzer(vt_service=vt)

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                if url:
                    result = loop.run_until_complete(analyzer.analyze_url(url))
                    data = asdict(result)
                elif text:
                    result = loop.run_until_complete(analyzer.analyze_message(text))
                    data = asdict(result)
                else:
                    loop.close()
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Missing 'url' or 'text' in payload"}).encode())
                    return

                loop.close()
                self._set_headers(200)
                self.wfile.write(json.dumps(data, indent=2).encode())
            except Exception as e:
                logger.error(f"Error in /check_url handler: {e}")
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        if self.path == "/scan":
            try:
                content_type = self.headers.get("Content-Type", "")
                file_bytes = b""
                filename = "unknown.bin"

                if "application/json" in content_type:
                    content_len = int(self.headers.get("Content-Length", 0))
                    raw_body = self.rfile.read(content_len).decode("utf-8")
                    payload = json.loads(raw_body) if raw_body else {}
                    file_url = payload.get("file_url")
                    filename = payload.get("filename", "uploaded_file.bin")
                    chat_id = payload.get("chat_id")
                    status_msg_id = payload.get("status_msg_id")
                    lang = payload.get("lang", "km")
                    file_size = payload.get("file_size", 0)

                    if not file_url:
                        self._set_headers(400)
                        self.wfile.write(json.dumps({"error": "Missing 'file_url' in JSON body"}).encode())
                        return

                    if chat_id and status_msg_id:
                        # Asynchronous execution to completely prevent Cloudflare 60s idle timeout
                        self._set_headers(200)
                        self.wfile.write(json.dumps({"status": "accepted", "message": "Scan job running in background"}).encode())

                        thread = threading.Thread(
                            target=self._process_scan_background,
                            args=(file_url, filename, chat_id, status_msg_id, lang, file_size),
                            daemon=True,
                        )
                        thread.start()
                        return

                    logger.info(f"Direct high-speed download initiated for '{filename}' from Telegram...")
                    with requests.get(file_url, stream=True, timeout=90) as r:
                        r.raise_for_status()
                        file_bytes = r.content
                    logger.info(f"Direct download completed: {len(file_bytes)} bytes downloaded.")

                elif content_type.startswith("multipart/form-data"):
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={
                            "REQUEST_METHOD": "POST",
                            "CONTENT_TYPE": self.headers["Content-Type"],
                        },
                    )

                    if "file" not in form:
                        self._set_headers(400)
                        self.wfile.write(json.dumps({"error": "Missing 'file' in multipart form"}).encode())
                        return

                    file_item = form["file"]
                    filename = file_item.filename or "unknown.bin"
                    file_bytes = file_item.file.read()
                else:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Expected application/json or multipart/form-data"}).encode())
                    return

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                scan_report = loop.run_until_complete(self._execute_scan(filename, file_bytes))
                loop.close()

                self._set_headers(200)
                self.wfile.write(json.dumps(scan_report, indent=2).encode())
            except Exception as e:
                logger.error(f"Error in /scan handler: {e}")
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

    def _process_scan_background(
        self,
        file_url: str,
        filename: str,
        chat_id: int,
        status_msg_id: int,
        lang: str,
        file_size: int,
    ) -> None:
        """Processes large file download, scan, and AI analysis in background, updating Telegram in real-time."""
        token = settings.TELEGRAM_BOT_TOKEN
        size_mb = f"{(file_size / (1024 * 1024)):.1f}" if file_size > 0 else ""
        size_label = f" ({size_mb} MB)" if size_mb else ""

        def render_bar(pct: int, length: int = 10) -> str:
            clamped = max(0, min(100, pct))
            filled = round((clamped / 100) * length)
            return "▰" * filled + "▱" * (length - filled)

        def edit_tg(text: str, reply_markup=None):
            url = f"https://api.telegram.org/bot{token}/editMessageText"
            body: Dict[str, Any] = {
                "chat_id": chat_id,
                "message_id": status_msg_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }
            if reply_markup:
                body["reply_markup"] = reply_markup
            try:
                r = requests.post(url, json=body, timeout=10)
                if not r.ok:
                    logger.warning(f"edit_tg markdown failed ({r.status_code}): {r.text}")
                    body.pop("parse_mode", None)
                    r2 = requests.post(url, json=body, timeout=10)
                    if not r2.ok:
                        logger.warning(f"edit_tg fallback failed ({r2.status_code}): {r2.text}")
            except Exception as e:
                logger.error(f"edit_tg exception: {e}")

        try:
            logger.info(f"[BackgroundScan] Downloading '{filename}' for chat {chat_id}...")
            chunks = []
            downloaded = 0
            last_edit = time.time()

            with requests.get(file_url, stream=True, timeout=120) as r:
                r.raise_for_status()
                total_len = int(r.headers.get("content-length") or file_size or 0)
                for chunk in r.iter_content(chunk_size=256 * 1024):
                    if chunk:
                        chunks.append(chunk)
                        downloaded += len(chunk)
                        now = time.time()
                        if total_len > 0 and (now - last_edit >= 1.5):
                            pct = min(int((downloaded / total_len) * 70), 70)
                            cur_mb = f"{(downloaded / (1024 * 1024)):.1f}"
                            tot_mb = f"{(total_len / (1024 * 1024)):.1f}"
                            bar = render_bar(pct)
                            msg = (
                                f"⚡ *កំពុងទាញយកឯកសារ ({tot_mb} MB)*\n`{bar}` {pct}%\n({cur_mb} MB / {tot_mb} MB)\n\n📥 _ទាញយកផ្ទាល់ពី Telegram CDN..._"
                                if lang == "km"
                                else f"⚡ *Downloading file ({tot_mb} MB)*\n`{bar}` {pct}%\n({cur_mb} MB / {tot_mb} MB)\n\n📥 _Direct download from Telegram CDN..._"
                            )
                            edit_tg(msg)
                            last_edit = now

            file_bytes = b"".join(chunks)
            logger.info(f"[BackgroundScan] Download complete: {len(file_bytes)} bytes. Running engines...")

            p80 = (
                f"🔍 *កំពុងវិភាគសុវត្ថិភាពឯកសារ (80%)*\n`{render_bar(80)}`\n\n🛡️ _ClamAV Antivirus, YARA Rules & SRE Engines..._"
                if lang == "km"
                else f"🔍 *Analyzing file security (80%)*\n`{render_bar(80)}`\n\n🛡️ _ClamAV Antivirus, YARA Rules & SRE Engines..._"
            )
            edit_tg(p80)

            # Execute scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scan_report = loop.run_until_complete(self._execute_scan(filename, file_bytes))
            loop.close()

            verdict = scan_report.get("verdict", "INCONCLUSIVE")
            severity = scan_report.get("severity", "MEDIUM")
            findings = scan_report.get("findings", ["Scan completed."])
            icon = "🟢" if verdict == "CLEAN" else ("🔴" if verdict == "MALICIOUS" else "🟡")

            logger.info(f"[BackgroundScan] Scan verdict for '{filename}': {verdict} ({severity})")

            ai_explanation = ""
            if settings.is_gemini_enabled:
                p92 = (
                    f"🤖 *កំពុងបូកសរុបលទ្ធផលជាមួយ AI (92%)*\n`{render_bar(92)}`\n\n🧠 _Google Gemini AI Security Assessment..._"
                    if lang == "km"
                    else f"🤖 *Generating AI Explanation (92%)*\n`{render_bar(92)}`\n\n🧠 _Google Gemini AI Security Assessment..._"
                )
                edit_tg(p92)

                try:
                    from app.services.ai_service import AIService, clean_ai_telegram_output
                    ai_service = AIService(api_key=settings.GEMINI_API_KEY, model=settings.GEMINI_MODEL, enabled=True)
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    prompt = (
                        f"[File Scan Result]\nFile: {filename}\nVerdict: {verdict}\nSeverity: {severity}\n"
                        f"Findings: {'; '.join(findings)}\n\n"
                        f"Explain these results in {('Khmer' if lang == 'km' else 'English')} and give security advice."
                    )
                    raw_answer = loop.run_until_complete(ai_service.answer_security_question(question=prompt, lang=lang))
                    loop.close()
                    if raw_answer:
                        ai_explanation = clean_ai_telegram_output(raw_answer)
                except Exception as e:
                    logger.error(f"Error calling Gemini in background: {e}")

            # Build final report
            header = "🛡️ *CyberGuard AI — លទ្ធផលស្កេនឯកសារ*" if lang == "km" else "🛡️ *CyberGuard AI — File Scan Result*"
            file_label = "📄 *ឯកសារ:*" if lang == "km" else "📄 *File:*"
            v_label = "លទ្ធផល (Verdict):" if lang == "km" else "Verdict:"
            s_label = "កម្រិតហានិភ័យ:" if lang == "km" else "Severity:"
            f_label = "🔍 *ការរកឃើញ (Findings):*" if lang == "km" else "🔍 *Findings:*"
            ai_label = "🤖 *ការវិភាគពី Gemini AI:*" if lang == "km" else "🤖 *Gemini AI Assessment:*"
            footer = "🛡️ _CyberGuard AI Zero-Trust File Inspection_"

            f_text = "\n".join(f"• {f}" for f in findings)
            ai_sec = f"\n\n{ai_label}\n{ai_explanation}" if ai_explanation else ""

            report_msg = (
                f"{header}\n\n"
                f"{file_label} `{filename}`{size_label}\n"
                f"{icon} *{v_label}* *{verdict}*\n"
                f"⚠️ *{s_label}* *{severity}*\n\n"
                f"{f_label}\n"
                f"{f_text}"
                f"{ai_sec}\n\n"
                f"{footer}"
            )

            # 1. Edit the progress message into the complete final scan report!
            edit_tg(report_msg)

            # 2. Refresh bottom reply keyboard
            reply_keyboard = {
                "keyboard": [
                    [{"text": "🔍 ស្កេនឯកសារ" if lang == "km" else "🔍 Scan File"}, {"text": "🔗 វិភាគ Link & សារ" if lang == "km" else "🔗 Inspect Link & Msg"}],
                    [{"text": "💬 សួរ AI Security" if lang == "km" else "💬 Ask AI Security"}, {"text": "⚙️ ស្ថានភាពម៉ាស៊ីន" if lang == "km" else "⚙️ System Status"}],
                    [{"text": "🔬 Ghidra Decompiler"}, {"text": "📋 ប្រវត្តិស្កេន" if lang == "km" else "📋 Scan History"}],
                    [{"text": "🌐 ផ្លាស់ប្តូរភាសា" if lang == "km" else "🌐 Switch Language"}, {"text": "📚 ការណែនាំ & ជំនួយ" if lang == "km" else "📚 Help & Guide"}],
                    [{"text": "🔐 គោលការណ៍ឯកជនភាព" if lang == "km" else "🔐 Privacy Policy"}],
                ],
                "resize_keyboard": True,
                "is_persistent": True,
            }
            try:
                requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": "🛡️ ជ្រើសរើសមុខងារខាងក្រោមដើម្បីបន្ត៖" if lang == "km" else "🛡️ Choose an option below to continue:",
                        "reply_markup": reply_keyboard,
                    },
                    timeout=5,
                )
            except Exception:
                pass

            logger.info(f"[BackgroundScan] Completed successfully for '{filename}'.")

        except Exception as e:
            logger.error(f"[BackgroundScan] Failed: {e}", exc_info=True)
            err_msg = (
                f"❌ បរាជ័យក្នុងការស្កេនឯកសារ៖ {e}"
                if lang == "km"
                else f"❌ Failed to scan file: {e}"
            )
            edit_tg(err_msg)

    async def _collect_engine_status(self) -> Dict[str, Any]:
        """Gathers status across all 12 engines."""
        clamav = ClamAVScanner(
            host=settings.CLAMAV_HOST,
            port=settings.CLAMAV_PORT,
            timeout=settings.CLAMAV_TIMEOUT,
            enabled=settings.CLAMAV_ENABLED,
        )
        yara = YaraScanner(
            rules_dir=settings.YARA_RULES_DIR,
            timeout=settings.YARA_TIMEOUT,
            enabled=settings.YARA_ENABLED,
        )
        yara.load_rules()

        clamav_online = await clamav.ping()
        clamav_ver = await clamav.get_version() if clamav_online else "Unavailable"
        yara_online = yara.is_available and yara.rules_loaded_count > 0

        return {
            "status": "online",
            "service": "CyberGuard AI Dedicated Scanner Backend",
            "engines": {
                "clamav": {
                    "status": "ONLINE" if clamav_online else "OFFLINE",
                    "version": clamav_ver,
                },
                "yara": {
                    "status": "READY" if yara_online else "OFFLINE",
                    "rules_loaded": yara.rules_loaded_count,
                },
                "virustotal": {"status": "CONFIGURED" if settings.VIRUSTOTAL_ENABLED and settings.VIRUSTOTAL_API_KEY else "DISABLED"},
                "oletools": {"status": "READY" if OletoolsAdapter().is_available() else "UNAVAILABLE"},
                "pdfid": {"status": "READY" if PDFiDAdapter().is_available() else "UNAVAILABLE"},
                "exiftool": {"status": "READY" if ExifToolAdapter().is_available() else "UNAVAILABLE"},
                "capa": {"status": "READY" if CapaAdapter().is_available() else "UNAVAILABLE"},
                "diec": {"status": "READY" if DiecAdapter().is_available() else "UNAVAILABLE"},
                "ghidra": {"status": "READY" if GhidraAdapter().is_available() else "UNAVAILABLE"},
                "gitleaks": {"status": "READY" if GitleaksAdapter().is_available() else "UNAVAILABLE"},
                "database": {"status": "OPERATIONAL"},
            },
        }

    async def _execute_scan(self, filename: str, file_bytes: bytes) -> Dict[str, Any]:
        """Runs the complete orchestrator scan pipeline."""
        clamav = ClamAVScanner(
            host=settings.CLAMAV_HOST,
            port=settings.CLAMAV_PORT,
            timeout=settings.CLAMAV_TIMEOUT,
            enabled=settings.CLAMAV_ENABLED,
        )
        yara = YaraScanner(
            rules_dir=settings.YARA_RULES_DIR,
            timeout=settings.YARA_TIMEOUT,
            enabled=settings.YARA_ENABLED,
        )
        yara.load_rules()
        orchestrator = ScannerOrchestrator(clamav=clamav, yara=yara)
        risk_engine = RiskEngine()

        file_service = FileService(base_temp_dir="temp_uploads")
        scan_id = uuid.uuid4().hex[:12]
        sandbox_dir = file_service.create_scan_sandbox(scan_id)

        # Extract valid trailing ASCII extensions (e.g. .pdf.rar or .exe) so format scanners trigger accurately,
        # but keep filename 100% ASCII-safe on disk so native C libraries (YARA, ClamAV) on Windows open it cleanly without Errno 22.
        m = re.findall(r"\.[a-zA-Z0-9]{1,10}", filename)
        safe_ext = "".join(m[-2:]) if m else ".bin"
        safe_disk_name = f"scan_target{safe_ext}"
        tmp_path = sandbox_dir / safe_disk_name
        tmp_path.write_bytes(file_bytes)

        try:
            orch_result = await orchestrator.execute_scan(tmp_path, filename)
            assessment = RiskEngine.evaluate(
                file_analysis=orch_result.file_analysis,
                clamav_result=orch_result.clamav_result,
                yara_result=orch_result.yara_result,
                script_findings=orch_result.script_findings,
                pdf_findings=orch_result.pdf_findings,
                archive_findings=orch_result.archive_findings,
                office_findings=orch_result.office_findings,
                adapter_results=orch_result.adapter_results,
            )

            is_malicious = assessment.verdict == Verdict.MALICIOUS or assessment.is_av_positive
            verdict_str = "MALICIOUS" if is_malicious else ("SUSPICIOUS" if assessment.verdict == Verdict.SUSPICIOUS else "CLEAN")

            clamav_detected = orch_result.clamav_result.is_threat if orch_result.clamav_result else False
            virus_name = orch_result.clamav_result.malware_name if orch_result.clamav_result else None

            yara_matches = []
            if orch_result.yara_result and orch_result.yara_result.matches:
                for m in orch_result.yara_result.matches:
                    yara_matches.append({"rule_name": m.rule, "tags": m.tags})

            return {
                "verdict": verdict_str,
                "severity": assessment.risk_level.value,
                "risk_score": assessment.score,
                "clamav": {
                    "status": orch_result.clamav_result.status.value if orch_result.clamav_result else "SKIPPED",
                    "detected": clamav_detected,
                    "virus_name": virus_name,
                },
                "yara": {
                    "status": orch_result.yara_result.status.value if orch_result.yara_result else "SKIPPED",
                    "matches": yara_matches,
                    "rules_evaluated": yara.rules_loaded_count,
                },
                "findings": assessment.findings if assessment.findings else ["No immediate security threats detected."],
                "recommendations": assessment.recommendations if assessment.recommendations else [
                    "Standard zero-trust verification applies."
                ],
            }
        finally:
            file_service.cleanup_scan_dir(sandbox_dir)


def run_scanner_api(host: str = "0.0.0.0", port: int = 8000):
    server = HTTPServer((host, port), ScannerAPIHandler)
    logger.info(f"CyberGuard AI Scanner API listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Scanner API server stopped.")
        server.server_close()


if __name__ == "__main__":
    run_scanner_api()
