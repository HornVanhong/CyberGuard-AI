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
import sys
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from app.config import settings
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

                    if not file_url:
                        self._set_headers(400)
                        self.wfile.write(json.dumps({"error": "Missing 'file_url' in JSON body"}).encode())
                        return

                    logger.info(f"Direct high-speed download initiated for '{filename}' from Telegram...")
                    import requests
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

        with tempfile.NamedTemporaryFile(delete=False, prefix="cyberguard_scan_") as tmp:
            tmp.write(file_bytes)
            tmp_path = Path(tmp.name)

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
            if tmp_path.exists():
                tmp_path.unlink()


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
