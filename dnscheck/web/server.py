"""
Local HTTP REST API & Static Web Dashboard Server for DNSGuard (`dnscheck ui`).
Binds strictly to 127.0.0.1 for local privacy and security.
"""

from __future__ import annotations

import json
import mimetypes
import os
import platform
import shutil
import subprocess
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from dnscheck import __version__
from dnscheck.detectors import (
    generate_claude_rules,
    run_ai_services_diagnostics,
    run_claude_split_audit,
    run_custom_dig,
    run_dns_benchmark,
    run_dns_leak_detection,
    run_full_audit,
    run_pollution_detection,
    run_proxy_config_audit,
    run_split_route_diagnostics,
    run_system_env_diagnostics,
    run_webrtc_ipv6_diagnostics,
)
from dnscheck.enricher.ip_intel import enrich_ips_batch

STATIC_DIR = Path(__file__).resolve().parent / "static"


class DNSCheckRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler serving static frontend assets and diagnostic JSON APIs."""

    server_version = f"DNSGuard/{__version__}"

    def log_message(self, format: str, *args) -> None:
        # Suppress noisy per-request stderr logs unless debugging
        if os.environ.get("DNSCHECK_DEBUG"):
            super().log_message(format, *args)

    def _send_json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length_str = self.headers.get("Content-Length", "0")
        try:
            length = int(length_str)
        except ValueError:
            length = 0
        if length <= 0 or length > 1024 * 1024:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8", errors="replace"))

    def _serve_static(self, req_path: str) -> None:
        rel = req_path.lstrip("/") or "index.html"
        target = (STATIC_DIR / rel).resolve()
        # Prevent path traversal outside STATIC_DIR
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return

        mime, _ = mimetypes.guess_type(str(target))
        if target.suffix == ".js":
            mime = "application/javascript; charset=utf-8"
        elif target.suffix == ".css":
            mime = "text/css; charset=utf-8"
        elif target.suffix == ".html":
            mime = "text/html; charset=utf-8"
        elif not mime:
            mime = "application/octet-stream"

        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/api/status":
                self._send_json({
                    "status": "ok",
                    "version": __version__,
                    "os": platform.system(),
                    "machine": platform.machine(),
                })
            elif path == "/api/run/all":
                self._send_json(run_full_audit())
            elif path == "/api/run/env":
                self._send_json(run_system_env_diagnostics().to_dict())
            elif path == "/api/run/split":
                self._send_json(run_split_route_diagnostics().to_dict())
            elif path == "/api/run/leak":
                split_rep = run_split_route_diagnostics()
                self._send_json(run_dns_leak_detection(split_report=split_rep).to_dict())
            elif path == "/api/run/webrtc":
                split_rep = run_split_route_diagnostics()
                self._send_json(run_webrtc_ipv6_diagnostics(split_report=split_rep).to_dict())
            elif path == "/api/run/pollute":
                self._send_json(run_pollution_detection().to_dict())
            elif path == "/api/run/bench":
                self._send_json(run_dns_benchmark().to_dict())
            elif path == "/api/run/ai":
                split_rep = run_split_route_diagnostics()
                self._send_json(run_ai_services_diagnostics(split_report=split_rep).to_dict())
            elif path == "/api/run/audit":
                self._send_json(run_proxy_config_audit().to_dict())
            elif path == "/api/run/claude":
                self._send_json(run_claude_split_audit().to_dict())
            elif path == "/api/claude/rules":
                qs = parse_qs(parsed.query)
                fmt = (qs.get("format", ["surge"])[0] or "surge").strip()
                pol = (qs.get("policy", ["Claude"])[0] or "Claude").strip()
                self._send_json({"format": fmt, "policy": pol, "rules": generate_claude_rules(fmt=fmt, policy=pol)})
            else:
                self._serve_static(path)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
            if path == "/api/dig":
                domain = str(body.get("domain", "")).strip()
                if not domain:
                    self._send_json({"error": "缺少查询域名 (domain)"}, status=HTTPStatus.BAD_REQUEST)
                    return
                result = run_custom_dig(
                    domain=domain,
                    server=str(body.get("server", "223.5.5.5")).strip() or "223.5.5.5",
                    proto=str(body.get("proto", "udp")).strip() or "udp",
                    qtype_name=str(body.get("qtype", "A")).strip() or "A",
                    ecs=str(body.get("ecs", "")).strip() or None,
                    edns_do=bool(body.get("edns_do", True)),
                )
                self._send_json(result)
            elif path == "/api/enrich":
                ips = body.get("ips") or []
                if not isinstance(ips, list):
                    self._send_json({"error": "ips must be a list"}, status=HTTPStatus.BAD_REQUEST)
                    return
                enriched = enrich_ips_batch([str(ip) for ip in ips[:30]])
                self._send_json({"results": {ip: info.to_dict() for ip, info in enriched.items()}})
            else:
                self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)


def create_server(port: int = 8765) -> ThreadingHTTPServer:
    """Create a ThreadingHTTPServer bound to 127.0.0.1, finding a free port if occupied."""
    if port == 0:
        return ThreadingHTTPServer(("127.0.0.1", 0), DNSCheckRequestHandler)

    for offset in range(15):
        try:
            return ThreadingHTTPServer(("127.0.0.1", port + offset), DNSCheckRequestHandler)
        except OSError:
            continue
    return ThreadingHTTPServer(("127.0.0.1", 0), DNSCheckRequestHandler)


def _launch_ui_window(url: str, desktop_app: bool = False) -> None:
    """Open the dashboard either in standalone browser --app mode or default web browser."""
    if desktop_app:
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            shutil.which("google-chrome"),
            shutil.which("chromium"),
            shutil.which("microsoft-edge"),
        ]
        for exe in candidates:
            if exe and os.path.exists(exe):
                try:
                    subprocess.Popen(
                        [exe, f"--app={url}", "--window-size=1280,860"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    return
                except Exception:
                    pass
    webbrowser.open(url)


def start_web_ui(
    port: int = 8765,
    open_browser: bool = True,
    desktop_app: bool = False,
) -> None:
    """Start the local DNSGuard Web/Desktop UI server and block until Ctrl+C."""
    httpd = create_server(port)
    actual_port = httpd.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"

    print("╔══════════════════════════════════════════════════════════════════════╗")
    print(f"║  DNSGuard 可视化安全审计台已启动: {url:<34} ║")
    print("║  按 Ctrl+C 停止本地探针服务                                          ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    if open_browser:
        threading.Timer(0.4, _launch_ui_window, args=(url, desktop_app)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭 DNSGuard 本地服务...")
    finally:
        httpd.server_close()
