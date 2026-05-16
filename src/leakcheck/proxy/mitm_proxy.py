from __future__ import annotations

import select
import socket
import subprocess
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from leakcheck.common.run_utils import save_json
from leakcheck.proxy.http_capture import ProxyCaptureStore
from leakcheck.proxy.reverse_proxy import HOP_BY_HOP_HEADERS


@dataclass(frozen=True)
class CertificateStatus:
    cert_dir: str
    ca_cert_path: str
    generated: bool
    installed: bool
    generation_error: str
    instructions: list[str]
    warning: str


class BrowserMitmCertificateManager:
    """Manage local-only certificate workflow metadata for browser proxy mode.

    Certificates are never installed automatically. The standalone runtime can
    capture plain HTTP immediately and tunnel HTTPS CONNECT traffic without
    decrypting it. Decrypted HTTPS capture should be wired through a dedicated
    MITM engine that uses the generated CA material.
    """

    def __init__(self, cert_dir: str | Path):
        self.cert_dir = Path(cert_dir)
        self.ca_cert_path = self.cert_dir / "leakcheck-local-ca.pem"
        self.private_key_path = self.cert_dir / "leakcheck-local-ca.key"

    def status(self) -> CertificateStatus:
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        generation_error = ""
        readme_path = self.cert_dir / "README.txt"
        if not readme_path.exists():
            readme_path.write_text(
                "\n".join(
                    [
                        "LeakCheck browser proxy certificate directory.",
                        "",
                        "LeakCheck does not auto-install trusted certificates.",
                        "Install a local CA manually only in a disposable browser profile.",
                        "Remove the CA from the browser or OS trust store after the audit.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
        if not self.ca_cert_path.exists() or not self.private_key_path.exists():
            generation_error = self._try_generate_local_ca()
        generated = self.ca_cert_path.exists() and self.private_key_path.exists()
        return CertificateStatus(
            cert_dir=str(self.cert_dir),
            ca_cert_path=str(self.ca_cert_path),
            generated=generated,
            installed=False,
            generation_error=generation_error,
            instructions=[
                "Configure the browser HTTP proxy to the LeakCheck listen host and port.",
                "Use a disposable browser profile for audits.",
                "Install the local CA manually only in that disposable browser profile.",
                "Remove the CA from the browser trust store after the audit.",
                "Never route personal or unrelated traffic through the capture proxy.",
            ],
            warning="Standalone browser proxy mode captures HTTP bodies and tunnels HTTPS without decrypting content.",
        )

    def _try_generate_local_ca(self) -> str:
        command = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "3650",
            "-nodes",
            "-keyout",
            str(self.private_key_path),
            "-out",
            str(self.ca_cert_path),
            "-subj",
            "/CN=LeakCheck Local Audit CA",
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)
            return ""
        except FileNotFoundError:
            return "OpenSSL was not found; CA generation is pending."
        except subprocess.SubprocessError as exc:
            return f"OpenSSL CA generation failed: {exc}"

    def payload(self) -> dict[str, Any]:
        status = self.status()
        return {
            "cert_dir": status.cert_dir,
            "ca_cert_path": status.ca_cert_path,
            "generated": status.generated,
            "installed": status.installed,
            "generation_error": status.generation_error,
            "instructions": status.instructions,
            "warning": status.warning,
        }


class BrowserMitmProxyRuntime:
    """Localhost explicit browser proxy capture runtime.

    This runtime accepts browser proxy traffic. Plain HTTP requests are forwarded
    and stored as full request/response pairs. HTTPS CONNECT requests are
    tunneled so browser traffic can continue, with metadata captured but bodies
    left unavailable unless a TLS MITM engine is added.
    """

    def __init__(
        self,
        *,
        store: ProxyCaptureStore,
        session_id: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        cert_dir: str | Path = "data/proxy_certs",
        timeout_s: int = 60,
    ):
        if listen_host not in {"127.0.0.1", "localhost"}:
            raise ValueError("browser MITM proxy listener is restricted to localhost")
        self.store = store
        self.session_id = session_id
        self.listen_host = "127.0.0.1" if listen_host == "localhost" else listen_host
        self.listen_port = int(listen_port)
        self.timeout_s = int(timeout_s)
        self.cert_manager = BrowserMitmCertificateManager(cert_dir)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def listen_url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}"

    def start(self) -> None:
        runtime = self
        runtime.cert_manager.status()

        class Handler(BaseHTTPRequestHandler):
            server_version = "LeakCheckBrowserProxy/0.1"

            def do_CONNECT(self) -> None:
                self._connect_tunnel()

            def do_GET(self) -> None:
                self._proxy_http()

            def do_POST(self) -> None:
                self._proxy_http()

            def do_PUT(self) -> None:
                self._proxy_http()

            def do_PATCH(self) -> None:
                self._proxy_http()

            def do_DELETE(self) -> None:
                self._proxy_http()

            def do_OPTIONS(self) -> None:
                self._proxy_http()

            def do_HEAD(self) -> None:
                self._proxy_http()

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _request_body(self) -> bytes:
                length = int(self.headers.get("content-length", "0") or 0)
                return self.rfile.read(length) if length else b""

            def _target_url(self) -> str:
                parsed = urlsplit(self.path)
                if parsed.scheme and parsed.netloc:
                    return self.path
                host = self.headers.get("host", "")
                return f"http://{host}{self.path}"

            def _proxy_headers(self) -> dict[str, str]:
                return {
                    key: value
                    for key, value in self.headers.items()
                    if key.lower() not in HOP_BY_HOP_HEADERS
                }

            def _send_response(self, response: requests.Response, include_body: bool = True) -> None:
                self.send_response(response.status_code)
                for key, value in response.headers.items():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                if include_body:
                    self.send_header("Content-Length", str(len(response.content)))
                self.end_headers()
                if include_body:
                    self.wfile.write(response.content)

            def _proxy_http(self) -> None:
                body = self._request_body()
                target = self._target_url()
                try:
                    response = requests.request(
                        method=self.command,
                        url=target,
                        headers=self._proxy_headers(),
                        data=body,
                        timeout=runtime.timeout_s,
                        allow_redirects=False,
                    )
                    runtime.store.record_exchange(
                        session_id=runtime.session_id,
                        method=self.command,
                        url=target,
                        request_headers=dict(self.headers.items()),
                        request_body=body.decode("utf-8", errors="replace"),
                        response_status=response.status_code,
                        response_headers=dict(response.headers.items()),
                        response_body=response.text,
                        transport="http",
                        metadata={"captured_by": "browser_mitm_proxy", "listen_url": runtime.listen_url},
                    )
                    self._send_response(response, include_body=self.command != "HEAD")
                except Exception as exc:
                    runtime.store.record_exchange(
                        session_id=runtime.session_id,
                        method=self.command,
                        url=target,
                        request_headers=dict(self.headers.items()),
                        request_body=body.decode("utf-8", errors="replace"),
                        response_status=502,
                        response_headers={},
                        response_body=str(exc),
                        transport="http",
                        metadata={"captured_by": "browser_mitm_proxy", "error": str(exc)},
                    )
                    self.send_response(502)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    payload = f"LeakCheck browser proxy error: {exc}".encode("utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

            def _connect_tunnel(self) -> None:
                host, _, port_raw = self.path.partition(":")
                port = int(port_raw or "443")
                upstream: socket.socket | None = None
                try:
                    upstream = socket.create_connection((host, port), timeout=runtime.timeout_s)
                    self.send_response(200, "Connection Established")
                    self.end_headers()
                    runtime.store.record_exchange(
                        session_id=runtime.session_id,
                        method="CONNECT",
                        url=f"https://{host}:{port}",
                        request_headers=dict(self.headers.items()),
                        request_body="",
                        response_status=200,
                        response_headers={},
                        response_body="",
                        transport="http",
                        metadata={
                            "captured_by": "browser_mitm_proxy",
                            "connect_tunnel": True,
                            "decrypted": False,
                        },
                    )
                    self._relay(upstream)
                except Exception as exc:
                    runtime.store.record_exchange(
                        session_id=runtime.session_id,
                        method="CONNECT",
                        url=f"https://{host}:{port}",
                        request_headers=dict(self.headers.items()),
                        request_body="",
                        response_status=502,
                        response_headers={},
                        response_body=str(exc),
                        transport="http",
                        metadata={"captured_by": "browser_mitm_proxy", "connect_tunnel": True, "error": str(exc)},
                    )
                    self.send_response(502)
                    self.end_headers()
                finally:
                    if upstream is not None:
                        upstream.close()

            def _relay(self, upstream: socket.socket) -> None:
                sockets = [self.connection, upstream]
                for sock in sockets:
                    sock.settimeout(runtime.timeout_s)
                while True:
                    readable, _, errored = select.select(sockets, [], sockets, runtime.timeout_s)
                    if errored or not readable:
                        break
                    for sock in readable:
                        other = upstream if sock is self.connection else self.connection
                        data = sock.recv(8192)
                        if not data:
                            return
                        other.sendall(data)

        self._server = ThreadingHTTPServer((self.listen_host, self.listen_port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def session_updates(self) -> dict[str, Any]:
        return {
            "listen_url": self.listen_url,
            "capture_mode": "browser_mitm",
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "certificate": self.cert_manager.payload(),
        }

    def write_certificate_status(self, session_dir: str | Path) -> None:
        save_json(Path(session_dir) / "certificate_status.json", self.cert_manager.payload())

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None
