from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from leakcheck.proxy.http_capture import ProxyCaptureStore

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
}


class ReverseProxyRuntime:
    """Small controlled reverse proxy for passive capture of known HTTP targets."""

    def __init__(
        self,
        *,
        store: ProxyCaptureStore,
        session_id: str,
        target_url: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8765,
        timeout_s: int = 60,
    ):
        if not target_url:
            raise ValueError("target_url is required for reverse proxy capture")
        parsed = urlsplit(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target_url must be an absolute http(s) URL")
        self.store = store
        self.session_id = session_id
        self.target_url = target_url.rstrip("/") + "/"
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.timeout_s = int(timeout_s)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def listen_url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}"

    def start(self) -> None:
        runtime = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "LeakCheckReverseProxy/0.1"

            def do_GET(self) -> None:
                self._proxy()

            def do_POST(self) -> None:
                self._proxy()

            def do_PUT(self) -> None:
                self._proxy()

            def do_PATCH(self) -> None:
                self._proxy()

            def do_DELETE(self) -> None:
                self._proxy()

            def do_OPTIONS(self) -> None:
                self._proxy()

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _request_body(self) -> bytes:
                length = int(self.headers.get("content-length", "0") or 0)
                return self.rfile.read(length) if length else b""

            def _target_url(self) -> str:
                path = self.path.lstrip("/")
                return urljoin(runtime.target_url, path)

            def _proxy_headers(self) -> dict[str, str]:
                return {
                    key: value
                    for key, value in self.headers.items()
                    if key.lower() not in HOP_BY_HOP_HEADERS
                }

            def _send_response(self, response: requests.Response) -> None:
                self.send_response(response.status_code)
                for key, value in response.headers.items():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)

            def _proxy(self) -> None:
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
                        metadata={"captured_by": "reverse_proxy", "listen_url": runtime.listen_url},
                    )
                    self._send_response(response)
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
                        metadata={"captured_by": "reverse_proxy", "error": str(exc)},
                    )
                    self.send_response(502)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    payload = f"LeakCheck proxy error: {exc}".encode("utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

        self._server = ThreadingHTTPServer((self.listen_host, self.listen_port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None
