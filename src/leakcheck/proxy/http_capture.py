from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from leakcheck.common.run_utils import append_jsonl, save_json
from leakcheck.common.schemas import ProxyExchange
from leakcheck.proxy.streaming import reconstruct_stream

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "openai-api-key",
    "proxy-authorization",
}
REDACTED = "[REDACTED]"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Redact token-bearing headers while preserving non-sensitive capture context."""
    out: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        name = str(key)
        out[name] = REDACTED if name.lower() in SENSITIVE_HEADER_NAMES else str(value)
    return out


def _parse_json_maybe(payload: str | bytes | dict[str, Any] | list[Any] | None) -> Any:
    if payload is None:
        return None
    if isinstance(payload, dict | list):
        return payload
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    text = str(payload).strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _first_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, list):
        parts = [_first_text(item) for item in value]
        joined = "\n".join(part for part in parts if part)
        return joined or None
    if isinstance(value, dict):
        for key in ("content", "text", "message", "prompt", "response", "output"):
            found = _first_text(value.get(key))
            if found:
                return found
        if isinstance(value.get("messages"), list):
            return _first_text(value["messages"])
    return None


def extract_prompt_response(request_body: Any, response_body: Any) -> tuple[str | None, str | None]:
    """Extract common chat prompt/response fields from JSON or flat text bodies."""
    request_data = _parse_json_maybe(request_body)
    if isinstance(response_body, str):
        reconstructed = reconstruct_stream(response_body)
        if reconstructed.stream_format not in {"plain_text", "empty"} and reconstructed.text:
            response_body = reconstructed.text
    response_data = _parse_json_maybe(response_body)

    prompt_text: str | None = None
    if isinstance(request_data, dict):
        if isinstance(request_data.get("messages"), list):
            user_messages = [
                msg.get("content")
                for msg in request_data["messages"]
                if isinstance(msg, dict) and msg.get("role") in {None, "user"}
            ]
            prompt_text = _first_text(user_messages)
        prompt_text = prompt_text or _first_text(request_data.get("prompt"))
        prompt_text = prompt_text or _first_text(request_data.get("message"))
        prompt_text = prompt_text or _first_text(request_data.get("input"))
        prompt_text = prompt_text or _first_text(request_data.get("text"))
    elif isinstance(request_data, str):
        prompt_text = request_data

    response_text: str | None = None
    if isinstance(response_data, dict):
        choices = response_data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                response_text = _first_text(first.get("message")) or _first_text(first.get("delta"))
                response_text = response_text or _first_text(first.get("text"))
        response_text = response_text or _first_text(response_data.get("response"))
        response_text = response_text or _first_text(response_data.get("output"))
        response_text = response_text or _first_text(response_data.get("content"))
        response_text = response_text or _first_text(response_data.get("text"))
    elif isinstance(response_data, str):
        response_text = response_data

    return prompt_text, response_text


def stream_reconstruction_metadata(response_body: Any, response_headers: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if not isinstance(response_body, str):
        return None
    content_type = ""
    for key, value in dict(response_headers or {}).items():
        if str(key).lower() == "content-type":
            content_type = str(value)
            break
    reconstructed = reconstruct_stream(response_body, content_type=content_type)
    if reconstructed.stream_format in {"plain_text", "empty"}:
        return None
    return reconstructed.metadata()


def is_local_target(url: str) -> bool:
    parsed = urlsplit(str(url or ""))
    host = (parsed.hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def sanitize_exchange_payload(exchange: ProxyExchange, include_bodies: bool = False) -> dict[str, Any]:
    payload = exchange.model_dump(mode="json")
    if not include_bodies:
        for key in ("request_body", "response_body", "prompt_text", "response_text"):
            if payload.get(key):
                payload[key] = REDACTED
    payload["request_headers"] = redact_headers(payload.get("request_headers", {}))
    payload["response_headers"] = redact_headers(payload.get("response_headers", {}))
    return payload


class ProxyCaptureStore:
    """Local-only session store for passive proxy captures and replay artifacts."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.active_session_id: str | None = None

    def _session_dir(self, session_id: str) -> Path:
        return self.root / session_id

    def _session_path(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "session.json"

    def _exchange_path(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "exchanges.jsonl"

    def start_session(self, target_url: str = "", mode: str = "passive", retention_limit: int = 500) -> dict[str, Any]:
        session_id = f"proxy_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        session = {
            "session_id": session_id,
            "target_url": target_url,
            "mode": mode,
            "status": "running",
            "started_at": _utc_now(),
            "stopped_at": None,
            "retention_limit": max(1, int(retention_limit)),
            "security": {
                "local_storage_only": True,
                "headers_redacted": True,
                "warning": "Proxy captures may contain sensitive request and response bodies.",
            },
        }
        self._session_dir(session_id).mkdir(parents=True, exist_ok=True)
        save_json(self._session_path(session_id), session)
        self.active_session_id = session_id
        return session

    def stop_session(self, session_id: str | None = None) -> dict[str, Any]:
        target_id = session_id or self.active_session_id
        if not target_id:
            return {"status": "stopped", "session_id": None}
        session = self.get_session(target_id)
        session["status"] = "stopped"
        session["stopped_at"] = _utc_now()
        save_json(self._session_path(target_id), session)
        if self.active_session_id == target_id:
            self.active_session_id = None
        return session

    def status(self) -> dict[str, Any]:
        if not self.active_session_id:
            return {"running": False, "session_id": None}
        session = self.get_session(self.active_session_id)
        return {"running": session.get("status") == "running", **session}

    def list_sessions(self) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("proxy_*/session.json"), reverse=True):
            with path.open("r", encoding="utf-8") as handle:
                session = json.load(handle)
            session["exchange_count"] = len(self.load_exchanges(str(session["session_id"])))
            sessions.append(session)
        return sessions

    def update_session(self, session_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        session = self.get_session(session_id)
        session.update(updates)
        save_json(self._session_path(session_id), session)
        return session

    def get_session(self, session_id: str) -> dict[str, Any]:
        path = self._session_path(session_id)
        if not path.exists():
            raise FileNotFoundError(f"Proxy session not found: {session_id}")
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def load_exchanges(self, session_id: str) -> list[ProxyExchange]:
        path = self._exchange_path(session_id)
        if not path.exists():
            return []
        exchanges: list[ProxyExchange] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    exchanges.append(ProxyExchange(**json.loads(line)))
        return exchanges

    def _enforce_retention(self, session_id: str) -> None:
        session = self.get_session(session_id)
        retention_limit = max(1, int(session.get("retention_limit", 500) or 500))
        path = self._exchange_path(session_id)
        if not path.exists():
            return
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) <= retention_limit:
            return
        path.write_text("\n".join(lines[-retention_limit:]) + "\n", encoding="utf-8")

    def record_exchange(
        self,
        *,
        session_id: str | None = None,
        method: str = "POST",
        url: str = "",
        request_headers: dict[str, Any] | None = None,
        request_body: Any = None,
        response_status: int | None = None,
        response_headers: dict[str, Any] | None = None,
        response_body: Any = None,
        transport: str = "http",
        metadata: dict[str, Any] | None = None,
    ) -> ProxyExchange:
        target_id = session_id or self.active_session_id
        if not target_id:
            raise RuntimeError("No active proxy capture session")
        prompt_text, response_text = extract_prompt_response(request_body, response_body)
        exchange_metadata = dict(metadata or {})
        stream_metadata = stream_reconstruction_metadata(response_body, response_headers)
        if stream_metadata:
            exchange_metadata["stream_reconstruction"] = stream_metadata
        request_body_text = request_body if isinstance(request_body, str) else json.dumps(request_body, ensure_ascii=False, default=str)
        response_body_text = response_body if isinstance(response_body, str) else json.dumps(response_body, ensure_ascii=False, default=str)
        exchange = ProxyExchange(
            exchange_id=f"ex_{uuid.uuid4().hex[:12]}",
            session_id=target_id,
            transport=transport,  # type: ignore[arg-type]
            method=method.upper(),
            url=url,
            request_headers=redact_headers(request_headers),
            request_body=request_body_text,
            response_status=response_status,
            response_headers=redact_headers(response_headers),
            response_body=response_body_text,
            prompt_text=prompt_text,
            response_text=response_text,
            metadata=exchange_metadata,
        )
        append_jsonl(self._exchange_path(target_id), exchange.model_dump(mode="json"))
        self._enforce_retention(target_id)
        return exchange
