from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from leakcheck.common.schemas import ProxyExchange
from leakcheck.proxy.http_capture import redact_headers

SKIP_REPLAY_HEADERS = {
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "authorization",
    "cookie",
    "proxy-authorization",
}


@dataclass(frozen=True)
class ReplayResult:
    exchange_id: str
    status_code: int | None
    response_body: str
    error: str = ""


def replay_exchange(exchange: ProxyExchange, timeout_s: int = 30) -> ReplayResult:
    """Replay one sanitized HTTP exchange against its original URL."""
    if not exchange.url:
        return ReplayResult(exchange.exchange_id, None, "", "exchange has no URL")
    headers = {
        key: value
        for key, value in dict(exchange.request_headers).items()
        if key.lower() not in SKIP_REPLAY_HEADERS and value != "[REDACTED]"
    }
    try:
        response = requests.request(
            method=exchange.method or "POST",
            url=exchange.url,
            headers=headers,
            data=exchange.request_body,
            timeout=timeout_s,
        )
        return ReplayResult(
            exchange_id=exchange.exchange_id,
            status_code=response.status_code,
            response_body=response.text,
        )
    except Exception as exc:
        return ReplayResult(exchange.exchange_id, None, "", str(exc))


def replay_payload(result: ReplayResult) -> dict[str, Any]:
    return {
        "exchange_id": result.exchange_id,
        "status_code": result.status_code,
        "response_body": result.response_body,
        "error": result.error,
        "response_headers_redacted": redact_headers({}),
    }


def compare_replay(original: ProxyExchange, result: ReplayResult) -> dict[str, Any]:
    original_text = (original.response_text or original.response_body or "").strip()
    replay_text = (result.response_body or "").strip()
    return {
        "exchange_id": original.exchange_id,
        "status_matches": result.status_code == original.response_status,
        "response_matches_exactly": bool(original_text) and original_text == replay_text,
        "original_status": original.response_status,
        "replay_status": result.status_code,
        "original_response_length": len(original_text),
        "replay_response_length": len(replay_text),
        "error": result.error,
    }
