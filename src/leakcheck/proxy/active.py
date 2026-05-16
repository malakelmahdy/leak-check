from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from leakcheck.common.run_utils import append_jsonl
from leakcheck.proxy.http_capture import ProxyCaptureStore


@dataclass(frozen=True)
class ActiveInjectionDecision:
    allowed: bool
    reason: str
    dry_run: bool = True


class ActiveInjectionGate:
    """Safety gate for future active prompt injection mode."""

    def __init__(self, cfg: dict[str, Any]):
        active_cfg = dict(cfg.get("active_injection", cfg) or {})
        self.enabled = bool(active_cfg.get("enabled", False))
        self.allowlist = {str(item).lower() for item in active_cfg.get("allowlist", []) or []}
        self.dry_run = bool(active_cfg.get("dry_run", True))
        self.max_prompt_count = max(0, int(active_cfg.get("max_prompt_count", 0) or 0))

    def decide(self, target_url: str, prompt_count: int) -> ActiveInjectionDecision:
        parsed = urlsplit(target_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"}:
            return ActiveInjectionDecision(False, "target URL must use http or https", dry_run=self.dry_run)
        if not host:
            return ActiveInjectionDecision(False, "target URL must include a host", dry_run=self.dry_run)
        if not parsed.path or parsed.path == "/":
            return ActiveInjectionDecision(False, "target URL must include an endpoint path", dry_run=self.dry_run)
        if not self.enabled:
            return ActiveInjectionDecision(False, "active injection is disabled", dry_run=True)
        if self.dry_run:
            return ActiveInjectionDecision(True, "dry-run preview only", dry_run=True)
        if host not in self.allowlist:
            return ActiveInjectionDecision(False, "target host is not allowlisted", dry_run=False)
        if self.max_prompt_count <= 0:
            return ActiveInjectionDecision(False, "max prompt count is not configured", dry_run=False)
        if int(prompt_count) > self.max_prompt_count:
            return ActiveInjectionDecision(False, "prompt count exceeds configured maximum", dry_run=False)
        return ActiveInjectionDecision(True, "active injection allowed", dry_run=False)


@dataclass(frozen=True)
class ActiveInjectionResult:
    prompt_index: int
    prompt_text: str
    dry_run: bool
    status_code: int | None = None
    exchange_id: str | None = None
    error: str = ""


def _audit_record(session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_injection": True,
        **payload,
    }


class ActiveInjectionRunner:
    """Execute explicitly enabled active prompt injection with audit logging."""

    def __init__(
        self,
        *,
        store: ProxyCaptureStore,
        session_id: str,
        cfg: dict[str, Any],
        audit_log_path: Any,
        timeout_s: int = 30,
    ):
        self.store = store
        self.session_id = session_id
        self.gate = ActiveInjectionGate(cfg)
        self.audit_log_path = audit_log_path
        self.timeout_s = int(timeout_s)
        self.stop_requested = False
        self._status: dict[str, Any] = {
            "session_id": session_id,
            "running": False,
            "stop_requested": False,
            "current_prompt_index": 0,
            "prompt_count": 0,
            "injected_count": 0,
            "error_count": 0,
            "dry_run": True,
            "target_url": "",
        }

    def stop(self) -> None:
        self.stop_requested = True
        self._status["stop_requested"] = True
        self._persist_status()
        append_jsonl(
            self.audit_log_path,
            _audit_record(self.session_id, {"event": "active_stop_requested"}),
        )

    def status(self) -> dict[str, Any]:
        return dict(self._status)

    def _persist_status(self) -> None:
        try:
            self.store.update_session(self.session_id, {"active_injection_status": dict(self._status)})
        except FileNotFoundError:
            return

    def preview(self, target_url: str, prompts: list[str]) -> dict[str, Any]:
        decision = self.gate.decide(target_url, len(prompts))
        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "dry_run": decision.dry_run,
            "target_url": target_url,
            "prompt_count": len(prompts),
            "prompts": [
                {"index": idx + 1, "prompt_text": prompt, "injected": False}
                for idx, prompt in enumerate(prompts)
            ],
        }

    def run(self, target_url: str, prompts: list[str]) -> list[ActiveInjectionResult]:
        decision = self.gate.decide(target_url, len(prompts))
        self._status.update(
            {
                "running": True,
                "stop_requested": False,
                "current_prompt_index": 0,
                "prompt_count": len(prompts),
                "injected_count": 0,
                "error_count": 0,
                "dry_run": decision.dry_run,
                "target_url": target_url,
            }
        )
        self._persist_status()
        append_jsonl(
            self.audit_log_path,
            _audit_record(
                self.session_id,
                {
                    "event": "active_injection_decision",
                    "target_url": target_url,
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "dry_run": decision.dry_run,
                    "prompt_count": len(prompts),
                },
            ),
        )
        if not decision.allowed:
            self._status["running"] = False
            self._status["error_count"] = 1
            self._persist_status()
            return [
                ActiveInjectionResult(
                    prompt_index=0,
                    prompt_text="",
                    dry_run=decision.dry_run,
                    error=decision.reason,
                )
            ]

        results: list[ActiveInjectionResult] = []
        try:
            for idx, prompt in enumerate(prompts, 1):
                self._status["current_prompt_index"] = idx
                self._persist_status()
                if self.stop_requested:
                    self._status["stop_requested"] = True
                    self._persist_status()
                    results.append(ActiveInjectionResult(idx, prompt, decision.dry_run, error="stop requested"))
                    break
                audit_payload = {
                    "event": "active_prompt_preview" if decision.dry_run else "active_prompt_injected",
                    "target_url": target_url,
                    "prompt_index": idx,
                    "prompt_text": prompt,
                    "dry_run": decision.dry_run,
                }
                append_jsonl(self.audit_log_path, _audit_record(self.session_id, audit_payload))
                if decision.dry_run:
                    results.append(ActiveInjectionResult(idx, prompt, dry_run=True))
                    continue
                try:
                    response = requests.post(
                        target_url,
                        json={
                            "message": prompt,
                            "metadata": {
                                "leakcheck_injected": True,
                                "session_id": self.session_id,
                                "prompt_index": idx,
                            },
                        },
                        timeout=self.timeout_s,
                    )
                    exchange = self.store.record_exchange(
                        session_id=self.session_id,
                        method="POST",
                        url=target_url,
                        request_headers={"content-type": "application/json"},
                        request_body={
                            "message": prompt,
                            "metadata": {"leakcheck_injected": True, "prompt_index": idx},
                        },
                        response_status=response.status_code,
                        response_headers=dict(response.headers.items()),
                        response_body=response.text,
                        transport="http",
                        metadata={"active_injection": True, "prompt_index": idx},
                    )
                    self._status["injected_count"] = int(self._status["injected_count"]) + 1
                    self._persist_status()
                    results.append(
                        ActiveInjectionResult(
                            prompt_index=idx,
                            prompt_text=prompt,
                            dry_run=False,
                            status_code=response.status_code,
                            exchange_id=exchange.exchange_id,
                        )
                    )
                except Exception as exc:
                    self._status["error_count"] = int(self._status["error_count"]) + 1
                    self._persist_status()
                    results.append(ActiveInjectionResult(idx, prompt, dry_run=False, error=str(exc)))
        finally:
            self._status["running"] = False
            self._persist_status()
        return results
