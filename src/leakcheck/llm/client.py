from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlsplit

import requests
from requests import exceptions as requests_exceptions

from leakcheck.common.run_utils import sanitize_endpoint_url
from leakcheck.common.schemas import LLMResponseRecord

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = {
    "lmstudio",
    "lmstudio_openai_compat",
    "llama.cpp",
    "llamacpp",
    "local_llama",
    "openai_compatible",
    "openai-compatible",
}


class LLMConfigError(ValueError):
    """Raised when LLM endpoint configuration is invalid before execution starts."""


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def validate_llm_config(llm_cfg: dict[str, Any]) -> dict[str, Any]:
    """Validate the V1 OpenAI-compatible LLM config and return normalized fields."""
    errors: list[str] = []
    provider = str(llm_cfg.get("provider", "")).strip().lower()
    endpoint = str(llm_cfg.get("endpoint", "")).strip()
    params = dict(llm_cfg.get("params", {}) or {})
    model = str(params.get("model", "")).strip()

    if not provider:
        errors.append("llm.provider is required")
    elif provider not in SUPPORTED_PROVIDERS:
        errors.append(f"llm.provider is unsupported: {provider}")

    parsed = urlsplit(endpoint)
    if not endpoint:
        errors.append("llm.endpoint is required")
    elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
        errors.append("llm.endpoint must be an absolute http(s) URL")

    if not model:
        errors.append("llm.params.model is required")

    try:
        timeout_s = int(llm_cfg.get("timeout_s", 60))
        if timeout_s <= 0:
            errors.append("llm.timeout_s must be positive")
    except (TypeError, ValueError):
        timeout_s = 60
        errors.append("llm.timeout_s must be an integer")

    try:
        retries = int(llm_cfg.get("retries", 2))
        if retries < 0:
            errors.append("llm.retries must be non-negative")
    except (TypeError, ValueError):
        retries = 2
        errors.append("llm.retries must be an integer")

    temperature = params.get("temperature", 0.3)
    if not _is_number(temperature):
        errors.append("llm.params.temperature must be numeric")

    try:
        max_tokens = int(params.get("max_tokens", 256))
        if max_tokens <= 0:
            errors.append("llm.params.max_tokens must be positive")
    except (TypeError, ValueError):
        max_tokens = 256
        errors.append("llm.params.max_tokens must be an integer")

    if errors:
        raise LLMConfigError("; ".join(errors))

    return {
        "provider": provider,
        "endpoint": endpoint,
        "safe_endpoint": sanitize_endpoint_url(endpoint),
        "model": model,
        "timeout_s": timeout_s,
        "retries": retries,
        "temperature": float(temperature),
        "max_tokens": max_tokens,
    }


def response_shape(raw: Any) -> str:
    """Describe the response format without including response content."""
    if isinstance(raw, dict):
        if isinstance(raw.get("choices"), list):
            return "openai_chat_completions"
        for key in ("text", "response", "output"):
            if key in raw:
                return f"flat_{key}"
        return "json_object"
    return type(raw).__name__


class LLMClient:
    """HTTP client for OpenAI-compatible chat completion endpoints."""

    def __init__(self, endpoint: str, timeout_s: int = 60, retries: int = 2, provider: str = "openai_compatible"):
        """Configure the client with endpoint URL, per-request timeout in seconds, and max retry count."""
        self.endpoint = endpoint
        self.safe_endpoint = sanitize_endpoint_url(endpoint)
        self.timeout_s = timeout_s
        self.retries = retries
        self.provider = provider

    def generate(self, prompt_text: str, params: dict[str, Any] | None = None) -> LLMResponseRecord:
        """
        Call an OpenAI-compatible chat completions endpoint and normalize the response
        into `LLMResponseRecord`.
        """
        params = dict(params or {})

        model_name = params.pop("model", "llama-3.2-3b-instruct")
        temperature = params.pop("temperature", 0.3)
        max_tokens = params.pop("max_tokens", 256)
        stream = params.pop("stream", False)

        payload: dict[str, Any] = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt_text}],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }
        payload.update(params)

        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            t0 = time.perf_counter()
            try:
                r = requests.post(self.endpoint, json=payload, timeout=(10, self.timeout_s))
                latency_ms = int((time.perf_counter() - t0) * 1000)

                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text}")

                data = r.json() if "application/json" in r.headers.get("content-type", "") else {"text": r.text}
                text = self._extract_text(data)

                return LLMResponseRecord(
                    prompt_id="",
                    response_text=text,
                    latency_ms=latency_ms,
                    model=(data.get("model") if isinstance(data, dict) else None) or model_name,
                    raw={
                        **data,
                        "_leakcheck": {
                            "provider": self.provider,
                            "response_shape": response_shape(data),
                            "raw_response_saved": True,
                        },
                    } if isinstance(data, dict) else {"raw": data},
                )

            except requests_exceptions.ReadTimeout as e:
                last_err = RuntimeError(
                    f"LLM read timed out after {self.timeout_s}s at {self.safe_endpoint}. "
                    "Increase llm.timeout_s or reduce the local model workload."
                )
                if attempt < self.retries:
                    continue
                raise RuntimeError(f"LLM request failed after retries: {last_err}") from e
            except Exception as e:
                last_err = e
                if attempt < self.retries:
                    continue
                raise RuntimeError(f"LLM request failed after retries: {e}") from e

        raise RuntimeError(f"LLM request failed: {last_err}")

    @staticmethod
    def _extract_text(data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            text = data.get("text") or data.get("response") or data.get("output") or ""

        if not text:
            raise RuntimeError(f"Malformed LLM response: no text field found; response shape={response_shape(data)}")
        return text if isinstance(text, str) else str(text)
