from __future__ import annotations

import logging
import time
from typing import Any

import requests
from requests import exceptions as requests_exceptions

from leakcheck.common.schemas import LLMResponseRecord

logger = logging.getLogger(__name__)


class LLMClient:
    """HTTP client for OpenAI-compatible chat completion endpoints.

    Handles retry on timeout, tolerant response parsing (OpenAI format + text/response/output fallbacks),
    and latency measurement.
    """

    def __init__(self, endpoint: str, timeout_s: int = 60, retries: int = 2):
        """Configure the client with endpoint URL, per-request timeout in seconds, and max retry count."""
        self.endpoint = endpoint
        self.timeout_s = timeout_s
        self.retries = retries

    def generate(self, prompt_text: str, params: dict[str, Any] | None = None) -> LLMResponseRecord:
        """
        LM Studio (OpenAI-compatible) chat completions:
        POST /v1/chat/completions
        JSON: { "model": "...", "messages": [{"role":"user","content":"..."}], ... }

        We keep this function tolerant:
        - If the server returns OpenAI-style choices[0].message.content -> use it
        - Otherwise fall back to keys like text/response/output
        """
        params = params or {}

        # Pull standard knobs (and remove them from params so we don't accidentally send duplicates)
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

        # Allow passing extra OpenAI-compatible fields if you add them later (top_p, stop, etc.)
        # Anything remaining in params will be included.
        payload.update(params)

        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            t0 = time.perf_counter()
            try:
                r = requests.post(self.endpoint, json=payload, timeout=(10, self.timeout_s))
                latency_ms = int((time.perf_counter() - t0) * 1000)

                # If LM Studio returns 400, we want the body because it explains exactly what's wrong.
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text}")

                data = r.json() if "application/json" in r.headers.get("content-type", "") else {"text": r.text}

                # Primary: OpenAI-compatible format
                text = ""
                try:
                    text = data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    # Fallback: older/simple formats
                    text = (
                        (data.get("text") if isinstance(data, dict) else None)
                        or (data.get("response") if isinstance(data, dict) else None)
                        or (data.get("output") if isinstance(data, dict) else None)
                        or ""
                    )
                    if not text:
                        logger.warning(
                            "LLM response format unrecognized — no text extracted. "
                            "Keys present: %s",
                            list(data.keys()) if isinstance(data, dict) else type(data).__name__,
                        )

                if not isinstance(text, str):
                    text = str(text)

                return LLMResponseRecord(
                    prompt_id="",
                    response_text=text,
                    latency_ms=latency_ms,
                    model=(data.get("model") if isinstance(data, dict) else None) or model_name,
                    raw=data if isinstance(data, dict) else {"raw": data},
                )

            except requests_exceptions.ReadTimeout as e:
                last_err = RuntimeError(
                    f"LLM read timed out after {self.timeout_s}s at {self.endpoint}. "
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
