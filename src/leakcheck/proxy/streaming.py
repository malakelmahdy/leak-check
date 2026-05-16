from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StreamReconstruction:
    text: str
    stream_format: str
    chunk_count: int
    confidence: float
    raw_retained: bool = True

    def metadata(self) -> dict[str, Any]:
        return {
            "stream_format": self.stream_format,
            "chunk_count": self.chunk_count,
            "confidence": self.confidence,
            "raw_retained": self.raw_retained,
            "reconstructed": bool(self.text),
        }


def reconstruct_openai_sse(payload: str) -> str:
    """Reconstruct text from OpenAI-style server-sent event delta chunks."""
    return _reconstruct_openai_sse_parts(payload)[0].strip()


def _reconstruct_openai_sse_parts(payload: str) -> tuple[str, int]:
    parts: list[str] = []
    chunks = 0
    for raw_line in str(payload or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        data = line.removeprefix("data:").strip()
        if not data or data == "[DONE]":
            continue
        chunks += 1
        try:
            item: Any = json.loads(data)
        except json.JSONDecodeError:
            parts.append(data)
            continue
        choices = item.get("choices") if isinstance(item, dict) else None
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                parts.append(delta["content"])
            elif isinstance(choice.get("text"), str):
                parts.append(choice["text"])
    return "".join(parts), chunks


def _first_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_first_text(item) for item in value)
    if isinstance(value, dict):
        for key in ("text", "content", "delta", "completion", "message"):
            text = _first_text(value.get(key))
            if text:
                return text
    return ""


def _sse_data_items(payload: str) -> tuple[list[Any], int]:
    items: list[Any] = []
    chunks = 0
    for raw_line in str(payload or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        data = line.removeprefix("data:").strip()
        if not data or data == "[DONE]":
            continue
        chunks += 1
        try:
            items.append(json.loads(data))
        except json.JSONDecodeError:
            items.append(data)
    return items, chunks


def _reconstruct_anthropic_sse(payload: str) -> StreamReconstruction:
    items, chunks = _sse_data_items(payload)
    parts: list[str] = []
    for item in items:
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        event_type = str(item.get("type", ""))
        if event_type in {"content_block_delta", "content_block_start"}:
            parts.append(_first_text(item.get("delta")) or _first_text(item.get("content_block")))
        elif event_type in {"message_delta", "completion"}:
            parts.append(_first_text(item))
    text = "".join(parts).strip()
    return StreamReconstruction(text, "anthropic_sse", chunks, 0.85 if text else 0.2)


def _reconstruct_jsonl(payload: str) -> StreamReconstruction:
    parts: list[str] = []
    chunks = 0
    for raw_line in str(payload or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        chunks += 1
        choices = item.get("choices") if isinstance(item, dict) else None
        if isinstance(choices, list) and choices:
            for choice in choices:
                parts.append(_first_text(choice.get("delta")) if isinstance(choice, dict) else "")
                if isinstance(choice, dict):
                    parts.append(_first_text(choice.get("message")) or _first_text(choice.get("text")))
        else:
            parts.append(_first_text(item))
    text = "".join(parts).strip()
    return StreamReconstruction(text, "jsonl", chunks, 0.75 if text else 0.1)


def reconstruct_stream(payload: str, content_type: str | None = None) -> StreamReconstruction:
    """Reconstruct common streamed LLM response formats into final text."""
    text = str(payload or "")
    lowered_type = str(content_type or "").lower()
    if not text.strip():
        return StreamReconstruction("", "empty", 0, 0.0)

    if looks_like_sse(text):
        reconstructed, chunks = _reconstruct_openai_sse_parts(text)
        return StreamReconstruction(reconstructed.strip(), "openai_sse", chunks, 0.9 if reconstructed.strip() else 0.2)

    if "text/event-stream" in lowered_type or "event:" in text or "data:" in text:
        anthropic = _reconstruct_anthropic_sse(text)
        if anthropic.text:
            return anthropic
        items, chunks = _sse_data_items(text)
        parts = [_first_text(item) for item in items]
        reconstructed = "".join(part for part in parts if part).strip()
        return StreamReconstruction(reconstructed, "generic_sse", chunks, 0.65 if reconstructed else 0.15)

    if "jsonl" in lowered_type or "ndjson" in lowered_type:
        return _reconstruct_jsonl(text)

    jsonl = _reconstruct_jsonl(text)
    if jsonl.text and jsonl.chunk_count > 1:
        return jsonl

    if "text/plain" in lowered_type:
        chunks = len([line for line in text.splitlines() if line.strip()]) or 1
        return StreamReconstruction(text.strip(), "chunked_text", chunks, 0.5)

    return StreamReconstruction(text.strip(), "plain_text", 1, 0.25)


def looks_like_sse(payload: Any) -> bool:
    return isinstance(payload, str) and "data:" in payload and ("choices" in payload or "[DONE]" in payload)
