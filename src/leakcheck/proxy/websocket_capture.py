from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class WebSocketMessage:
    message_id: str
    session_id: str
    connection_id: str
    direction: str
    payload: str
    order: int
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)


class WebSocketCaptureBuffer:
    """In-memory capture buffer for future WebSocket proxy integration."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.connection_id = f"ws_{uuid.uuid4().hex[:10]}"
        self.messages: list[WebSocketMessage] = []

    def record(self, direction: str, payload: str, metadata: dict[str, Any] | None = None) -> WebSocketMessage:
        message = WebSocketMessage(
            message_id=f"wsm_{uuid.uuid4().hex[:12]}",
            session_id=self.session_id,
            connection_id=self.connection_id,
            direction=direction,
            payload=payload,
            order=len(self.messages) + 1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        self.messages.append(message)
        return message
