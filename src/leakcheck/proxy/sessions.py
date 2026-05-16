from __future__ import annotations

from typing import Iterable

from leakcheck.common.schemas import ConversationTrace, ConversationTurn, ProxyExchange


def reconstruct_conversation(
    exchanges: Iterable[ProxyExchange],
    *,
    conversation_id: str | None = None,
) -> ConversationTrace:
    """Build a conversation trace from extracted prompt/response proxy exchanges."""
    ordered = sorted(list(exchanges), key=lambda item: item.timestamp)
    first = ordered[0] if ordered else None
    trace_id = conversation_id or (first.session_id if first else "proxy_empty")
    trace = ConversationTrace(
        conversation_id=trace_id,
        base_id=trace_id,
        category="proxy_capture",
        target_type="proxy",
        transport=(first.transport if first else "http"),  # type: ignore[arg-type]
        metadata={"exchange_count": len(ordered)},
    )
    parent_turn_id: str | None = None
    for idx, exchange in enumerate(ordered, 1):
        if not exchange.prompt_text and not exchange.response_text:
            continue
        turn_id = f"{trace_id}:t{idx}"
        trace.turns.append(
            ConversationTurn(
                turn_id=turn_id,
                conversation_id=trace_id,
                turn_number=len(trace.turns) + 1,
                parent_turn_id=parent_turn_id,
                prompt_text=exchange.prompt_text or "",
                response_text=exchange.response_text or "",
                mutation_source="proxy",
                target_type="proxy",
                transport=exchange.transport,
                timestamp=exchange.timestamp,
                metadata={
                    "exchange_id": exchange.exchange_id,
                    "url": exchange.url,
                    "status": exchange.response_status,
                },
            )
        )
        parent_turn_id = turn_id
    return trace
