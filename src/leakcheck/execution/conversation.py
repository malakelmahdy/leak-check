from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from leakcheck.attack.strategies import MutationStrategy
from leakcheck.common.schemas import ConversationTurn, DetectionResult, LLMResponseRecord, PromptRecord
from leakcheck.detect.detector import Detector
from leakcheck.llm.client import LLMClient
from leakcheck.scoring.score import ScoringPolicy, compute_severity, score_output_fields


@dataclass(frozen=True)
class ConversationRunResult:
    records: list[dict[str, Any]]
    turns: list[ConversationTurn]


def _target_cfg(cfg: dict[str, Any]) -> tuple[str, str]:
    target_cfg = dict(cfg.get("target", {}) or {})
    return str(target_cfg.get("type", "endpoint")), str(target_cfg.get("transport", "http"))


def _conversation_id(base: PromptRecord, seed: int, strategy_name: str) -> str:
    return f"{base.id}:{strategy_name}:{seed}"


def _chain(values: list[str]) -> list[str]:
    return [value for value in values if value]


def _record_for_turn(
    *,
    prompt: PromptRecord,
    mutation: Any,
    response: LLMResponseRecord,
    detection: DetectionResult,
    repeatability: float,
    scoring_policy: ScoringPolicy,
    target_type: str,
    transport: str,
    conversation_id: str,
    turn: ConversationTurn,
    turns: list[ConversationTurn],
    conversation_score: float,
    worst_turn_score: float,
) -> dict[str, Any]:
    score = compute_severity(detection, repeatability=repeatability, policy=scoring_policy)
    prompt_chain = _chain([item.prompt_text for item in turns])
    response_chain = _chain([item.response_text for item in turns])
    return {
        "base_id": prompt.id,
        "prompt_id": mutation.mutation_id,
        "category": prompt.category,
        "mutation_level": 0,
        "mutation_preset": "conversation",
        "operators": mutation.operators,
        "prompt_text": mutation.text,
        "response_text": response.response_text,
        "latency_ms": response.latency_ms,
        "verdict": detection.verdict,
        "is_attempt": detection.verdict in ("attack_attempt", "attack_success"),
        "is_success": detection.verdict == "attack_success",
        "over_refusal": bool(detection.evidence.get("over_refusal", False)),
        "confidence": detection.confidence,
        "rule_hits": detection.rule_hits,
        "similarity_score": detection.similarity_score,
        "response_signals": detection.response_signals,
        "evidence": detection.evidence,
        "conversation_id": conversation_id,
        "turn_number": turn.turn_number,
        "conversation_length": len(turns),
        "prompt_chain": prompt_chain,
        "response_chain": response_chain,
        "worst_turn_score": worst_turn_score,
        "conversation_score": conversation_score,
        "mutation_source": mutation.mutation_source,
        "strategy_metadata": mutation.strategy_metadata.model_dump() if mutation.strategy_metadata else {},
        "target_type": target_type,
        "transport": transport,
        "conversation_turn": turn.model_dump(mode="json"),
        **score_output_fields(score),
    }


def run_conversation(
    *,
    prompt: PromptRecord,
    cfg: dict[str, Any],
    seed: int,
    strategy: MutationStrategy,
    client: LLMClient,
    llm_params: dict[str, Any],
    detector: Detector,
    scoring_policy: ScoringPolicy,
) -> ConversationRunResult:
    """Run one conversation trace for a base prompt and return result records."""
    conversation_cfg = dict(cfg.get("conversation", {}) or {})
    max_turns = max(1, int(conversation_cfg.get("max_turns", 1)))
    stop_on_success = bool(conversation_cfg.get("stop_on_success", True))
    target_type, transport = _target_cfg(cfg)
    conversation_id = _conversation_id(prompt, seed, strategy.strategy_name)
    turns: list[ConversationTurn] = []
    pending_records: list[tuple[Any, LLMResponseRecord, DetectionResult, ConversationTurn]] = []

    for turn_number in range(1, max_turns + 1):
        state = {
            "conversation_id": conversation_id,
            "turn_number": turn_number,
            "mutation_idx": turn_number,
            "objective": prompt.text,
            "history": list(turns),
            "last_response": turns[-1].response_text if turns else "",
        }
        mutations = strategy.generate(prompt, cfg, seed, conversation_state=state)
        if not mutations:
            break
        mutation = mutations[0]
        response = client.generate(mutation.text, params=llm_params)
        response.prompt_id = mutation.mutation_id
        parent_turn_id = turns[-1].turn_id if turns else None
        turn = ConversationTurn(
            turn_id=f"{conversation_id}:t{turn_number}",
            conversation_id=conversation_id,
            turn_number=turn_number,
            parent_turn_id=parent_turn_id,
            prompt_text=mutation.text,
            response_text=response.response_text,
            mutation_source=mutation.mutation_source,
            target_type=target_type,  # type: ignore[arg-type]
            transport=transport,  # type: ignore[arg-type]
            metadata={"prompt_id": mutation.mutation_id},
        )
        detection = detector.detect(
            prompt_id=mutation.mutation_id,
            category=prompt.category,
            prompt_text=mutation.text,
            response_text=response.response_text,
        )
        turns.append(turn)
        pending_records.append((mutation, response, detection, turn))
        if stop_on_success and detection.verdict == "attack_success":
            break

    success_flags = [1 if item[2].verdict == "attack_success" else 0 for item in pending_records]
    repeatability = sum(success_flags) / max(1, len(success_flags))
    turn_scores = [
        compute_severity(item[2], repeatability=repeatability, policy=scoring_policy).severity
        for item in pending_records
    ]
    worst_turn_score = max(turn_scores, default=0.0)
    conversation_score = worst_turn_score

    records = [
        _record_for_turn(
            prompt=prompt,
            mutation=mutation,
            response=response,
            detection=detection,
            repeatability=repeatability,
            scoring_policy=scoring_policy,
            target_type=target_type,
            transport=transport,
            conversation_id=conversation_id,
            turn=turn,
            turns=turns,
            conversation_score=conversation_score,
            worst_turn_score=worst_turn_score,
        )
        for mutation, response, detection, turn in pending_records
    ]
    return ConversationRunResult(records=records, turns=turns)
