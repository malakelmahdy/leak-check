from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from leakcheck.common.schemas import ConversationTrace, DetectionResult, ProxyExchange
from leakcheck.detect.detector import Detector
from leakcheck.proxy.sessions import reconstruct_conversation
from leakcheck.scoring.score import compute_severity, score_output_fields

REDACTED_TEXT = "[REDACTED]"


@dataclass(frozen=True)
class ProxyScoringConfig:
    similarity_model: str
    similarity_threshold: float = 0.50
    use_learned: bool = False
    learned_path: str | None = None
    category: str = "proxy_capture"


def _empty_detection_payload(category: str, error: str) -> dict[str, Any]:
    return {
        "category": category,
        "verdict": "error",
        "error": error,
        "confidence": 0.0,
        "rule_hits": [],
        "similarity_score": 0.0,
        "response_signals": [],
        "severity": 0.0,
        "level": "low",
        "attack_risk_score": 0.0,
        "attack_risk_band": "none",
        "attack_risk_rationale": [],
        "signoff_severity": 0.0,
        "signoff_severity_label": "none",
        "leak_severity_score": 0.0,
        "leak_severity_band": "none",
        "leak_severity_rationale": [],
        "evidence": {"error": error},
    }


def detection_payload(det: DetectionResult, *, repeatability: float | None = None) -> dict[str, Any]:
    score = compute_severity(det, repeatability=repeatability)
    return {
        "category": det.category,
        "verdict": det.verdict,
        "confidence": det.confidence,
        "rule_hits": det.rule_hits,
        "similarity_score": det.similarity_score,
        "response_signals": det.response_signals,
        "evidence": det.evidence,
        **score_output_fields(score),
    }


class ProxyScoringService:
    """Score reconstructed proxy prompt/response turns with the standard detector."""

    def __init__(
        self,
        config: ProxyScoringConfig,
        *,
        detector_factory: Callable[[], Detector] | None = None,
    ):
        self.config = config
        self._detector_factory = detector_factory

    def _detector(self) -> Detector:
        if self._detector_factory is not None:
            return self._detector_factory()
        return Detector(
            similarity_model=self.config.similarity_model,
            similarity_threshold=self.config.similarity_threshold,
            use_learned=self.config.use_learned,
            learned_path=self.config.learned_path,
        )

    def score_trace(self, trace: ConversationTrace) -> list[dict[str, Any]]:
        detector = self._detector()
        findings: list[dict[str, Any]] = []
        for turn in trace.turns:
            if not turn.prompt_text and not turn.response_text:
                continue
            try:
                det = detector.detect(
                    prompt_id=turn.turn_id,
                    category=self.config.category,
                    prompt_text=turn.prompt_text,
                    response_text=turn.response_text,
                )
                detection = detection_payload(det, repeatability=None)
            except Exception as exc:
                detection = _empty_detection_payload(self.config.category, str(exc))
            findings.append(
                {
                    "turn_number": turn.turn_number,
                    "turn_id": turn.turn_id,
                    "exchange_id": turn.metadata.get("exchange_id"),
                    "prompt_text": turn.prompt_text,
                    "response_text": turn.response_text,
                    "detection": detection,
                }
            )
        return findings

    def score_exchanges(self, exchanges: list[ProxyExchange], *, conversation_id: str) -> dict[str, Any]:
        trace = reconstruct_conversation(exchanges, conversation_id=conversation_id)
        findings = self.score_trace(trace)
        return {
            "conversation": trace.model_dump(mode="json"),
            "findings": findings,
            "scoring": summarize_proxy_findings(findings),
        }


def summarize_proxy_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [dict(item.get("detection", {}) or {}) for item in findings]
    worst_leak = max((float(item.get("signoff_severity", item.get("severity", 0.0)) or 0.0) for item in scored), default=0.0)
    worst_attack = max((float(item.get("attack_risk_score", 0.0) or 0.0) for item in scored), default=0.0)
    actionable = [
        item
        for item in scored
        if str(item.get("verdict", "safe")) != "safe"
        or float(item.get("signoff_severity", item.get("severity", 0.0)) or 0.0) > 0.0
    ]
    return {
        "turn_count": len(findings),
        "finding_count": len(actionable),
        "worst_leak_severity": round(worst_leak, 1),
        "worst_attack_risk": round(worst_attack, 1),
        "scored": True,
    }


def redact_scored_payload_bodies(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    conversation = dict(redacted.get("conversation", {}) or {})
    turns = []
    for turn in conversation.get("turns", []) or []:
        if not isinstance(turn, dict):
            continue
        turns.append(
            {
                **turn,
                "prompt_text": REDACTED_TEXT if turn.get("prompt_text") else "",
                "response_text": REDACTED_TEXT if turn.get("response_text") else "",
            }
        )
    if conversation:
        conversation["turns"] = turns
        redacted["conversation"] = conversation

    findings = []
    for finding in redacted.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        findings.append(
            {
                **finding,
                "prompt_text": REDACTED_TEXT if finding.get("prompt_text") else "",
                "response_text": REDACTED_TEXT if finding.get("response_text") else "",
            }
        )
    redacted["findings"] = findings
    return redacted
