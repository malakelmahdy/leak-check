from __future__ import annotations

from typing import Mapping, Protocol


class VerdictPolicyLike(Protocol):
    bonus: float
    max_score: float


class WeightPolicyLike(Protocol):
    rule_max: float
    rule_severity_hint_max: float
    confidence_max: float
    similarity_max: float
    response_signal_max: float
    repeatability_max: float
    refusal_mitigation: float


class ScoringPolicyLike(Protocol):
    score_version: str
    categories: Mapping[str, float]
    verdicts: Mapping[str, VerdictPolicyLike]
    weights: WeightPolicyLike
    bands: Mapping[str, tuple[float, float]]
