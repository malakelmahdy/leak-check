from __future__ import annotations

from typing import Any, Optional, Literal
from pydantic import BaseModel, Field


class PromptRecord(BaseModel):
    id: str
    category: str
    text: str
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class MutationRecord(BaseModel):
    base_id: str
    mutation_id: str
    operators: list[str]
    text: str
    seed: int


class LLMResponseRecord(BaseModel):
    prompt_id: str
    response_text: str
    latency_ms: int
    model: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    prompt_id: str
    category: str
    verdict: str  # "attack_success" | "attack_attempt" | "safe"
    confidence: float
    rule_hits: list[str] = Field(default_factory=list)
    similarity_score: float = 0.0
    response_signals: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class SeverityInput(BaseModel):
    prompt_id: str
    attack_category: str
    final_verdict: str
    rule_hits: list[str] = Field(default_factory=list)
    rule_severity_hints: list[str] = Field(default_factory=list)
    classifier_label: Optional[str] = None
    classifier_confidence: Optional[float] = None
    similarity_score: Optional[float] = None
    response_signals: list[str] = Field(default_factory=list)
    repeatability: Optional[float] = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScoreContribution(BaseModel):
    factor: str
    kind: str
    value: Any = None
    delta: float
    reason: str


class ScoreExplanation(BaseModel):
    score_version: str
    final_score: float
    severity_label: str
    verdict: str
    top_contributors: list[ScoreContribution] = Field(default_factory=list)
    evidence_summary: list[str] = Field(default_factory=list)
    rationale: str
    caveats: list[str] = Field(default_factory=list)


class ScoreRecord(BaseModel):
    prompt_id: str
    severity: float  # 0-10
    level: str       # low/medium/high/critical
    severity_label: str = ""
    score_version: str = ""
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    components: dict[str, Any] = Field(default_factory=dict)
    explanation: Optional[ScoreExplanation] = None


class DetectorEvidence(BaseModel):
    evidence_id: str
    detector_id: str
    detector_family: Literal["static", "semantic", "dynamic"]
    evidence_kind: str
    leak_type: str = "other"
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    candidate_text: Optional[str] = None
    normalized_text: Optional[str] = None
    source_asset_id: Optional[str] = None
    start_char: Optional[int] = Field(default=None, ge=0)
    end_char: Optional[int] = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    validation_id: str
    validator_id: str
    status: Literal["validated", "rejected", "inconclusive", "not_applicable"]
    confidence_delta: float = Field(ge=-1.0, le=1.0, default=0.0)
    validated_asset_id: Optional[str] = None
    validated_leak_type: Optional[str] = None
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class LeakageFinding(BaseModel):
    finding_id: str
    prompt_id: str
    leak_type: str
    attack_category: str
    asset_id: Optional[str] = None
    asset_sensitivity: float = Field(ge=0.0, le=10.0, default=0.0)
    exposure_extent: float = Field(ge=0.0, le=1.0, default=0.0)
    exposure_level: Literal["none", "partial", "substantial", "full"] = "none"
    evidence_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    exploitability: float = Field(ge=0.0, le=1.0, default=0.0)
    exact_match: bool = False
    exact_canary: bool = False
    validated: bool = False
    supported_by: list[DetectorEvidence] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)
    summary: str = ""
    review_required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SeverityScore(BaseModel):
    finding_id: str
    score_version: str
    impact: float = Field(ge=0.0, le=10.0)
    evidence_confidence: float = Field(ge=0.0, le=1.0)
    exploitability: float = Field(ge=0.0, le=1.0)
    exposure_extent: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=10.0)
    severity_band: Literal["none", "low", "medium", "high", "critical"]
    review_required: bool = False
    rationale: list[str] = Field(default_factory=list)


class AttackRiskScore(BaseModel):
    score_version: str
    attack_intent_confidence: float = Field(ge=0.0, le=1.0)
    attack_capability: float = Field(ge=0.0, le=1.0)
    attack_sophistication: float = Field(ge=0.0, le=1.0)
    persistence_or_override_strength: float = Field(ge=0.0, le=1.0)
    execution_readiness: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=10.0)
    severity_band: Literal["none", "low", "medium", "high", "critical"]
    rationale: list[str] = Field(default_factory=list)
