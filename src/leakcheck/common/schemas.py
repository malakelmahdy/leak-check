from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class PromptRecord(BaseModel):
    """Input prompt record ingested from a dataset. Carries category, raw text, and optional metadata into the mutation and detection pipeline."""

    id: str
    category: str
    text: str
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class MutationRecord(BaseModel):
    """Mutated variant of a base prompt produced by the attack mutation stage. Records which operators were applied and the resulting text."""

    base_id: str
    mutation_id: str
    operators: list[str]
    text: str
    seed: int


class LLMResponseRecord(BaseModel):
    """Raw output returned by the LLM for a single prompt. Preserves response text, latency, and the original API payload for downstream detection."""

    prompt_id: str
    response_text: str
    latency_ms: int
    model: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """Verdict and supporting evidence produced by the detector for one prompt. Aggregates rule hits, semantic similarity, and response signals into a single confidence-weighted verdict."""

    prompt_id: str
    category: str
    verdict: str  # "attack_success" | "attack_attempt" | "safe"
    confidence: float
    rule_hits: list[str] = Field(default_factory=list)
    similarity_score: float = 0.0
    response_signals: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class SeverityInput(BaseModel):
    """Enriched input assembled for the severity scoring stage. Collects verdict, rule hits, classifier output, and signal data from detection into a single scoring payload."""

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
    """Single factor's contribution to a composite severity score. Records the factor name, its value, the score delta it caused, and a human-readable reason."""

    factor: str
    kind: str
    value: str | float | None = None
    delta: float
    reason: str


class ScoreExplanation(BaseModel):
    """Human-readable explanation of a v1 severity score. Summarises the final score, top contributing factors, evidence, and any scoring caveats for report output."""

    score_version: str
    final_score: float
    severity_label: str
    verdict: str
    top_contributors: list[ScoreContribution] = Field(default_factory=list)
    evidence_summary: list[str] = Field(default_factory=list)
    rationale: str
    caveats: list[str] = Field(default_factory=list)


class ScoreRecord(BaseModel):
    """Complete v1 scoring result for one prompt. Holds the 0–10 severity value, band label, and an optional structured explanation written to results.jsonl."""

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
    """Single piece of evidence emitted by one detector. Captures the detector family, leak type, confidence, and optional character offsets of the candidate text."""

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
    """Result of post-detection validation for a piece of evidence. Records the validator's status decision and any confidence adjustment it applies to the parent finding."""

    validation_id: str
    validator_id: str
    status: Literal["validated", "rejected", "inconclusive", "not_applicable"]
    confidence_delta: float = Field(ge=-1.0, le=1.0, default=0.0)
    validated_asset_id: Optional[str] = None
    validated_leak_type: Optional[str] = None
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class LeakageFinding(BaseModel):
    """Complete finding record representing a detected information leak. Combines asset sensitivity, exposure extent, exploitability, supporting evidence, and validation outcomes into a single reportable unit."""

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
    """V2 severity score computed for a single LeakageFinding. Derives a 0–10 final score from impact, evidence confidence, exploitability, and exposure extent."""

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
    """Attack risk assessment capturing intent confidence, capability, and sophistication of an observed attack. Produces a 0–10 final score and severity band used by the v2 scoring path."""

    score_version: str
    attack_intent_confidence: float = Field(ge=0.0, le=1.0)
    attack_capability: float = Field(ge=0.0, le=1.0)
    attack_sophistication: float = Field(ge=0.0, le=1.0)
    persistence_or_override_strength: float = Field(ge=0.0, le=1.0)
    execution_readiness: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=10.0)
    severity_band: Literal["none", "low", "medium", "high", "critical"]
    rationale: list[str] = Field(default_factory=list)
