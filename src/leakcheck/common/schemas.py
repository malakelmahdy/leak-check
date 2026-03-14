from __future__ import annotations

from typing import Any, Optional
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


class ScoreRecord(BaseModel):
    prompt_id: str
    severity: float  # 0-10
    level: str       # low/medium/high/critical
    components: dict[str, Any] = Field(default_factory=dict)
