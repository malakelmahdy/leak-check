from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from leakcheck.common.schemas import MutationRecord, PromptRecord


class MutationStrategy(ABC):
    """Interface implemented by prompt mutation strategies."""

    strategy_name: str
    template_version: str = ""

    @abstractmethod
    def generate(
        self,
        base_prompt: PromptRecord,
        campaign_config: dict[str, Any],
        seed: int,
        conversation_state: dict[str, Any] | None = None,
    ) -> list[MutationRecord]:
        """Return one or more mutation records for a prompt and optional conversation state."""
