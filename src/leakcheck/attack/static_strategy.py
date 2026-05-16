from __future__ import annotations

from typing import Any

from leakcheck.attack.mutate import mutate_prompt, operators_from_level
from leakcheck.attack.strategies import MutationStrategy
from leakcheck.common.schemas import MutationRecord, MutationStrategyMetadata, PromptRecord


class StaticMutationStrategy(MutationStrategy):
    """Adapter around the existing deterministic mutation pipeline."""

    strategy_name = "static"
    template_version = "static_mutate_v1"

    def generate(
        self,
        base_prompt: PromptRecord,
        campaign_config: dict[str, Any],
        seed: int,
        conversation_state: dict[str, Any] | None = None,
    ) -> list[MutationRecord]:
        attack_cfg = dict(campaign_config.get("attack", {}) or {})
        mutation_cfg = dict(campaign_config.get("mutation", {}) or {})
        attack_enabled = bool(attack_cfg.get("enabled", True))
        mutation_level = int(attack_cfg.get("mutation_level", 0) or 0)
        operators = operators_from_level(mutation_level, list(attack_cfg.get("operators", [])))
        turn_number = int((conversation_state or {}).get("turn_number", 1))

        if not attack_enabled:
            return [
                MutationRecord(
                    base_id=base_prompt.id,
                    mutation_id=f"{base_prompt.id}_m0",
                    operators=[],
                    text=base_prompt.text,
                    seed=seed,
                    mutation_source=self.strategy_name,
                    strategy_metadata=MutationStrategyMetadata(
                        strategy_name=self.strategy_name,
                        template_version=self.template_version,
                        seed=seed,
                        operators=[],
                        turn_number=turn_number,
                    ),
                )
            ]

        mutations_per = int(mutation_cfg.get("count", attack_cfg.get("mutations_per_prompt", 1)))
        if conversation_state is not None:
            mutations_per = 1
        records: list[MutationRecord] = []
        for mutation_idx in range(1, mutations_per + 1):
            idx = int((conversation_state or {}).get("mutation_idx", mutation_idx))
            record = mutate_prompt(base_prompt, operators, seed=seed, idx=idx)
            record.mutation_source = self.strategy_name
            record.strategy_metadata = MutationStrategyMetadata(
                strategy_name=self.strategy_name,
                template_version=self.template_version,
                seed=seed,
                operators=list(record.operators),
                turn_number=turn_number,
                metadata={"mutation_index": idx},
            )
            records.append(record)
        return records
