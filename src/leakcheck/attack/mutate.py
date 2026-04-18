from __future__ import annotations

import random
from typing import Callable

from leakcheck.attack import operators as ops
from leakcheck.common.schemas import MutationRecord, PromptRecord

OP_MAP: dict[str, Callable[[str, random.Random], str]] = {
    # attack-style
    "prefix_injection": ops.prefix_injection,
    "role_wrapper": ops.role_wrapper,
    "instruction_stack": ops.instruction_stack,

    # neutral/benign-safe
    "benign_rephrase_prefix": ops.benign_rephrase_prefix,
    "benign_wrapper": ops.benign_wrapper,

    # shared
    "format_shift": ops.format_shift,
    "obfuscate_spacing": ops.obfuscate_spacing,
}

# Operators allowed per category
ATTACK_OPS = {
    "prefix_injection",
    "role_wrapper",
    "instruction_stack",
    "format_shift",
    "obfuscate_spacing",
}

BENIGN_OPS = {
    # only benign-safe transformations
    "benign_rephrase_prefix",
    "benign_wrapper",
    "format_shift",
    "obfuscate_spacing",
}


def _filter_ops_for_category(category: str, operators: list[str]) -> list[str]:
    # Default: treat unknown categories as attack categories
    if category == "benign":
        allowed = BENIGN_OPS
    else:
        allowed = ATTACK_OPS

    # If the campaign.yaml includes operators, we apply only those that are allowed.
    return [op for op in operators if op in allowed]


def mutate_prompt(base: PromptRecord, operators: list[str], seed: int, idx: int) -> MutationRecord:
    """Apply mutation operators to a base prompt, filtered by category.

    Benign prompts only receive benign-safe operators; all others receive attack operators.
    Seed + idx ensures deterministic reproducibility across runs.
    """
    rng = random.Random(seed + idx * 99991)
    text = base.text

    # ✅ Policy: benign prompts do NOT receive attack-style wrappers.
    # Unknown categories default to attack operators — a misconfigured benign category will silently receive attack mutations.
    filtered_ops = _filter_ops_for_category(base.category, operators)

    applied: list[str] = []
    for op_name in filtered_ops:
        fn = OP_MAP.get(op_name)
        if fn is None:
            continue
        text = fn(text, rng)
        applied.append(op_name)

    mutation_id = f"{base.id}_m{idx}"
    return MutationRecord(
        base_id=base.id,
        mutation_id=mutation_id,
        operators=applied,
        text=text,
        seed=seed,
    )
