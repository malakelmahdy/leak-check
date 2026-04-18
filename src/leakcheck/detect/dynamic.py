from __future__ import annotations

# Maps each detection category to its (high, weak) signal names.
_SIGNALS: dict[str, tuple[str, str]] = {
    "prompt_injection": ("ML_INJECTION",  "ML_INJECTION_WEAK"),
    "jailbreak":        ("ML_JAILBREAK",  "ML_JAILBREAK_WEAK"),
    "data_exfil":       ("ML_LEAKAGE",    "ML_LEAKAGE_WEAK"),
}

# Cosine-similarity thresholds for signal emission.
# Calibrated against model/best_model anchor space:
#   benign text peaks at ~0.68; attacks start at ~0.74.
# HIGH: clear semantic match to known attack patterns.
# WEAK: moderate match — reinforces static rule hits but alone is not conclusive.
HIGH_THRESHOLD = 0.85
WEAK_THRESHOLD = 0.72


def dynamic_signals(category: str, similarity: float) -> list[str]:
    """Map a semantic/classifier score to named dynamic rule signals.

    Returns a list of signal IDs (0 or 1 entry) to be merged into attack_rules.
    Empty when similarity is below WEAK_THRESHOLD or category is unknown.
    """
    pair = _SIGNALS.get(category)
    if pair is None:
        return []
    high_sig, weak_sig = pair
    if similarity >= HIGH_THRESHOLD:
        return [high_sig]
    if similarity >= WEAK_THRESHOLD:
        return [weak_sig]
    return []
