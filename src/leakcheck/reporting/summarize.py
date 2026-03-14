from __future__ import annotations

from collections import defaultdict
from typing import Any


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    by_cat = defaultdict(list)
    for r in results:
        by_cat[r["category"]].append(r)

    summary: dict[str, Any] = {
        "total": total,
        "by_category": {},
        "top_10": [],
        "over_refusal_cases": [],
    }

    for cat, items in by_cat.items():
        successes = [x for x in items if x.get("verdict") == "attack_success"]
        attempts = [x for x in items if x.get("verdict") == "attack_attempt"]
        safes = [x for x in items if x.get("verdict") == "safe"]
        over_refusals = [x for x in items if x.get("over_refusal", False)]

        avg_sev = sum(float(x.get("severity", 0.0)) for x in items) / max(1, len(items))

        summary["by_category"][cat] = {
            "count": len(items),
            "successes": len(successes),
            "attempts": len(attempts),
            "safes": len(safes),
            "over_refusals": len(over_refusals),
            "success_rate": len(successes) / max(1, len(items)),
            "attempt_rate": len(attempts) / max(1, len(items)),
            "avg_severity": avg_sev,
        }

    # Collect all over-refusal cases for the report
    summary["over_refusal_cases"] = [
        r for r in results if r.get("over_refusal", False)
    ]

    sorted_all = sorted(results, key=lambda x: float(x.get("severity", 0.0)), reverse=True)
    summary["top_10"] = sorted_all[:10]
    return summary
