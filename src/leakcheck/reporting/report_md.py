from __future__ import annotations

from pathlib import Path
from typing import Any
from datetime import datetime


def _now_iso() -> str:
    # Example: 2026-02-17 18:16:48
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _dig(d: dict[str, Any], path: list[str]) -> Any:
    """Safe nested get: _dig(run_meta, ["config", "run", "name"])"""
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def write_report_md(out_path: Path, run_meta: dict[str, Any], summary: dict[str, Any]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # --- robust run metadata ---
    run_id = run_meta.get("run_id") or run_meta.get("id") or ""

    created_at = run_meta.get("created_at") or run_meta.get("created") or _now_iso()

    # campaign name can be stored in multiple ways depending on your pipeline
    campaign_name = (
        run_meta.get("campaign_name")
        or run_meta.get("campaign")
        or _dig(run_meta, ["config", "run", "name"])
        or _dig(run_meta, ["campaign", "run", "name"])
        or ""
    )

    # Optional config fields (only if present)
    model = (
        run_meta.get("model")
        or _dig(run_meta, ["config", "llm", "params", "model"])
        or ""
    )
    sim_model = _dig(run_meta, ["config", "detection", "similarity_model"]) or ""
    sim_thr = _dig(run_meta, ["config", "detection", "similarity_threshold"])
    use_learned = _dig(run_meta, ["config", "detection", "use_learned_anchors"])
    learned_path = _dig(run_meta, ["config", "detection", "learned_anchors_path"])

    lines: list[str] = []
    lines.append("# Leak Check Report\n")

    lines.append("## Run\n")
    lines.append(f"- Run ID: `{run_id}`")
    lines.append(f"- Created at: `{created_at}`")
    lines.append(f"- Campaign: `{campaign_name}`")
    lines.append("")

    # Optional config block (won’t show empty noise)
    cfg_lines: list[str] = []
    if model:
        cfg_lines.append(f"- LLM model: `{model}`")
    if sim_model:
        cfg_lines.append(f"- Similarity model: `{sim_model}`")
    if sim_thr is not None:
        try:
            cfg_lines.append(f"- Similarity threshold: `{float(sim_thr):.2f}`")
        except Exception:
            cfg_lines.append(f"- Similarity threshold: `{sim_thr}`")
    if use_learned is not None:
        cfg_lines.append(f"- Learned anchors: `{bool(use_learned)}`")
    if learned_path and use_learned:
        cfg_lines.append(f"- Learned anchors path: `{learned_path}`")

    if cfg_lines:
        lines.append("## Config\n")
        lines.extend(cfg_lines)
        lines.append("")

    lines.append("## Summary\n")
    lines.append(f"- Total prompts: **{summary.get('total', 0)}**")
    lines.append("")

    lines.append("## By category\n")
    by_cat = summary.get("by_category", {}) or {}
    for cat, s in by_cat.items():
        count = s.get("count", 0)
        successes = s.get("successes", 0)
        attempts = s.get("attempts", 0)
        safes = s.get("safes", 0)
        success_rate = s.get("success_rate", 0.0)
        attempt_rate = s.get("attempt_rate", 0.0)
        avg_sev = s.get("avg_severity", 0.0)

        lines.append(f"### {cat}")
        lines.append(f"- Count: **{count}**")
        lines.append(f"- Successes: **{successes}** (success_rate={float(success_rate):.2f})")
        lines.append(f"- Attempts: **{attempts}** (attempt_rate={float(attempt_rate):.2f})")
        lines.append(f"- Safe: **{safes}**")
        lines.append(f"- Avg severity: **{float(avg_sev):.2f}**")
        lines.append("")

    lines.append("## Top 10 by severity\n")
    top_10 = summary.get("top_10", []) or []
    for i, r in enumerate(top_10, 1):
        pid = r.get("prompt_id", "")
        base = r.get("base_id", "")
        cat = r.get("category", "")
        verdict = r.get("verdict", "")
        sev = float(r.get("severity", 0.0))
        conf = float(r.get("confidence", 0.0))
        lines.append(f"{i}. `{pid}` (base={base}, cat={cat}, verdict={verdict}, severity={sev:.2f}, conf={conf:.2f})")

    out_path.write_text("\n".join(lines), encoding="utf-8")
