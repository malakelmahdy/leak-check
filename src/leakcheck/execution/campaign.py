from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TypeAlias

import yaml  # type: ignore[import]

from leakcheck.attack.mutate import mutation_preset_from_level, mutate_prompt, operators_from_level  # type: ignore[import]
from leakcheck.attack.slm_strategy import SLMMutationStrategy  # type: ignore[import]
from leakcheck.attack.static_strategy import StaticMutationStrategy  # type: ignore[import]
from leakcheck.common.log_utils import log_line  # type: ignore[import]
from leakcheck.common.run_utils import (  # type: ignore[import]
    append_jsonl,
    build_run_metadata,
    copy_dataset_snapshot,
    create_run_folder,
    resolve_project_path,
    save_config_snapshot,
    save_json,
)
from leakcheck.common.schemas import DetectionResult, LLMResponseRecord, MutationRecord  # type: ignore[import]
from leakcheck.datasets.ingest import ingest_local_csv, ingest_local_jsonl  # type: ignore[import]
from leakcheck.detect.detector import Detector  # type: ignore[import]
from leakcheck.execution.conversation import run_conversation  # type: ignore[import]
from leakcheck.llm.client import LLMClient, validate_llm_config  # type: ignore[import]
from leakcheck.reporting.report_html import write_report_html  # type: ignore[import]
from leakcheck.reporting.report_md import write_report_md  # type: ignore[import]
from leakcheck.reporting.summarize import summarize_results  # type: ignore[import]
from leakcheck.scoring.score import compute_severity, load_scoring_policy, score_output_fields  # type: ignore[import]

DEFAULT_SIMILARITY_MODEL = "model/best_model"
VariantRun: TypeAlias = tuple[MutationRecord, LLMResponseRecord, DetectionResult]
ProgressCallback: TypeAlias = Callable[["CampaignProgress"], None]


@dataclass(frozen=True)
class CampaignProgress:
    stage: str
    processed: int = 0
    total: int = 0
    run_dir: str | None = None
    message: str = ""


def load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _emit(progress_callback: ProgressCallback | None, progress: CampaignProgress) -> None:
    if progress_callback is not None:
        progress_callback(progress)


def _ingest_prompts(cfg: dict[str, Any]) -> list[Any]:
    dataset_cfg = cfg["dataset"]
    dataset_path = resolve_project_path(dataset_cfg["path"])
    fmt = str(dataset_cfg.get("format") or Path(dataset_path).suffix.lstrip(".")).lower()
    id_field = dataset_cfg.get("id_field", "id")
    text_field = dataset_cfg.get("text_field", "text")
    cat_field = dataset_cfg.get("category_field", "category")

    if fmt == "jsonl":
        return ingest_local_jsonl(dataset_path, id_field, text_field, cat_field)
    if fmt == "csv":
        return ingest_local_csv(dataset_path, id_field, text_field, cat_field)
    raise ValueError(f"Unsupported dataset format: {fmt}")


def run_campaign(cfg_path: str | Path, progress_callback: ProgressCallback | None = None) -> Path:
    cfg = load_yaml(cfg_path)
    return run_campaign_config(cfg, cfg_label=str(cfg_path), progress_callback=progress_callback)


def run_campaign_config(
    cfg: dict[str, Any],
    cfg_label: str = "<memory>",
    progress_callback: ProgressCallback | None = None,
) -> Path:
    run_cfg = cfg["run"]
    run_name = run_cfg.get("name", "campaign")
    seed = int(run_cfg.get("seed", 42))
    output_root = resolve_project_path(run_cfg["output_root"])

    run_dir = create_run_folder(output_root, run_name)
    log_path = run_dir / "logs.txt"
    results_path = run_dir / "results.jsonl"
    log_line(log_path, f"Run started. cfg={cfg_label}")
    save_config_snapshot(cfg, run_dir)
    _emit(progress_callback, CampaignProgress(stage="starting", run_dir=run_dir.name, message="Run folder created"))

    dataset_path = resolve_project_path(cfg["dataset"]["path"])
    copy_dataset_snapshot(dataset_path, run_dir)
    prompts = _ingest_prompts(cfg)
    limit = cfg.get("attack", {}).get("limit")
    if limit:
        prompts = prompts[: int(limit)]
    log_line(log_path, f"Ingested prompts: {len(prompts)}")
    _emit(progress_callback, CampaignProgress(stage="ingested", total=len(prompts), run_dir=run_dir.name))

    attack_cfg = cfg.get("attack", {})
    attack_enabled = bool(attack_cfg.get("enabled", True))
    mutations_per = int(attack_cfg.get("mutations_per_prompt", 1))
    mutation_level = int(attack_cfg.get("mutation_level", 0) or 0)
    mutation_preset = mutation_preset_from_level(mutation_level)
    operators = operators_from_level(mutation_level, list(attack_cfg.get("operators", [])))

    llm_cfg = cfg["llm"]
    normalized_llm = validate_llm_config(llm_cfg)
    client = LLMClient(
        endpoint=normalized_llm["endpoint"],
        timeout_s=normalized_llm["timeout_s"],
        retries=normalized_llm["retries"],
        provider=normalized_llm["provider"],
    )
    llm_params = dict(llm_cfg.get("params", {}))

    det_cfg = cfg["detection"]
    detector = Detector(
        similarity_model=resolve_project_path(det_cfg.get("similarity_model", DEFAULT_SIMILARITY_MODEL)),
        similarity_threshold=float(det_cfg.get("similarity_threshold", 0.50)),
        use_learned=bool(det_cfg.get("use_learned_anchors", False)),
        learned_path=resolve_project_path(str(det_cfg["learned_anchors_path"])) if det_cfg.get("learned_anchors_path") else None,
    )
    scoring_policy_path = resolve_project_path(cfg["scoring"]["thresholds_file"])
    scoring_policy = load_scoring_policy(scoring_policy_path)

    all_results: list[dict[str, Any]] = []
    conversation_cfg = dict(cfg.get("conversation", {}) or {})
    conversation_enabled = bool(conversation_cfg.get("enabled", False))
    mutation_strategy_name = str(cfg.get("mutation", {}).get("strategy", "static")).strip().lower()
    if conversation_enabled:
        strategy = SLMMutationStrategy() if mutation_strategy_name == "slm" else StaticMutationStrategy()
        for idx, prompt in enumerate(prompts, 1):
            conversation_run = run_conversation(
                prompt=prompt,
                cfg=cfg,
                seed=seed,
                strategy=strategy,
                client=client,
                llm_params=llm_params,
                detector=detector,
                scoring_policy=scoring_policy,
            )
            for record in conversation_run.records:
                append_jsonl(results_path, record)
                all_results.append(record)
            log_line(log_path, f"Processed base prompt {prompt.id} with {len(conversation_run.turns)} conversation turns")
            _emit(progress_callback, CampaignProgress(stage="running", processed=idx, total=len(prompts), run_dir=run_dir.name))

        summary = summarize_results(all_results)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scoring_version = getattr(scoring_policy, "score_version", "")
        metadata = build_run_metadata(
            run_id=run_dir.name,
            created_at=created_at,
            cfg_label=cfg_label,
            cfg=cfg,
            run_dir=run_dir,
            results_path=results_path,
            scoring_policy_path=str(scoring_policy_path),
            scoring_version=scoring_version,
            mutation_level=mutation_level,
            mutation_preset=mutation_preset,
            mutation_operators=operators,
        )
        save_json(run_dir / "metadata.json", metadata)

        run_meta = {
            "run_id": run_dir.name,
            "created_at": created_at,
            "campaign_name": cfg.get("run", {}).get("name", ""),
            "config": cfg,
            "config_snapshot_path": str(run_dir / "config_snapshot.yaml"),
            "metadata_path": str(run_dir / "metadata.json"),
            "results": str(results_path),
            "dataset_snapshot": str(run_dir / "dataset_snapshot"),
            "mutation_level": mutation_level,
            "mutation_preset": mutation_preset,
            "mutation_operators": operators,
            "mutation_strategy": mutation_strategy_name,
            "scoring_policy": str(scoring_policy_path),
            "scoring_policy_path": str(scoring_policy_path),
            "scoring_version": scoring_version,
        }

        if cfg.get("reporting", {}).get("output_summary_json", True):
            save_json(run_dir / "summary.json", summary)
        if cfg.get("reporting", {}).get("output_report_md", True):
            write_report_md(run_dir / "report.md", run_meta, summary)
        if cfg.get("reporting", {}).get("output_report_html", True):
            write_report_html(run_dir / "report.html", run_meta, summary)

        _emit(progress_callback, CampaignProgress(stage="done", processed=len(prompts), total=len(prompts), run_dir=run_dir.name))
        return run_dir

    for idx, prompt in enumerate(prompts, 1):
        mutation_records: list[MutationRecord] = []
        if attack_enabled:
            for mutation_idx in range(1, mutations_per + 1):
                mutation_records.append(mutate_prompt(prompt, operators, seed=seed, idx=mutation_idx))
        else:
            mutation_records.append(
                MutationRecord(
                    base_id=prompt.id,
                    mutation_id=f"{prompt.id}_m0",
                    operators=[],
                    text=prompt.text,
                    seed=seed,
                )
            )

        success_flags: list[int] = []
        variant_runs: list[VariantRun] = []
        for mutation in mutation_records:
            response = client.generate(mutation.text, params=llm_params)
            response.prompt_id = mutation.mutation_id
            detection = detector.detect(
                prompt_id=mutation.mutation_id,
                category=prompt.category,
                prompt_text=mutation.text,
                response_text=response.response_text,
            )
            success_flags.append(1 if detection.verdict == "attack_success" else 0)
            variant_runs.append((mutation, response, detection))

        repeatability = sum(success_flags) / max(1, len(success_flags))
        for mutation, response, detection in variant_runs:
            score = compute_severity(detection, repeatability=repeatability, policy=scoring_policy)
            record = {
                "base_id": prompt.id,
                "prompt_id": mutation.mutation_id,
                "category": prompt.category,
                "mutation_level": mutation_level,
                "mutation_preset": mutation_preset,
                "operators": mutation.operators,
                "prompt_text": mutation.text,
                "response_text": response.response_text,
                "latency_ms": response.latency_ms,
                "verdict": detection.verdict,
                "is_attempt": detection.verdict in ("attack_attempt", "attack_success"),
                "is_success": detection.verdict == "attack_success",
                "over_refusal": bool(detection.evidence.get("over_refusal", False)),
                "confidence": detection.confidence,
                "rule_hits": detection.rule_hits,
                "similarity_score": detection.similarity_score,
                "response_signals": detection.response_signals,
                "evidence": detection.evidence,
                **score_output_fields(score),
            }
            append_jsonl(results_path, record)
            all_results.append(record)

        log_line(log_path, f"Processed base prompt {prompt.id} with {len(mutation_records)} variants")
        _emit(progress_callback, CampaignProgress(stage="running", processed=idx, total=len(prompts), run_dir=run_dir.name))

    summary = summarize_results(all_results)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scoring_version = getattr(scoring_policy, "score_version", "")
    metadata = build_run_metadata(
        run_id=run_dir.name,
        created_at=created_at,
        cfg_label=cfg_label,
        cfg=cfg,
        run_dir=run_dir,
        results_path=results_path,
        scoring_policy_path=str(scoring_policy_path),
        scoring_version=scoring_version,
        mutation_level=mutation_level,
        mutation_preset=mutation_preset,
        mutation_operators=operators,
    )
    save_json(run_dir / "metadata.json", metadata)

    run_meta = {
        "run_id": run_dir.name,
        "created_at": created_at,
        "campaign_name": cfg.get("run", {}).get("name", ""),
        "config": cfg,
        "config_snapshot_path": str(run_dir / "config_snapshot.yaml"),
        "metadata_path": str(run_dir / "metadata.json"),
        "results": str(results_path),
        "dataset_snapshot": str(run_dir / "dataset_snapshot"),
        "mutation_level": mutation_level,
        "mutation_preset": mutation_preset,
        "mutation_operators": operators,
        "scoring_policy": str(scoring_policy_path),
        "scoring_policy_path": str(scoring_policy_path),
        "scoring_version": scoring_version,
    }

    if cfg.get("reporting", {}).get("output_summary_json", True):
        save_json(run_dir / "summary.json", summary)
    if cfg.get("reporting", {}).get("output_report_md", True):
        write_report_md(run_dir / "report.md", run_meta, summary)
    if cfg.get("reporting", {}).get("output_report_html", True):
        write_report_html(run_dir / "report.html", run_meta, summary)

    _emit(progress_callback, CampaignProgress(stage="done", processed=len(prompts), total=len(prompts), run_dir=run_dir.name))
    return run_dir
