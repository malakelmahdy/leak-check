"""
LeakCheck Web Dashboard — Flask application.

Serves 4 pages (Home, Campaigns, Reports, Chat) and JSON API endpoints
that wrap the existing leakcheck pipeline.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, TypeAlias

import yaml  # type: ignore[import]
import requests  # type: ignore[import]
from flask import Flask, jsonify, request, render_template, send_from_directory  # type: ignore[import]

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent.parent  # leak-check/
DEFAULT_SIMILARITY_MODEL = str(PROJECT_ROOT / "model" / "best_model")

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

# Store campaign jobs in-memory
_jobs: dict[str, dict[str, Any]] = {}

# Default LLM endpoint
LLM_ENDPOINT = os.environ.get("LLM_ENDPOINT", "http://127.0.0.1:1234/v1/chat/completions")
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "llama-3.2-3b-instruct")
LLM_TIMEOUT_S = int(os.environ.get("LLM_TIMEOUT_S", "180"))
logger = logging.getLogger(__name__)
VariantRun: TypeAlias = tuple["MutationRecord", "LLMResponseRecord", "DetectionResult"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _runs_dir() -> Path:
    return PROJECT_ROOT / "data" / "runs"


def _chat_detector():
    """Return a fresh Detector for each call.

    Model weights are cached globally by _load_embedding_model so there is no
    per-request model reload cost.  The Detector itself is intentionally NOT
    cached so that:
      - configuration changes (thresholds.yaml) take effect immediately,
      - the semantic index is rebuilt from the current static anchors,
      - no stale state leaks between requests.
    """
    from leakcheck.detect.detector import Detector  # type: ignore[import]

    return Detector(
        similarity_model=DEFAULT_SIMILARITY_MODEL,
        similarity_threshold=0.50,
        use_learned=False,
        learned_path=None,
    )


def _score_detection(det: "DetectionResult", repeatability: float | None = None) -> dict[str, Any]:
    from leakcheck.scoring.score import compute_severity, score_output_fields  # type: ignore[import]

    score = compute_severity(det, repeatability=repeatability)

    return {
        "category": det.category,
        "verdict": det.verdict,
        "confidence": det.confidence,
        "rule_hits": det.rule_hits,
        "similarity_score": det.similarity_score,
        "response_signals": det.response_signals,
        "evidence": det.evidence,
        **score_output_fields(score),
    }


def _empty_detection_payload(category: str, error: str) -> dict[str, Any]:
    return {
        "category": category,
        "verdict": "error",
        "error": error,
        "confidence": 0.0,
        "rule_hits": [],
        "similarity_score": 0.0,
        "response_signals": [],
        "severity": 0.0,
        "level": "low",
        "attack_risk_score": 0.0,
        "attack_risk_band": "none",
        "attack_risk_rationale": [],
        "signoff_severity": 0.0,
        "signoff_severity_label": "none",
        "leak_severity_score": 0.0,
        "leak_severity_band": "none",
        "leak_severity_rationale": [],
        "evidence": {"error": error},
    }


def _list_runs() -> list[dict[str, Any]]:
    """List all run folders with their summary data."""
    runs_path = _runs_dir()
    if not runs_path.exists():
        return []

    runs = []
    for d in sorted(runs_path.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        summary_file = d / "summary.json"
        config_file = d / "config_snapshot.yaml"
        report_html = d / "report.html"

        name: str = d.name
        run_info: dict[str, Any] = {
            "id": name,
            "path": str(d),
            "has_report": report_html.exists(),
            "created": name[:15] if len(name) >= 15 else name,  # type: ignore[index]
        }

        # Parse timestamp from folder name (YYYYMMDD_HHMMSS_...)
        try:
            ts = datetime.strptime(name[:15], "%Y%m%d_%H%M%S")  # type: ignore[index]
            run_info["created_at"] = ts.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            run_info["created_at"] = "—"

        if summary_file.exists():
            try:
                with summary_file.open("r", encoding="utf-8") as f:
                    summary = json.load(f)
                run_info["total"] = summary.get("total", 0)
                run_info["worst_signoff_score"] = summary.get("worst_signoff_score", 0.0)
                run_info["worst_signoff_label"] = summary.get("worst_signoff_label", "none")
                run_info["worst_attack_risk_score"] = summary.get("worst_attack_risk_score", 0.0)
                run_info["worst_attack_risk_band"] = summary.get("worst_attack_risk_band", "none")
                run_info["validated_critical_count"] = summary.get("validated_critical_count", 0)
                run_info["review_queue_count"] = summary.get("review_queue_count", 0)
                by_cat = summary.get("by_category", {})
                run_info["successes"] = sum(c.get("successes", 0) for c in by_cat.values())
                run_info["attempts"] = sum(c.get("attempts", 0) for c in by_cat.values())
                run_info["safes"] = sum(c.get("safes", 0) for c in by_cat.values())
                total = run_info["total"]
                run_info["success_rate"] = round(run_info["successes"] / total * 100, 1) if total else 0
            except Exception:
                logger.debug("Failed to parse run summary for %s", d, exc_info=True)

        if config_file.exists():
            try:
                with config_file.open("r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                run_info["campaign_name"] = cfg.get("run", {}).get("name", "—")
                run_info["model"] = cfg.get("llm", {}).get("params", {}).get("model", "—")
            except Exception:
                logger.debug("Failed to parse run config for %s", d, exc_info=True)

        runs.append(run_info)

    return runs


def _call_llm(prompt: str, model: str | None = None) -> dict[str, Any]:
    """Call the LLM endpoint and return the response."""
    model = model or DEFAULT_MODEL
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 1024,
    }
    try:
        resp = requests.post(LLM_ENDPOINT, json=payload, timeout=(10, LLM_TIMEOUT_S))
        resp.raise_for_status()
        data = resp.json()
        # OpenAI-compatible format
        choices = data.get("choices", [])
        if choices:
            text = choices[0].get("message", {}).get("content", "")
        else:
            text = data.get("text") or data.get("response") or str(data)
        return {"text": text, "raw": data}
    except Exception as e:
        logger.warning("LLM call failed for model %s", model, exc_info=True)
        return {"text": "", "error": str(e)}


def _detect_prompt(prompt: str, response: str, category: str = "unknown") -> dict[str, Any]:
    """Run detection pipeline on a single prompt/response pair."""
    try:
        det = _chat_detector().detect(
            prompt_id="chat_msg",
            category=category,
            prompt_text=prompt,
            response_text=response,
        )
        return _score_detection(det, repeatability=None)
    except Exception as e:
        logger.exception("Detection failed for category %s", category)
        return _empty_detection_payload(category, str(e))


def _precheck_prompt(prompt: str) -> dict[str, Any]:
    """Classify a prompt before it reaches the LLM."""
    try:
        det = _chat_detector().classify_prompt(
            prompt_id="chat_msg",
            prompt_text=prompt,
        )
        return _score_detection(det, repeatability=None)
    except Exception as e:
        logger.exception("Prompt precheck failed")
        return _empty_detection_payload("unknown", str(e))


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.route("/")
def page_home():
    return render_template("index.html")


@app.route("/campaigns")
def page_campaigns():
    return render_template("campaigns.html")


@app.route("/reports")
def page_reports():
    return render_template("reports.html")


@app.route("/chat")
def page_chat():
    return render_template("chat.html")


# ---------------------------------------------------------------------------
# API: Reports
# ---------------------------------------------------------------------------
@app.route("/api/reports")
def api_list_reports():
    return jsonify(_list_runs())


@app.route("/api/reports/<run_id>/html")
def api_report_html(run_id: str):
    run_dir = _runs_dir() / run_id
    if not (run_dir / "report.html").exists():
        return jsonify({"error": "Report not found"}), 404
    return send_from_directory(str(run_dir), "report.html")


@app.route("/api/reports/<run_id>/summary")
def api_report_summary(run_id: str):
    summary_file = _runs_dir() / run_id / "summary.json"
    if not summary_file.exists():
        return jsonify({"error": "Summary not found"}), 404
    with summary_file.open("r", encoding="utf-8") as f:
        return jsonify(json.load(f))


# ---------------------------------------------------------------------------
# API: Chat
# ---------------------------------------------------------------------------
@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(force=True)
    prompt = data.get("message", "").strip()
    model = data.get("model") or DEFAULT_MODEL

    if not prompt:
        return jsonify({"error": "Empty message"}), 400

    precheck = _precheck_prompt(prompt)

    # Resolve the best attack category from precheck evidence so detect() uses
    # the right rule set and anchor embeddings regardless of whether blocked.
    detect_category = str(
        (precheck.get("evidence") or {}).get("best_candidate_category")
        or precheck.get("category")
        or "unknown"
    )

    if precheck.get("verdict") == "error":
        return jsonify({
            "error": "Prompt safety precheck failed.",
            "detection": precheck,
            "model": model,
        }), 500

    if precheck.get("verdict") == "attack_attempt":
        # Run full detect() with empty response so the detection panel always
        # shows complete evidence (static + dynamic rule hits, scoring) rather
        # than precheck-only data.
        detection = _detect_prompt(prompt, "", category=detect_category)
        return jsonify({
            "reply": "Blocked: this prompt was classified as unsafe and was not sent to the LLM.",
            "detection": detection,
            "model": model,
            "blocked": True,
        }), 403

    # Call LLM
    llm_result = _call_llm(prompt, model)
    if llm_result.get("error"):
        detection = {
            **precheck,
            "error": str(llm_result["error"]),
            "evidence": {
                **dict(precheck.get("evidence") or {}),
                "llm_error": str(llm_result["error"]),
            },
        }
        return jsonify({
            "error": "LLM request failed.",
            "detection": detection,
            "model": model,
        }), 502
    response_text = llm_result.get("text", "")

    detection = _detect_prompt(prompt, response_text, category=detect_category)

    return jsonify({
        "reply": response_text,
        "detection": detection,
        "model": model,
    })


# ---------------------------------------------------------------------------
# API: Campaign
# ---------------------------------------------------------------------------
@app.route("/api/campaign/run", methods=["POST"])
def api_campaign_run():
    """Start a campaign in a background thread."""
    data = request.get_json(force=True)

    job_id = str(uuid.uuid4())[:8]  # type: ignore[index]
    _jobs[job_id] = {"status": "starting", "progress": 0, "run_dir": None, "error": None}

    def _run_campaign_thread():
        try:
            _jobs[job_id]["status"] = "running"

            # Load base config
            cfg_path = PROJECT_ROOT / "configs" / "campaign.yaml"
            with cfg_path.open("r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)

            # Override with user settings
            if data.get("model"):
                cfg.setdefault("llm", {}).setdefault("params", {})["model"] = data["model"]
            if data.get("prompt_count"):
                cfg.setdefault("attack", {})["limit"] = int(data["prompt_count"])
            if data.get("mutations_per_prompt"):
                cfg.setdefault("attack", {})["mutations_per_prompt"] = int(data["mutations_per_prompt"])
            if data.get("mutation_level"):
                cfg.setdefault("attack", {})["mutation_level"] = int(data["mutation_level"])
            if data.get("campaign_name"):
                cfg.setdefault("run", {})["name"] = data["campaign_name"]

            # Run the pipeline (reuse CLI logic inline)
            from leakcheck.common.run_utils import create_run_folder, save_config_snapshot, copy_dataset_snapshot, append_jsonl, save_json  # type: ignore[import]
            from leakcheck.common.run_utils import resolve_project_path  # type: ignore[import]
            from leakcheck.common.log_utils import log_line  # type: ignore[import]
            from leakcheck.datasets.ingest import ingest_local_jsonl, ingest_local_csv  # type: ignore[import]
            from leakcheck.attack.mutate import mutate_prompt  # type: ignore[import]
            from leakcheck.llm.client import LLMClient  # type: ignore[import]
            from leakcheck.detect.detector import Detector  # type: ignore[import]
            from leakcheck.scoring.score import compute_severity, load_scoring_policy, score_output_fields  # type: ignore[import]
            from leakcheck.reporting.summarize import summarize_results  # type: ignore[import]
            from leakcheck.reporting.report_md import write_report_md  # type: ignore[import]
            from leakcheck.reporting.report_html import write_report_html  # type: ignore[import]
            from leakcheck.common.schemas import DetectionResult, LLMResponseRecord, MutationRecord, PromptRecord  # type: ignore[import]

            # Create run folder
            output_root = resolve_project_path(cfg["run"]["output_root"])
            run_name = cfg["run"].get("name", "web_campaign")
            seed = int(cfg["run"].get("seed", 42))
            run_dir = create_run_folder(output_root, run_name)
            save_config_snapshot(cfg, run_dir)

            ds_path = resolve_project_path(cfg["dataset"]["path"])
            id_field = cfg["dataset"].get("id_field", "id")
            text_field = cfg["dataset"].get("text_field", "text")
            cat_field = cfg["dataset"].get("category_field", "category")
            copy_dataset_snapshot(ds_path, run_dir)

            # Ingest
            if ds_path.endswith(".csv"):
                prompts = ingest_local_csv(ds_path, id_field, text_field, cat_field)
            else:
                prompts = ingest_local_jsonl(ds_path, id_field, text_field, cat_field)

            # Apply limit
            limit = cfg.get("attack", {}).get("limit")
            if limit:
                prompts = prompts[:int(limit)]

            _jobs[job_id]["total"] = len(prompts)

            results_path = run_dir / "results.jsonl"
            log_path = run_dir / "logs.txt"

            client = LLMClient(
                endpoint=cfg["llm"]["endpoint"],
                timeout_s=int(cfg["llm"].get("timeout_s", 60)),
                retries=int(cfg["llm"].get("retries", 2)),
            )
            llm_params = dict(cfg["llm"].get("params", {}))
            det_cfg = cfg.get("detection", {})
            detector = Detector(
                similarity_model=resolve_project_path(det_cfg["similarity_model"]) if det_cfg.get("similarity_model") else DEFAULT_SIMILARITY_MODEL,
                similarity_threshold=float(det_cfg.get("similarity_threshold", 0.50)),
                use_learned=bool(det_cfg.get("use_learned_anchors", False)),
                learned_path=resolve_project_path(str(det_cfg["learned_anchors_path"])) if det_cfg.get("learned_anchors_path") else None,
            )
            scoring_policy = load_scoring_policy(resolve_project_path(cfg["scoring"]["thresholds_file"]))
            attack_enabled = bool(cfg.get("attack", {}).get("enabled", True))
        
            # Resolve operators from level if provided, otherwise use explicit list
            level = int(cfg.get("attack", {}).get("mutation_level", 0))
            ops = list(cfg.get("attack", {}).get("operators", []))
            
            # If level is set (e.g. from UI slider), it overrides the default config operators
            if level > 0:
                benign_base = ["benign_rephrase_prefix", "benign_wrapper"]
                if level == 1:
                    ops = ["format_shift"] + benign_base
                elif level == 2:
                    ops = ["format_shift", "obfuscate_spacing"] + benign_base
                elif level == 3:
                    ops = ["format_shift", "obfuscate_spacing", "prefix_injection"] + benign_base
                elif level == 4:
                    ops = ["format_shift", "obfuscate_spacing", "prefix_injection", "role_wrapper"] + benign_base
                elif level >= 5:
                    ops = ["format_shift", "obfuscate_spacing", "prefix_injection", "role_wrapper", "instruction_stack"] + benign_base
            
            # Ensure we have at least one operator if level was requested but no mapping found
            if level > 0 and not ops:
                 ops = ["format_shift"] + ["benign_rephrase_prefix"]

            mutations_per = int(cfg.get("attack", {}).get("mutations_per_prompt", 1))

            all_results = []

            for idx, p in enumerate(prompts):
                _jobs[job_id]["progress"] = idx + 1

                # Build mutation records (same logic as CLI)
                mutation_records = []
                if attack_enabled:
                    for mi in range(1, mutations_per + 1):
                        mutation_records.append(mutate_prompt(p, ops, seed=seed, idx=mi))
                else:
                    mutation_records.append(MutationRecord(
                        base_id=p.id, mutation_id=f"{p.id}_m0",
                        operators=[], text=p.text, seed=seed,
                    ))

                success_flags: list[int] = []
                variant_runs: list[VariantRun] = []
                for m in mutation_records:
                    prompt_id = m.mutation_id

                    # LLM call
                    llm_resp = client.generate(m.text, params=dict(llm_params))
                    llm_resp.prompt_id = prompt_id

                    # Detect
                    det = detector.detect(
                        prompt_id=prompt_id,
                        category=p.category,
                        prompt_text=m.text,
                        response_text=llm_resp.response_text,
                    )
                    success_flags.append(1 if det.verdict == "attack_success" else 0)
                    variant_runs.append((m, llm_resp, det))

                final_repeatability = sum(success_flags) / max(1, len(success_flags))

                for m, llm_resp, det in variant_runs:
                    score = compute_severity(det, repeatability=final_repeatability, policy=scoring_policy)
                    record = {
                        "base_id": p.id,
                        "prompt_id": m.mutation_id,
                        "category": p.category,
                        "operators": m.operators,
                        "prompt_text": m.text,
                        "response_text": llm_resp.response_text,
                        "latency_ms": llm_resp.latency_ms,
                        "verdict": det.verdict,
                        "is_attempt": det.verdict in ("attack_attempt", "attack_success"),
                        "is_success": det.verdict == "attack_success",
                        "over_refusal": bool(det.evidence.get("over_refusal", False)),
                        "confidence": det.confidence,
                        "rule_hits": det.rule_hits,
                        "similarity_score": det.similarity_score,
                        "response_signals": det.response_signals,
                        "evidence": det.evidence,
                        **score_output_fields(score),
                    }
                    append_jsonl(results_path, record)
                    all_results.append(record)

                log_line(log_path, f"Processed base prompt {p.id} with {len(mutation_records)} variants")

            # Summary + reports
            summary = summarize_results(all_results)
            run_meta = {
                "run_id": run_dir.name,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "campaign_name": cfg.get("run", {}).get("name", ""),
                "config": cfg,
                "config_snapshot_path": str(run_dir / "config_snapshot.yaml"),
                "results": str(results_path),
                "dataset_snapshot": str(run_dir / "dataset_snapshot"),
            }
            save_json(run_dir / "summary.json", summary)

            if cfg.get("reporting", {}).get("output_report_md", True):
                write_report_md(run_dir / "report.md", run_meta, summary)
            if cfg.get("reporting", {}).get("output_report_html", True):
                write_report_html(run_dir / "report.html", run_meta, summary)

            _jobs[job_id]["status"] = "done"
            _jobs[job_id]["run_dir"] = run_dir.name

        except Exception as e:
            logger.exception("Campaign job %s failed", job_id)
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)

    thread = threading.Thread(target=_run_campaign_thread, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "starting"})


@app.route("/api/campaign/status/<job_id>")
def api_campaign_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


# ---------------------------------------------------------------------------
# API: Ping LLM
# ---------------------------------------------------------------------------
@app.route("/api/ping")
def api_ping():
    try:
        resp = requests.post(
            LLM_ENDPOINT,
            json={"model": DEFAULT_MODEL, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5},
            timeout=10,
        )
        return jsonify({"status": "ok", "code": resp.status_code})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def start_server(host: str = "0.0.0.0", port: int = 5000, debug: bool = True):
    print(f"\n  LeakCheck Dashboard → http://localhost:{port}\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    start_server()
