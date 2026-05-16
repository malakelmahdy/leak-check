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
from typing import Any

import yaml  # type: ignore[import]
from flask import Flask, jsonify, render_template, request, send_from_directory  # type: ignore[import]
from leakcheck.common.run_utils import resolve_child_path, resolve_project_path  # type: ignore[import]
from leakcheck.execution.campaign import CampaignProgress, run_campaign_config  # type: ignore[import]
from leakcheck.evaluation.benchmark import benchmark_payload, write_benchmark_markdown  # type: ignore[import]
from leakcheck.evaluation.metrics import evaluate_results_file  # type: ignore[import]
from leakcheck.proxy.active import ActiveInjectionRunner  # type: ignore[import]
from leakcheck.llm.client import LLMClient, response_shape, validate_llm_config  # type: ignore[import]
from leakcheck.proxy.http_capture import ProxyCaptureStore, sanitize_exchange_payload  # type: ignore[import]
from leakcheck.proxy.mitm_proxy import BrowserMitmCertificateManager, BrowserMitmProxyRuntime  # type: ignore[import]
from leakcheck.proxy.replay import compare_replay, replay_exchange, replay_payload  # type: ignore[import]
from leakcheck.proxy.reverse_proxy import ReverseProxyRuntime  # type: ignore[import]
from leakcheck.proxy.scoring import (  # type: ignore[import]
    ProxyScoringConfig,
    ProxyScoringService,
    detection_payload,
    redact_scored_payload_bodies,
)
from leakcheck.reporting.proxy_report import write_proxy_report_html, write_proxy_report_md  # type: ignore[import]

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
_proxy_store: ProxyCaptureStore | None = None
_proxy_runtime: ReverseProxyRuntime | BrowserMitmProxyRuntime | None = None
_active_runner: ActiveInjectionRunner | None = None

# Default LLM endpoint
LLM_ENDPOINT = os.environ.get("LLM_ENDPOINT", "http://127.0.0.1:1234/v1/chat/completions")
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "llama-3.2-3b-instruct")
LLM_TIMEOUT_S = int(os.environ.get("LLM_TIMEOUT_S", "180"))
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _runs_dir() -> Path:
    return PROJECT_ROOT / "data" / "runs"


def _proxy_sessions_dir() -> Path:
    return PROJECT_ROOT / "data" / "proxy_sessions"


def _campaign_config() -> dict[str, Any]:
    cfg_path = PROJECT_ROOT / "configs" / "campaign.yaml"
    if not cfg_path.exists():
        return {}
    with cfg_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    return loaded if isinstance(loaded, dict) else {}


def _proxy_config() -> dict[str, Any]:
    return dict(_campaign_config().get("proxy", {}) or {})


def _resolve_proxy_cert_dir(raw_path: str | None = None) -> Path:
    cert_path = raw_path or str(dict(_proxy_config().get("mitm", {}) or {}).get("cert_dir", "")) or "data/proxy_certs"
    resolved = Path(resolve_project_path(cert_path))
    data_root = (PROJECT_ROOT / "data").resolve()
    if data_root not in resolved.resolve().parents and resolved.resolve() != data_root:
        raise ValueError("MITM certificate directory must stay under the project data directory")
    return resolved


def _evaluation_dir() -> Path:
    return PROJECT_ROOT / "data" / "evaluation"


def _proxy_capture_store() -> ProxyCaptureStore:
    global _proxy_store
    if _proxy_store is None:
        _proxy_store = ProxyCaptureStore(_proxy_sessions_dir())
    return _proxy_store


def _stop_proxy_runtime() -> None:
    global _proxy_runtime
    if _proxy_runtime is not None:
        _proxy_runtime.stop()
        _proxy_runtime = None


def _active_audit_log_path(session_id: str) -> Path:
    return _proxy_sessions_dir() / session_id / "active_injection_audit.jsonl"


def _read_active_audit_log(session_id: str, limit: int = 100) -> list[dict[str, Any]]:
    path = _active_audit_log_path(session_id)
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows[-max(1, int(limit)) :]


def _is_localhost_host(host: str) -> bool:
    raw_host = str(host or "").strip().lower()
    if raw_host.startswith("[::1]"):
        hostname = "::1"
    else:
        hostname = raw_host.split(":", 1)[0]
    return hostname in {"localhost", "127.0.0.1", "::1"}


@app.context_processor
def inject_security_warning() -> dict[str, Any]:
    return {
        "show_v1_security_warning": not _is_localhost_host(request.host),
        "v1_security_warning": "V1 dashboard is not production-authenticated. Use only on localhost or trusted networks.",
    }


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


def _score_detection(det: "DetectionResult", repeatability: float | None = None) -> dict[str, Any]:  # noqa: F821
    return detection_payload(det, repeatability=repeatability)


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
                logger.warning("Failed to parse run summary for %s", d, exc_info=True)

        if config_file.exists():
            try:
                with config_file.open("r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                run_info["campaign_name"] = cfg.get("run", {}).get("name", "—")
                run_info["model"] = cfg.get("llm", {}).get("params", {}).get("model", "—")
            except Exception:
                logger.warning("Failed to parse run config for %s", d, exc_info=True)

        runs.append(run_info)

    return runs


def _call_llm(prompt: str, model: str | None = None) -> dict[str, Any]:
    """Call the LLM endpoint and return the response."""
    model = model or DEFAULT_MODEL
    llm_cfg = {
        "provider": "openai_compatible",
        "endpoint": LLM_ENDPOINT,
        "timeout_s": LLM_TIMEOUT_S,
        "retries": 0,
        "params": {"model": model, "temperature": 0.7, "max_tokens": 1024},
    }
    try:
        normalized = validate_llm_config(llm_cfg)
        client = LLMClient(
            endpoint=normalized["endpoint"],
            timeout_s=normalized["timeout_s"],
            retries=normalized["retries"],
            provider=normalized["provider"],
        )
        resp = client.generate(prompt, params=llm_cfg["params"])
        return {
            "text": resp.response_text,
            "raw": resp.raw,
            "latency_ms": resp.latency_ms,
            "model": resp.model,
            "response_shape": response_shape(resp.raw),
        }
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


def _proxy_session_payload(session_id: str) -> dict[str, Any]:
    store = _proxy_capture_store()
    session = store.get_session(session_id)
    exchanges = store.load_exchanges(session_id)
    replay_results_path = _proxy_sessions_dir() / session_id / "replay_results.json"
    replay_results: list[dict[str, Any]] = []
    if replay_results_path.exists():
        loaded = json.loads(replay_results_path.read_text(encoding="utf-8"))
        replay_results = loaded if isinstance(loaded, list) else []
    scoring = ProxyScoringService(
        ProxyScoringConfig(similarity_model=DEFAULT_SIMILARITY_MODEL),
        detector_factory=_chat_detector,
    ).score_exchanges(exchanges, conversation_id=session_id)
    return {
        "session": session,
        "exchanges": [exchange.model_dump(mode="json") for exchange in exchanges],
        "replay_results": replay_results,
        **scoring,
    }


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


@app.route("/proxy")
def page_proxy():
    proxy_cfg = _proxy_config()
    mitm_cfg = dict(proxy_cfg.get("mitm", {}) or {})
    return render_template(
        "proxy.html",
        proxy_defaults={
            "implementation": proxy_cfg.get("implementation", "reverse_proxy"),
            "retention_limit": proxy_cfg.get("retention_limit", 500),
            "mitm": {
                "listen_host": mitm_cfg.get("listen_host", "127.0.0.1"),
                "listen_port": mitm_cfg.get("listen_port", 8080),
                "cert_dir": mitm_cfg.get("cert_dir", "data/proxy_certs"),
            },
        },
    )


# ---------------------------------------------------------------------------
# API: Reports
# ---------------------------------------------------------------------------
@app.route("/api/reports")
def api_list_reports():
    return jsonify(_list_runs())


@app.route("/api/reports/<run_id>/html")
def api_report_html(run_id: str):
    try:
        run_dir = resolve_child_path(_runs_dir(), run_id)
    except ValueError:
        return jsonify({"error": "Invalid run id"}), 400
    if not run_dir.is_dir() or not (run_dir / "report.html").exists():
        return jsonify({"error": "Report not found"}), 404
    return send_from_directory(str(run_dir), "report.html")


@app.route("/api/reports/<run_id>/summary")
def api_report_summary(run_id: str):
    try:
        run_dir = resolve_child_path(_runs_dir(), run_id)
    except ValueError:
        return jsonify({"error": "Invalid run id"}), 400
    summary_file = run_dir / "summary.json"
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

            cfg_path = PROJECT_ROOT / "configs" / "campaign.yaml"
            with cfg_path.open("r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)

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

            def _progress(progress: CampaignProgress) -> None:
                if progress.total:
                    _jobs[job_id]["total"] = progress.total
                _jobs[job_id]["progress"] = progress.processed
                if progress.run_dir:
                    _jobs[job_id]["run_dir"] = progress.run_dir
                if progress.message:
                    _jobs[job_id]["message"] = progress.message

            run_dir = run_campaign_config(cfg, cfg_label=str(cfg_path), progress_callback=_progress)
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
# API: Proxy Capture
# ---------------------------------------------------------------------------
@app.route("/api/proxy/start", methods=["POST"])
def api_proxy_start():
    global _proxy_runtime
    data = request.get_json(silent=True) or {}
    target_url = str(data.get("target_url", "") or "")
    mode = str(data.get("mode", "passive") or "passive")
    if mode not in {"passive", "replay"}:
        return jsonify({"error": "Only passive and replay proxy modes are available"}), 400
    proxy_cfg = _proxy_config()
    mitm_cfg = dict(proxy_cfg.get("mitm", {}) or {})
    implementation = str(data.get("implementation", proxy_cfg.get("implementation", "reverse_proxy")) or "reverse_proxy")
    if implementation not in {"reverse_proxy", "mitm"}:
        return jsonify({"error": "Proxy implementation must be reverse_proxy or mitm"}), 400
    retention_limit = int(data.get("retention_limit", proxy_cfg.get("retention_limit", 500)) or 500)
    listen_host = str(data.get("listen_host", mitm_cfg.get("listen_host", "127.0.0.1")) or "127.0.0.1")
    default_port = 8080 if implementation == "mitm" else 8765
    configured_port = mitm_cfg.get("listen_port", default_port) if implementation == "mitm" else default_port
    listen_port = int(data.get("listen_port", configured_port) or configured_port)
    if listen_host not in {"127.0.0.1", "localhost"}:
        return jsonify({"error": "Proxy listener is restricted to localhost"}), 400
    try:
        cert_dir = _resolve_proxy_cert_dir(str(data.get("cert_dir", mitm_cfg.get("cert_dir", "")) or ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    _stop_proxy_runtime()
    store = _proxy_capture_store()
    session = store.start_session(
        target_url=target_url,
        mode=mode,
        retention_limit=retention_limit,
    )
    if mode == "passive" and implementation == "reverse_proxy":
        try:
            _proxy_runtime = ReverseProxyRuntime(
                store=store,
                session_id=str(session["session_id"]),
                target_url=target_url,
                listen_host="127.0.0.1",
                listen_port=listen_port,
            )
            _proxy_runtime.start()
            session = store.update_session(
                str(session["session_id"]),
                {
                    "listen_url": _proxy_runtime.listen_url,
                    "capture_mode": "reverse_proxy",
                    "listen_host": "127.0.0.1",
                    "listen_port": listen_port,
                },
            )
        except Exception as exc:
            store.stop_session(str(session["session_id"]))
            return jsonify({"error": str(exc)}), 400
    elif mode == "passive" and implementation == "mitm":
        try:
            _proxy_runtime = BrowserMitmProxyRuntime(
                store=store,
                session_id=str(session["session_id"]),
                listen_host=listen_host,
                listen_port=listen_port,
                cert_dir=str(cert_dir),
            )
            _proxy_runtime.start()
            session_updates = _proxy_runtime.session_updates()
            session = store.update_session(str(session["session_id"]), session_updates)
            _proxy_runtime.write_certificate_status(_proxy_sessions_dir() / str(session["session_id"]))
        except Exception as exc:
            store.stop_session(str(session["session_id"]))
            return jsonify({"error": str(exc)}), 400
    return jsonify(session)


@app.route("/api/proxy/certificate")
def api_proxy_certificate():
    try:
        cert_dir = _resolve_proxy_cert_dir(request.args.get("cert_dir"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(BrowserMitmCertificateManager(cert_dir).payload())


@app.route("/api/proxy/stop", methods=["POST"])
def api_proxy_stop():
    data = request.get_json(silent=True) or {}
    _stop_proxy_runtime()
    try:
        session = _proxy_capture_store().stop_session(data.get("session_id"))
    except FileNotFoundError:
        return jsonify({"error": "Proxy session not found"}), 404
    return jsonify(session)


@app.route("/api/proxy/status")
def api_proxy_status():
    return jsonify(_proxy_capture_store().status())


@app.route("/api/proxy/sessions")
def api_proxy_sessions():
    return jsonify(_proxy_capture_store().list_sessions())


@app.route("/api/proxy/sessions/<session_id>")
def api_proxy_session_detail(session_id: str):
    try:
        return jsonify(_proxy_session_payload(session_id))
    except FileNotFoundError:
        return jsonify({"error": "Proxy session not found"}), 404


@app.route("/api/proxy/sessions/<session_id>/export", methods=["POST"])
def api_proxy_session_export(session_id: str):
    data = request.get_json(silent=True) or {}
    include_bodies = bool(data.get("include_bodies", False))
    try:
        payload = _proxy_session_payload(session_id)
    except FileNotFoundError:
        return jsonify({"error": "Proxy session not found"}), 404
    if not include_bodies:
        exchanges = _proxy_capture_store().load_exchanges(session_id)
        payload["exchanges"] = [sanitize_exchange_payload(exchange, include_bodies=False) for exchange in exchanges]
        payload = redact_scored_payload_bodies(payload)
    export_path = _proxy_sessions_dir() / session_id / "export.json"
    with export_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    report_md = write_proxy_report_md(_proxy_sessions_dir() / session_id / "report.md", payload)
    report_html = write_proxy_report_html(_proxy_sessions_dir() / session_id / "report.html", payload)
    return jsonify({
        "status": "exported",
        "path": str(export_path),
        "report_md": str(report_md),
        "report_html": str(report_html),
        **payload,
    })


@app.route("/api/proxy/sessions/<session_id>/replay", methods=["POST"])
def api_proxy_session_replay(session_id: str):
    data = request.get_json(silent=True) or {}
    exchange_id = str(data.get("exchange_id", "") or "")
    try:
        exchanges = _proxy_capture_store().load_exchanges(session_id)
        _proxy_capture_store().get_session(session_id)
    except FileNotFoundError:
        return jsonify({"error": "Proxy session not found"}), 404
    if exchange_id:
        exchanges = [exchange for exchange in exchanges if exchange.exchange_id == exchange_id]
    if not exchanges:
        return jsonify({"error": "No replayable exchanges found"}), 404
    timeout_s = int(data.get("timeout_s", 30) or 30)
    results = []
    for exchange in exchanges:
        result = replay_exchange(exchange, timeout_s=timeout_s)
        results.append(
            {
                "replay": replay_payload(result),
                "comparison": compare_replay(exchange, result),
            }
        )
    replay_path = _proxy_sessions_dir() / session_id / "replay_results.json"
    with replay_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, ensure_ascii=False, indent=2)
    return jsonify({"status": "replayed", "path": str(replay_path), "results": results})


@app.route("/api/proxy/exchanges", methods=["POST"])
def api_proxy_record_exchange():
    data = request.get_json(force=True)
    try:
        exchange = _proxy_capture_store().record_exchange(
            session_id=data.get("session_id"),
            method=str(data.get("method", "POST")),
            url=str(data.get("url", "")),
            request_headers=dict(data.get("request_headers", {}) or {}),
            request_body=data.get("request_body"),
            response_status=data.get("response_status"),
            response_headers=dict(data.get("response_headers", {}) or {}),
            response_body=data.get("response_body"),
            transport=str(data.get("transport", "http")),
            metadata=dict(data.get("metadata", {}) or {}),
        )
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(exchange.model_dump(mode="json"))


@app.route("/api/proxy/active/preview", methods=["POST"])
def api_proxy_active_preview():
    data = request.get_json(force=True)
    session_id = str(data.get("session_id", "") or _proxy_capture_store().active_session_id or "")
    if not session_id:
        return jsonify({"error": "Active injection requires a proxy session"}), 400
    cfg = dict(data.get("config", {}) or {})
    runner = ActiveInjectionRunner(
        store=_proxy_capture_store(),
        session_id=session_id,
        cfg=cfg,
        audit_log_path=_active_audit_log_path(session_id),
        timeout_s=int(data.get("timeout_s", 30) or 30),
    )
    return jsonify(runner.preview(str(data.get("target_url", "")), [str(item) for item in data.get("prompts", [])]))


@app.route("/api/proxy/active/run", methods=["POST"])
def api_proxy_active_run():
    global _active_runner
    data = request.get_json(force=True)
    session_id = str(data.get("session_id", "") or _proxy_capture_store().active_session_id or "")
    if not session_id:
        return jsonify({"error": "Active injection requires a proxy session"}), 400
    try:
        _proxy_capture_store().get_session(session_id)
    except FileNotFoundError:
        return jsonify({"error": "Proxy session not found"}), 404
    _active_runner = ActiveInjectionRunner(
        store=_proxy_capture_store(),
        session_id=session_id,
        cfg=dict(data.get("config", {}) or {}),
        audit_log_path=_active_audit_log_path(session_id),
        timeout_s=int(data.get("timeout_s", 30) or 30),
    )
    results = _active_runner.run(
        str(data.get("target_url", "")),
        [str(item) for item in data.get("prompts", [])],
    )
    return jsonify({"session_id": session_id, "results": [result.__dict__ for result in results]})


@app.route("/api/proxy/active/stop", methods=["POST"])
def api_proxy_active_stop():
    if _active_runner is not None:
        _active_runner.stop()
        return jsonify({"status": "stop_requested", "runner": _active_runner.status()})
    return jsonify({"status": "idle"})


@app.route("/api/proxy/active/status")
def api_proxy_active_status():
    session_id = str(request.args.get("session_id", "") or _proxy_capture_store().active_session_id or "")
    audit_log = _read_active_audit_log(session_id) if session_id else []
    session_status: dict[str, Any] = {"running": False}
    if session_id:
        try:
            session = _proxy_capture_store().get_session(session_id)
            session_status = dict(session.get("active_injection_status", {}) or {"running": False})
        except FileNotFoundError:
            session_status = {"running": False}
    runner_status = (
        _active_runner.status()
        if _active_runner is not None and (not session_id or _active_runner.session_id == session_id)
        else session_status
    )
    return jsonify({"session_id": session_id, "runner": runner_status, "audit_log": audit_log})


@app.route("/api/proxy/sessions/<session_id>/active/audit")
def api_proxy_active_audit(session_id: str):
    try:
        _proxy_capture_store().get_session(session_id)
    except FileNotFoundError:
        return jsonify({"error": "Proxy session not found"}), 404
    limit = int(request.args.get("limit", "100") or 100)
    return jsonify({"session_id": session_id, "audit_log": _read_active_audit_log(session_id, limit=limit)})


# ---------------------------------------------------------------------------
# API: Evaluation
# ---------------------------------------------------------------------------
@app.route("/api/evaluation/results", methods=["POST"])
def api_evaluation_results():
    data = request.get_json(force=True)
    results_path_raw = str(data.get("results_path", "") or "")
    if not results_path_raw:
        return jsonify({"error": "results_path is required"}), 400
    results_path = Path(results_path_raw)
    if not results_path.is_absolute():
        results_path = PROJECT_ROOT / results_path
    if not results_path.exists():
        return jsonify({"error": "results file not found"}), 404
    out_path = _evaluation_dir() / f"{results_path.parent.name}_metrics.json"
    metrics = evaluate_results_file(results_path, out_path=out_path)
    return jsonify({"metrics": metrics, "path": str(out_path)})


@app.route("/api/evaluation/benchmark", methods=["POST", "GET"])
def api_evaluation_benchmark():
    out_path = _evaluation_dir() / "benchmark_comparison.md"
    write_benchmark_markdown(out_path)
    return jsonify({"path": str(out_path), **benchmark_payload()})


# ---------------------------------------------------------------------------
# API: Ping LLM
# ---------------------------------------------------------------------------
@app.route("/api/ping")
def api_ping():
    llm_cfg = {
        "provider": "openai_compatible",
        "endpoint": LLM_ENDPOINT,
        "timeout_s": 10,
        "retries": 0,
        "params": {"model": DEFAULT_MODEL, "temperature": 0.0, "max_tokens": 5},
    }
    try:
        normalized = validate_llm_config(llm_cfg)
        client = LLMClient(
            endpoint=normalized["endpoint"],
            timeout_s=normalized["timeout_s"],
            retries=normalized["retries"],
            provider=normalized["provider"],
        )
        resp = client.generate("hi", params=llm_cfg["params"])
        return jsonify({
            "status": "ok",
            "provider": normalized["provider"],
            "endpoint": normalized["safe_endpoint"],
            "model": resp.model,
            "latency_ms": resp.latency_ms,
            "response_shape": response_shape(resp.raw),
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def start_server(host: str = "0.0.0.0", port: int = 5000, debug: bool = True):
    if debug and not _is_localhost_host(host):
        print("  WARNING: V1 dashboard is not production-authenticated. Use only on localhost or trusted networks.")
    print(f"\n  LeakCheck Dashboard → http://localhost:{port}\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    start_server()
