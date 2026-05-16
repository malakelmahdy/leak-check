from __future__ import annotations

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_SECRET_KEY_RE = re.compile(r"(api[_-]?key|\btoken\b|secret|password|credential|authorization)", re.I)


def resolve_project_path(path_str: str) -> str:
    """Resolve a path relative to the project root, or return it unchanged if absolute."""
    path = Path(path_str)
    if path.is_absolute():
        return str(path)
    return str((PROJECT_ROOT / path).resolve())


def create_run_folder(output_root: str, run_name: str) -> Path:
    """Create a timestamped run directory: {output_root}/YYYYMMDD_HHMMSS_{run_name}. Returns the Path."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = _SAFE_NAME_RE.sub("_", str(run_name)).strip("._-") or "campaign"
    run_id = f"{ts}_{safe_name}"
    run_dir = Path(output_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def resolve_child_path(root: str | Path, child: str | Path) -> Path:
    """Resolve a child path and require it to stay under root."""
    root_path = Path(root).resolve()
    child_path = (root_path / child).resolve()
    if child_path != root_path and root_path not in child_path.parents:
        raise ValueError(f"Path escapes root: {child}")
    return child_path


def sanitize_endpoint_url(endpoint: str | None) -> str:
    """Return an endpoint URL safe for audit metadata by removing userinfo, query, and fragment."""
    if not endpoint:
        return ""
    parsed = urlsplit(str(endpoint))
    hostname = parsed.hostname or ""
    netloc = hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def contains_secret_key(payload: Any) -> bool:
    """Return True if a nested dict/list contains a secret-like key name."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            if _SECRET_KEY_RE.search(str(key)):
                return True
            if contains_secret_key(value):
                return True
    elif isinstance(payload, list):
        return any(contains_secret_key(item) for item in payload)
    return False


def build_run_metadata(
    *,
    run_id: str,
    created_at: str,
    cfg_label: str,
    cfg: dict[str, Any],
    run_dir: Path,
    results_path: Path,
    scoring_policy_path: str,
    scoring_version: str,
    mutation_level: int,
    mutation_preset: str,
    mutation_operators: list[str],
) -> dict[str, Any]:
    """Build metadata.json content with trace fields only. Full config snapshots stay separate."""
    llm_cfg = dict(cfg.get("llm", {}) or {})
    llm_params = dict(llm_cfg.get("params", {}) or {})
    detection_cfg = dict(cfg.get("detection", {}) or {})
    dataset_cfg = dict(cfg.get("dataset", {}) or {})

    metadata = {
        "run_id": run_id,
        "created_at": created_at,
        "campaign_name": cfg.get("run", {}).get("name", ""),
        "config_label": cfg_label,
        "config_snapshot_path": str(run_dir / "config_snapshot.yaml"),
        "results_path": str(results_path),
        "dataset_snapshot_path": str(run_dir / "dataset_snapshot"),
        "dataset": {
            "path": dataset_cfg.get("path", ""),
            "format": dataset_cfg.get("format", ""),
            "text_field": dataset_cfg.get("text_field", "text"),
            "id_field": dataset_cfg.get("id_field", "id"),
            "category_field": dataset_cfg.get("category_field", "category"),
        },
        "llm": {
            "provider": llm_cfg.get("provider", ""),
            "model": llm_params.get("model", ""),
            "endpoint_url": sanitize_endpoint_url(llm_cfg.get("endpoint", "")),
            "timeout_s": llm_cfg.get("timeout_s"),
            "retries": llm_cfg.get("retries"),
            "temperature": llm_params.get("temperature"),
            "max_tokens": llm_params.get("max_tokens"),
        },
        "mutation": {
            "level": mutation_level,
            "preset": mutation_preset,
            "operators": mutation_operators,
        },
        "detection": {
            "similarity_model": detection_cfg.get("similarity_model", ""),
            "similarity_threshold": detection_cfg.get("similarity_threshold"),
            "use_learned_anchors": detection_cfg.get("use_learned_anchors", False),
            "learned_anchors_path": detection_cfg.get("learned_anchors_path", ""),
        },
        "scoring": {
            "policy_path": scoring_policy_path,
            "version": scoring_version,
        },
    }
    if contains_secret_key(metadata):
        raise ValueError("metadata contains a secret-like key")
    return metadata


def save_config_snapshot(cfg: dict[str, Any], run_dir: Path) -> Path:
    """Write the campaign config dict as YAML to config_snapshot.yaml in the run directory."""
    out = run_dir / "config_snapshot.yaml"
    with out.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    return out


def copy_dataset_snapshot(dataset_path: str, run_dir: Path) -> Path:
    """Copy the input dataset into dataset_snapshot/ under the run directory for audit traceability."""
    src = Path(dataset_path)
    dst = run_dir / "dataset_snapshot" / src.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append a single JSON object to a JSONL file. Creates parent dirs if needed. Not atomic but safe for sequential streaming."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False))
        f.write("\n")


def save_json(path: Path, obj: Any) -> None:
    """Write an object as pretty-printed JSON. Creates parent dirs if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
