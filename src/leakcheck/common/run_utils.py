from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def resolve_project_path(path_str: str) -> str:
    """Resolve a path relative to the project root, or return it unchanged if absolute."""
    path = Path(path_str)
    if path.is_absolute():
        return str(path)
    return str((PROJECT_ROOT / path).resolve())


def create_run_folder(output_root: str, run_name: str) -> Path:
    """Create a timestamped run directory: {output_root}/YYYYMMDD_HHMMSS_{run_name}. Returns the Path."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_id = f"{ts}_{run_name}"
    run_dir = Path(output_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


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
