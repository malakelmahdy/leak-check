from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "prepare_datasets.py"
TEST_OUTPUT_ROOT = Path(__file__).resolve().parents[1] / "data" / "test_prepare_datasets"


def _load_prepare_datasets_module():
    spec = importlib.util.spec_from_file_location("prepare_datasets_test_module", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prepare_datasets_honors_env_override(monkeypatch):
    datasets_root = TEST_OUTPUT_ROOT / "datasets_env"
    datasets_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LEAKCHECK_DATASETS_ROOT", str(datasets_root))

    module = _load_prepare_datasets_module()

    assert module.DATASETS_ROOT == datasets_root


def test_write_jsonl_does_not_mutate_input_records(monkeypatch):
    datasets_root = TEST_OUTPUT_ROOT / "datasets_write"
    datasets_root.mkdir(parents=True, exist_ok=True)
    out_path = TEST_OUTPUT_ROOT / f"records-{uuid.uuid4().hex}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("LEAKCHECK_DATASETS_ROOT", str(datasets_root))
    module = _load_prepare_datasets_module()
    records = [{"id": "p1", "category": "benign", "text": "hello\u2028world"}]

    module.write_jsonl(out_path, records)

    assert records[0]["text"] == "hello\u2028world"
    assert "\\u2028" not in out_path.read_text(encoding="utf-8")
