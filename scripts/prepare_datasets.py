"""
prepare_datasets.py - Convert external datasets into leakcheck JSONL format.

Usage:
    .venv/Scripts/python scripts/prepare_datasets.py

Reads from:  Downloads/DATASETS to use/
Writes to:   data/raw/prompts_demo.jsonl   (~700 rows, stratified sample)
             data/raw/prompts_full.jsonl   (all rows merged)
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import pyarrow.parquet as pq

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATASETS_ROOT = Path(r"C:\Users\mahmoud\Downloads\DATASETS to use")
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DEMO_OUT = OUTPUT_DIR / "prompts_demo.jsonl"
FULL_OUT = OUTPUT_DIR / "prompts_full.jsonl"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_text(text: str) -> str:
    """Strip Unicode line/paragraph separators that confuse editors."""
    return text.replace("\u2028", " ").replace("\u2029", " ")


def write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            r["text"] = _clean_text(r["text"])
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  Wrote {len(records):,} rows → {path}")


def stratified_sample(records: list[dict], n: int, rng: random.Random) -> list[dict]:
    """Sample n records, balanced across categories."""
    by_cat: dict[str, list[dict]] = {}
    for r in records:
        by_cat.setdefault(r["category"], []).append(r)

    per_cat = max(1, n // len(by_cat)) if by_cat else n
    sampled: list[dict] = []
    for cat, items in by_cat.items():
        k = min(per_cat, len(items))
        sampled.extend(rng.sample(items, k))

    rng.shuffle(sampled)
    return sampled[:n]


# ---------------------------------------------------------------------------
# Dataset 1: Parquet — prompt-injection-safety (test split only)
# ---------------------------------------------------------------------------
PARQUET_LABEL_MAP = {0: "benign", 1: "prompt_injection", 2: "jailbreak"}

def load_parquet_safety() -> list[dict]:
    path = DATASETS_ROOT / "prompt-injection-safety" / "test-00000-of-00001.parquet"
    if not path.exists():
        print(f"  [SKIP] {path} not found")
        return []

    table = pq.read_table(path)
    records = []
    for i in range(len(table)):
        text = str(table.column("text")[i].as_py()).strip()
        label = int(table.column("label")[i].as_py())
        cat = PARQUET_LABEL_MAP.get(label, "benign")
        if not text:
            continue
        records.append({"id": f"pis_{i}", "category": cat, "text": text})

    print(f"  Loaded {len(records):,} rows from parquet (test split)")
    return records


# ---------------------------------------------------------------------------
# Dataset 2: CSV — prompt-injections-benchmark
# ---------------------------------------------------------------------------
BENCHMARK_LABEL_MAP = {"jailbreak": "jailbreak", "benign": "benign"}

def load_benchmark_csv() -> list[dict]:
    path = DATASETS_ROOT / "prompt-injections-benchmark" / "test.csv"
    if not path.exists():
        print(f"  [SKIP] {path} not found")
        return []

    records = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            text = (row.get("text") or "").strip()
            label = (row.get("label") or "").strip().lower()
            cat = BENCHMARK_LABEL_MAP.get(label, "benign")
            if not text:
                continue
            records.append({"id": f"pib_{i}", "category": cat, "text": text})

    print(f"  Loaded {len(records):,} rows from benchmark CSV")
    return records


# ---------------------------------------------------------------------------
# Dataset 3: CSV — prompt-injection-attack-dataset
# ---------------------------------------------------------------------------
def load_attack_csv() -> list[dict]:
    path = DATASETS_ROOT / "prompt-injection-attack-dataset" / "complete_dataset.csv"
    if not path.exists():
        print(f"  [SKIP] {path} not found")
        return []

    records = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            # Use combine_attack column — the fully-composed attack prompt
            text = (row.get("combine_attack") or "").strip()
            if not text or len(text) < 20:
                continue
            records.append({"id": f"pia_{i}", "category": "prompt_injection", "text": text})

    print(f"  Loaded {len(records):,} rows from attack CSV")
    return records


# ---------------------------------------------------------------------------
# Dataset 4: CSV — jailbreak-classification (train + test)
# ---------------------------------------------------------------------------
JBC_LABEL_MAP = {"jailbreak": "jailbreak", "benign": "benign"}

def load_jailbreak_csv() -> list[dict]:
    base = DATASETS_ROOT / "jailbreak-classification"
    records = []
    for fname in ["jailbreak_dataset_train.csv", "jailbreak_dataset_test.csv"]:
        path = base / fname
        if not path.exists():
            print(f"  [SKIP] {path} not found")
            continue
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                text = (row.get("prompt") or "").strip()
                label = (row.get("type") or "").strip().lower()
                cat = JBC_LABEL_MAP.get(label, "benign")
                if not text:
                    continue
                records.append({"id": f"jbc_{fname[0]}_{i}", "category": cat, "text": text})

    print(f"  Loaded {len(records):,} rows from jailbreak CSV")
    return records


# ---------------------------------------------------------------------------
# Original demo prompts (keep them)
# ---------------------------------------------------------------------------
def load_original_prompts() -> list[dict]:
    path = OUTPUT_DIR / "prompts.jsonl"
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    print(f"  Loaded {len(records):,} original prompts")
    return records


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    rng = random.Random(42)
    print("=== Dataset Preparation ===\n")

    # Load all sources
    parquet_records = load_parquet_safety()
    benchmark_records = load_benchmark_csv()
    attack_records = load_attack_csv()
    jailbreak_records = load_jailbreak_csv()
    original_records = load_original_prompts()

    # Full merged dataset
    full = parquet_records + benchmark_records + attack_records + jailbreak_records
    write_jsonl(FULL_OUT, full)

    # Demo dataset: stratified sample + originals
    demo_parts = []
    demo_parts.extend(stratified_sample(parquet_records, 200, rng))
    demo_parts.extend(stratified_sample(benchmark_records, 200, rng))
    demo_parts.extend(rng.sample(attack_records, min(100, len(attack_records))))
    demo_parts.extend(stratified_sample(jailbreak_records, 200, rng))
    demo_parts.extend(original_records)

    # De-duplicate by id (originals take priority)
    seen = set()
    deduped = []
    for r in demo_parts:
        if r["id"] not in seen:
            seen.add(r["id"])
            deduped.append(r)

    rng.shuffle(deduped)
    write_jsonl(DEMO_OUT, deduped)

    # Summary
    print("\n=== Summary ===")
    for label, records in [("Full", full), ("Demo", deduped)]:
        cats = {}
        for r in records:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        print(f"  {label}: {len(records):,} total — {dict(sorted(cats.items()))}")

    print(f"\nDone! Update campaign.yaml dataset.path to: data/raw/prompts_demo.jsonl")


if __name__ == "__main__":
    main()
