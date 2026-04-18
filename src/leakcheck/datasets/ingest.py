from __future__ import annotations

import csv
import json
from pathlib import Path

from leakcheck.common.schemas import PromptRecord


def ingest_local_jsonl(path: str, id_field: str, text_field: str, category_field: str) -> list[PromptRecord]:
    """Load prompts from a JSONL file. Field names are configurable per campaign config. Skips records with empty id or text."""
    p = Path(path)
    records: list[PromptRecord] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            rid = str(obj.get(id_field, "")).strip()
            txt = str(obj.get(text_field, "")).strip()
            cat = str(obj.get(category_field, "unknown")).strip()
            if not rid or not txt:
                continue
            records.append(PromptRecord(id=rid, category=cat, text=txt, source=str(p)))
    return records


def ingest_local_csv(path: str, id_field: str, text_field: str, category_field: str) -> list[PromptRecord]:
    """Load prompts from a CSV file using DictReader. Field names are configurable. Skips records with empty id or text."""
    p = Path(path)
    records: list[PromptRecord] = []
    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = str(row.get(id_field, "")).strip()
            txt = str(row.get(text_field, "")).strip()
            cat = str(row.get(category_field, "unknown")).strip()
            if not rid or not txt:
                continue
            records.append(PromptRecord(id=rid, category=cat, text=txt, source=str(p)))
    return records
