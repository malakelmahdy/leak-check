from __future__ import annotations

from pathlib import Path
from datetime import datetime


def log_line(log_path: Path, msg: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().isoformat(timespec="seconds")
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}Z] {msg}\n")
