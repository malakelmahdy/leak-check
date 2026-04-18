from __future__ import annotations

from datetime import datetime
from pathlib import Path


def log_line(log_path: Path, msg: str) -> None:
    """Append an ISO-timestamped log entry to the run log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().isoformat(timespec="seconds")
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}Z] {msg}\n")
