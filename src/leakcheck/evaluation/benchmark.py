from __future__ import annotations

from pathlib import Path
from typing import Any


BENCHMARK_ROWS = [
    {
        "capability": "Endpoint campaigns",
        "leakcheck": "Supported",
        "garak": "Supported",
        "pyrit": "Supported",
    },
    {
        "capability": "Multi-turn adaptive mutation",
        "leakcheck": "Supported through conversation runner and SLM strategy",
        "garak": "Limited by probe/generator configuration",
        "pyrit": "Supported through orchestrators",
    },
    {
        "capability": "Passive browser-aware capture",
        "leakcheck": "Reverse proxy capture implemented",
        "garak": "Not primary focus",
        "pyrit": "Not primary focus",
    },
    {
        "capability": "Replay saved traffic",
        "leakcheck": "Implemented for captured HTTP exchanges",
        "garak": "Not primary focus",
        "pyrit": "Requires custom workflow",
    },
    {
        "capability": "Privacy leak scoring",
        "leakcheck": "Built-in attack risk and signoff severity",
        "garak": "Detector/probe-oriented",
        "pyrit": "Score-oriented but workflow dependent",
    },
    {
        "capability": "Report evidence chains",
        "leakcheck": "Prompt/response chains in Markdown and HTML reports",
        "garak": "Run output and reports",
        "pyrit": "Memory and score artifacts",
    },
]


def benchmark_markdown(extra_notes: list[str] | None = None) -> str:
    lines = [
        "# LeakCheck Benchmark Comparison",
        "",
        "| Capability | LeakCheck | Garak | PyRIT |",
        "|---|---|---|---|",
    ]
    for row in BENCHMARK_ROWS:
        lines.append(
            f"| {row['capability']} | {row['leakcheck']} | {row['garak']} | {row['pyrit']} |"
        )
    notes = extra_notes or []
    if notes:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {note}" for note in notes)
    return "\n".join(lines) + "\n"


def write_benchmark_markdown(out_path: str | Path, extra_notes: list[str] | None = None) -> Path:
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(benchmark_markdown(extra_notes), encoding="utf-8")
    return target


def benchmark_payload() -> dict[str, Any]:
    return {"tools": ["LeakCheck", "Garak", "PyRIT"], "rows": BENCHMARK_ROWS}
