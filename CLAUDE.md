# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt   # installs CUDA wheels via --extra-index-url
pip install -e .                  # installs leakcheck CLI in editable mode
```

`requirements.txt` must be used (not just `pip install -e .`) to get the correct CUDA PyTorch wheels from `https://download.pytorch.org/whl/cu118`.

## Common Commands

```bash
# Run tests (detection smoke tests require torch + sentence-transformers)
pytest
pytest tests/test_schemas.py          # run a single test file
pytest tests/test_scoring.py -k name  # run a single test by name

# CLI
leakcheck run configs/campaign.yaml
leakcheck serve --port 5000
leakcheck ping --endpoint http://127.0.0.1:1234/v1/chat/completions
leakcheck top data/runs/<run-id>/results.jsonl -n 5
leakcheck report data/runs/<run-id>   # regenerate report.html from summary.json
leakcheck selftest-semantic
```

The LLM endpoint defaults to `http://127.0.0.1:1234/v1/chat/completions` (LM Studio). Override with `LLM_ENDPOINT` and `LLM_MODEL` env vars when using the web app.

## Architecture

### Pipeline flow (CLI and web share the same core modules)

```
config YAML
  → ingest prompts (leakcheck/datasets/ingest.py)
  → mutate prompts (leakcheck/attack/mutate.py + operators.py)
  → LLM call      (leakcheck/llm/client.py)
  → detect        (leakcheck/detect/detector.py)
      ├─ rule hits     (detect/rules.py)
      ├─ semantic sim  (detect/semantic.py  — sentence-transformers)
      └─ response sig  (detect/response_signals.py)
  → score         (leakcheck/scoring/score.py + configs/thresholds.yaml)
  → summarize     (leakcheck/reporting/summarize.py)
  → report        (leakcheck/reporting/report_md.py + report_html.py)
```

Run outputs land in `data/runs/<timestamp>_<name>/` containing `results.jsonl`, `summary.json`, `config_snapshot.yaml`, `report.md`, `report.html`.

### Key architectural notes

**Web app duplicates pipeline logic.** `src/leakcheck/web/app.py` contains an inline copy of the campaign runner (not a call to `run_campaign()`). Changes to the CLI pipeline must be mirrored manually in the web app's `_run_campaign_job()` thread.

**`report.html` is generated at run time.** Older runs in `data/runs/` may only have `results.jsonl` and no `report.html`. The `leakcheck report <run_dir>` command regenerates it, but requires `summary.json` to exist. The web endpoint `/api/reports/<run_id>/html` returns 404 for these older runs.

**Semantic index is cached per category.** `build_semantic_index()` in `detect/semantic.py` uses `@lru_cache`. The web chat path hardcodes `all-MiniLM-L6-v2`; the CLI/campaign path uses whatever `detection.similarity_model` points to (default: `model/best_model`, a local fine-tuned model).

**Mutation is category-aware.** `benign` prompts only receive benign-safe operators; all other categories get attack operators. Unknown categories are treated as attack categories.

**Learned anchors are append-only per run.** Anchors written during a run are not retroactively re-embedded into the already-cached index for that run; they take effect on the next run.

**Scoring produces 0–10 CVSS-like severity.** `safe` always → 0.0. Bands: low 0.1–3.9, medium 4.0–6.9, high 7.0–8.9, critical 9.0–10.0. Policy loaded from `configs/thresholds.yaml`.

### Module map

| Path | Responsibility |
|------|---------------|
| `src/leakcheck/cli.py` | All CLI subcommands |
| `src/leakcheck/web/app.py` | Flask app, API routes, inline campaign runner |
| `src/leakcheck/attack/` | Mutation operators and prompt variant generation |
| `src/leakcheck/detect/` | Verdict logic, rules, semantic similarity, response signals |
| `src/leakcheck/llm/client.py` | OpenAI-compatible HTTP client with retry |
| `src/leakcheck/scoring/` | Severity scoring, CVSS explainer |
| `src/leakcheck/reporting/` | `summarize_results()`, HTML/MD report writers |
| `src/leakcheck/common/` | Schemas (`PromptRecord`, `MutationRecord`), run folder utils |
| `configs/campaign.yaml` | Active campaign config (edit before each run) |
| `data/raw/` | Input datasets (`prompts_demo.jsonl`, `prompts_full.jsonl`) |
| `model/best_model/` | Local sentence-transformers model for similarity |
