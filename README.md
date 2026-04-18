# LeakCheck — automated prompt-safety auditing for local LLMs

## Overview

- Probes LLM endpoints for prompt injection, jailbreak, and data exfiltration vulnerabilities using configurable prompt mutation operators
- Detects attack outcomes through three combined signals: regex rule matching, semantic similarity (sentence-transformers), and response-side signal analysis
- Produces a dual severity score: **leak severity** (0–10, CVSS-aligned bands) and **attack risk score**, both written to `results.jsonl`
- Generates JSONL result records, Markdown reports, and self-contained HTML reports with charts per run

## Architecture

```
configs/campaign.yaml
  └─ ingest prompts     (datasets/ingest.py)
  └─ mutate prompts     (attack/mutate.py + operators.py)
  └─ LLM call           (llm/client.py)
  └─ detect             (detect/detector.py)
       ├─ rule hits     (detect/rules.py)
       ├─ semantic sim  (detect/semantic.py)
       └─ response sig  (detect/response_signals.py)
  └─ score              (scoring/score.py + configs/thresholds.yaml)
  └─ summarize          (reporting/summarize.py)
  └─ report             (reporting/report_md.py + report_html.py)
```

Run outputs land in `data/runs/<timestamp>_<name>/` containing `results.jsonl`, `summary.json`, `config_snapshot.yaml`, `report.md`, and `report.html`.

**Note:** `src/leakcheck/web/app.py` contains an inline copy of the campaign runner, not a call to `run_campaign()`. Changes to the CLI pipeline must be mirrored manually in the web app's `_run_campaign_job()` thread.

## Repository Layout

```
configs/                    YAML campaign config and scoring thresholds
data/
  raw/                      Input datasets (prompts_demo.jsonl, prompts_full.jsonl)
  interim/                  Learned anchors (learned_attacks.jsonl)
  runs/                     Generated run artifacts (timestamped subdirs)
model/
  best_model/               Local fine-tuned sentence-transformers model
scripts/                    Utility scripts (dataset preparation)
src/leakcheck/
  attack/                   Mutation operators and prompt variant generation
  common/                   Schemas (PromptRecord, MutationRecord), run folder utils
  datasets/                 Prompt ingestion (JSONL, CSV)
  detect/                   Detector, rules, semantic similarity, response signals
  llm/                      OpenAI-compatible HTTP client with retry
  reporting/                summarize_results(), HTML and Markdown report writers
  scoring/                  Severity scoring, CVSS explainer
  validators/               Validated finding types
  web/                      Flask app, API routes, inline campaign runner
tests/                      Test suite
```

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt   # required: applies --extra-index-url for CUDA wheels
pip install -e .                  # installs leakcheck CLI in editable mode
```

`pip install -e .` alone does **not** apply the CUDA PyTorch wheel index from `requirements.txt`. Both steps are required for GPU-accelerated inference.

Requires Python `>=3.10,<3.14`.

## Configuration

### campaign.yaml keys

| Section | Key | Type | Effect |
|---------|-----|------|--------|
| `run` | `name` | string | Label appended to the run folder name |
| `run` | `seed` | int | Seed for deterministic mutation |
| `run` | `output_root` | string | Root directory for run output (e.g. `data/runs`) |
| `dataset` | `path` | string | Path to input dataset |
| `dataset` | `format` | string | `jsonl` or `csv` |
| `dataset` | `text_field` | string | Field containing prompt text |
| `dataset` | `id_field` | string | Field containing prompt ID |
| `dataset` | `category_field` | string | Field containing prompt category |
| `attack` | `enabled` | bool | Enable mutation generation |
| `attack` | `mutations_per_prompt` | int | Number of variants to generate per prompt |
| `attack` | `operators` | list | Operator names to apply (see Detection Pipeline) |
| `llm` | `provider` | string | Client type (e.g. `lmstudio_openai_compat`) |
| `llm` | `endpoint` | string | Chat completions URL |
| `llm` | `timeout_s` | int | Request timeout in seconds |
| `llm` | `retries` | int | Retry count on failure |
| `llm` | `params.model` | string | Model name sent in request body |
| `llm` | `params.temperature` | float | Sampling temperature |
| `llm` | `params.max_tokens` | int | Max tokens in response |
| `detection` | `similarity_model` | string | SentenceTransformers model name or local path |
| `detection` | `similarity_threshold` | float | Cosine similarity threshold for attack flagging |
| `detection` | `use_learned_anchors` | bool | Load additional anchors from file |
| `detection` | `learned_anchors_path` | string | Path to learned anchors JSONL |
| `scoring` | `thresholds_file` | string | Path to thresholds YAML |
| `reporting` | `output_report_md` | bool | Write `report.md` |
| `reporting` | `output_report_html` | bool | Write `report.html` |
| `reporting` | `output_summary_json` | bool | Write `summary.json` |

### Environment variables (web app)

| Variable | Default | Effect |
|----------|---------|--------|
| `LLM_ENDPOINT` | `http://127.0.0.1:1234/v1/chat/completions` | LLM endpoint used by the web app |
| `LLM_MODEL` | `llama-3.2-3b-instruct` | Model name sent in web app requests |
| `LLM_TIMEOUT_S` | `180` | Request timeout (seconds) for the web app |

## Quick Start

```bash
# 1. Verify LLM endpoint is reachable
leakcheck ping --endpoint http://127.0.0.1:1234/v1/chat/completions

# 2. Edit configs/campaign.yaml (set dataset path, model, endpoint)

# 3. Run a campaign
leakcheck run configs/campaign.yaml

# 4. Inspect top results
leakcheck top data/runs/<run-id>/results.jsonl -n 5

# 5. Open the HTML report
#    data/runs/<run-id>/report.html
```

## CLI Reference

### `leakcheck run`

Run a full campaign from a YAML config file.

```
leakcheck run <config>
```

| Argument | Description |
|----------|-------------|
| `config` | Path to `campaign.yaml` |

```bash
leakcheck run configs/campaign.yaml
```

### `leakcheck serve`

Start the LeakCheck Flask web dashboard.

```
leakcheck serve [--host HOST] [--port PORT]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--host` | `0.0.0.0` | Host to bind to |
| `--port` | `5000` | Port to listen on |

```bash
leakcheck serve --port 5000
# then open http://localhost:5000
```

### `leakcheck ping`

Test connectivity to an LLM endpoint by sending a single prompt.

```
leakcheck ping [--endpoint URL]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--endpoint` | `http://127.0.0.1:1234/v1/chat/completions` | Chat completions URL |

```bash
leakcheck ping --endpoint http://127.0.0.1:1234/v1/chat/completions
```

### `leakcheck top`

Print the top-N results from a `results.jsonl` file, sorted by severity descending.

```
leakcheck top <results> [-n N]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `results` | — | Path to `results.jsonl` |
| `-n` | `5` | Number of results to display |

```bash
leakcheck top data/runs/<run-id>/results.jsonl -n 10
```

### `leakcheck report`

Regenerate `report.html` from an existing run folder. Requires `summary.json` to be present.

```
leakcheck report <run_dir>
```

| Argument | Description |
|----------|-------------|
| `run_dir` | Path to run folder |

```bash
leakcheck report data/runs/<run-id>
```

### `leakcheck selftest-semantic`

Build semantic indices for `prompt_injection`, `jailbreak`, and `data_exfil`, then print cosine similarity scores for sample prompts. Useful for verifying the sentence-transformers stack.

```bash
leakcheck selftest-semantic
```

## Detection Pipeline

### Stage 1 — Rule detection

Regex rules defined in `detect/rules.py` match against a canonicalized (lowercased, de-obfuscated) copy of the prompt text.

Rule IDs by category:

- **prompt_injection:** `PI_IGNORE_PREV`, `PI_SYSTEM_PROMPT`, `PI_REVEAL_SYSTEM`, `PI_LEAK_REQUEST`
- **jailbreak:** `JB_DEV_MODE`, `JB_BYPASS`, `JB_NO_RESTRICTIONS`
- **data_exfil:** `EXFIL_KEYS`, `EXFIL_CONFIDENTIAL`, `EXFIL_REVEAL`, `EXFIL_TRAINING_DATA`

ML classifier signals (`ML_INJECTION`, `ML_JAILBREAK`, `ML_LEAKAGE`, and weak variants) are also supported as dynamic rule hits weighted in `configs/thresholds.yaml`.

### Stage 2 — Semantic similarity

`detect/semantic.py` embeds the prompt with a SentenceTransformers model and computes cosine similarity against per-category static anchor texts. The index is cached per `(model, category)` pair via `@lru_cache`.

- Short greetings (`hi`, `hello`) are whitelisted to similarity `0.0`
- Prompts shorter than 15 characters require similarity ≥ `0.75` to count
- If `use_learned_anchors` is enabled, additional anchors are loaded from `learned_anchors_path` at index build time

### Stage 3 — Response signals

`detect/response_signals.py` analyzes the LLM response to classify:

- **Refusal signals** — model declined the request
- **Attempt/mention signals** — model acknowledged the intent
- **Success signals** — model complied with the attack

Success signals are gated: refusal text prevents a success classification.

Verdicts emitted: `safe`, `attack_attempt`, `attack_success`.

## Scoring

LeakCheck uses a dual scoring system, both written to each `results.jsonl` record via `score_output_fields()`.

### Leak severity (0–10)

CVSS-aligned severity score computed from category base score, verdict bonus, rule hits, semantic similarity, response signals, and repeatability across variants.

| Band | Range |
|------|-------|
| none | 0.0 |
| low | 0.1–3.9 |
| medium | 4.0–6.9 |
| high | 7.0–8.9 |
| critical | 9.0–10.0 |

- `safe` verdict always forces severity `0.0`
- `attack_attempt` is capped at `6.9`; `attack_success` can reach `10.0`
- Policy loaded from `configs/thresholds.yaml` (`score_version: leakcheck_cvss_aligned_v1`)

### Attack risk score

A second score field capturing attack-side risk, also present in `results.jsonl`. Both scores are visible in the `leakcheck top` output (`attack_risk=` and `leak=` columns).

## Testing

```bash
# Run all tests
pytest

# Run a specific file
pytest tests/test_schemas.py

# Run a specific test by name
pytest tests/test_scoring.py -k <name>
```

| Test file | Description |
|-----------|-------------|
| `tests/test_schemas.py` | Pydantic schema validation for core record types |
| `tests/test_mutation_determinism.py` | Mutation operators produce stable output for a fixed seed |
| `tests/test_detection_smoke.py` | End-to-end detector smoke test (requires torch + sentence-transformers) |
| `tests/test_scoring.py` | Severity scoring logic and CVSS explainer |
| `tests/test_reporting.py` | HTML and Markdown report generation |
| `tests/test_web_detection.py` | Web app detection helpers and API routes |
| `tests/test_run_utils.py` | Run folder utilities and path resolution |
| `tests/test_validators_registry.py` | Validator registry and typed finding construction |
| `tests/test_dependency_hygiene.py` | Verifies no import cycles exist in the internal module graph |
| `tests/test_repo_hygiene.py` | Verifies no internal import cycles at the repository level |
| `tests/test_prepare_datasets.py` | Dataset preparation script import and structure |

## Code Quality

```bash
# Lint
ruff check src/ tests/

# Format check
ruff format --check src/ tests/

# Auto-fix
ruff check --fix src/ tests/
```

Relevant `pyproject.toml` config:

```toml
[tool.ruff]
line-length = 120
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "W", "I"]
ignore = ["E501"]
```

Install dev dependencies with `pip install -e ".[dev]"` (includes `pytest>=8.0` and `ruff>=0.4`).

## Known Limitations

- **Web app duplicates CLI pipeline.** `src/leakcheck/web/app.py` contains an inline copy of `run_campaign()`; changes to the CLI pipeline must be mirrored manually in the web app.
- **`model/best_model` is machine-local.** The local fine-tuned model is not portable across machines. Use `all-MiniLM-L6-v2` (a public SentenceTransformers model) as a portable alternative in `configs/campaign.yaml`.
- **Learned anchors are append-only per run.** Anchors written during a run are not retroactively embedded into the already-cached index for that run; they take effect on the next run.
- **Web chat hardcodes `all-MiniLM-L6-v2`.** The `/api/chat` detection path uses a fixed model name, independent of `campaign.yaml`.
- **Web job state is in-memory only.** The `_jobs` dictionary is lost on process restart; there is no persistence layer.
- **HTML reports reference external CDNs.** Generated `report.html` files load Chart.js and Google Fonts from the internet; offline rendering is not guaranteed.
- **Unknown prompt categories default to attack operators.** Mutation filtering treats any category other than `benign` as an attack category.
