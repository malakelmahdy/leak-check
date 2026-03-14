# LeakCheck

LeakCheck is a local auditing tool for probing LLM prompt safety. It can:

- load prompt datasets from `jsonl` or `csv`
- mutate prompts with deterministic attack-style or benign-safe operators
- send prompts to an OpenAI-compatible chat-completions endpoint
- classify outcomes as `safe`, `attack_attempt`, or `attack_success`
- score and summarize results
- generate Markdown and HTML reports
- serve a Flask dashboard for running campaigns, browsing reports, and chatting with a model

This README is based on the code currently in this repository. Where behavior is environment-specific or not enforced in code, that is called out explicitly.

## What The Project Contains

- CLI entrypoint: [src/leakcheck/cli.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/cli.py)
- Prompt mutation logic: [src/leakcheck/attack/mutate.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/attack/mutate.py)
- Detection pipeline: [src/leakcheck/detect/detector.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/detector.py)
- Semantic similarity helpers: [src/leakcheck/detect/semantic.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/semantic.py)
- Rule-based detection: [src/leakcheck/detect/rules.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/rules.py)
- Response-signal extraction: [src/leakcheck/detect/response_signals.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/response_signals.py)
- LLM client: [src/leakcheck/llm/client.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/llm/client.py)
- Scoring: [src/leakcheck/scoring/score.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/scoring/score.py)
- Reporting: [src/leakcheck/reporting/report_md.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/reporting/report_md.py), [src/leakcheck/reporting/report_html.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/reporting/report_html.py)
- Web dashboard: [src/leakcheck/web/app.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/web/app.py)
- Example campaign config: [configs/campaign.yaml](/c:/Users/user/Downloads/leak-check/leak-check/configs/campaign.yaml)

## Architecture

The main batch pipeline in `leakcheck run` is:

1. Read YAML config.
2. Create a timestamped run directory under `run.output_root`.
3. Snapshot the config and input dataset.
4. Ingest prompts from `jsonl` or `csv`.
5. Generate prompt mutations if attacks are enabled.
6. Send each prompt variant to the configured LLM endpoint.
7. Detect rule hits, semantic similarity, and response signals.
8. Assign a verdict and severity score.
9. Append results to `results.jsonl`.
10. Build `summary.json`, `report.md`, and optionally `report.html`.

The web dashboard reuses the same core modules, but the campaign execution logic is duplicated inline inside [src/leakcheck/web/app.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/web/app.py).

## Requirements

## Python

The checked-in package metadata currently declares:

- Python `>=3.10,<3.14` in [pyproject.toml](/c:/Users/user/Downloads/leak-check/leak-check/pyproject.toml)

That constraint matters for the current ML stack. Detection depends on `sentence-transformers`, which imports `torch`.

## Dependencies

Core dependencies declared in [pyproject.toml](/c:/Users/user/Downloads/leak-check/leak-check/pyproject.toml):

- `pydantic`
- `pyyaml`
- `rich`
- `requests`
- `python-dotenv`
- `numpy`
- `torch`
- `torchvision`
- `torchaudio`
- `sentence-transformers`
- `pyarrow`
- `flask`

[requirements.txt](/c:/Users/user/Downloads/leak-check/leak-check/requirements.txt) also includes:

- `--extra-index-url https://download.pytorch.org/whl/cu118`

That extra index is a `pip` option, so it is present in `requirements.txt`, not in `pyproject.toml`.

## Install

Create a fresh virtual environment with a supported Python version:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

If you prefer editable install only:

```powershell
pip install -e .
```

Note that `pip install -e .` by itself does not apply the CUDA wheel index from `requirements.txt`.

## LLM Endpoint

The project expects an OpenAI-compatible chat completions endpoint. The default endpoint used in both CLI config and the web app is:

```text
http://127.0.0.1:1234/v1/chat/completions
```

The client sends:

```json
{
  "model": "...",
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.3,
  "max_tokens": 256,
  "stream": false
}
```

This behavior is implemented in [src/leakcheck/llm/client.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/llm/client.py).

The client is tolerant of multiple response shapes:

- OpenAI-style `choices[0].message.content`
- fallback fields like `text`, `response`, or `output`

## Quick Start

## 1. Check the LLM endpoint

```powershell
leakcheck ping --endpoint http://127.0.0.1:1234/v1/chat/completions
```

## 2. Review the campaign config

The default config is [configs/campaign.yaml](/c:/Users/user/Downloads/leak-check/leak-check/configs/campaign.yaml).

Important: the checked-in `detection.similarity_model` currently points to a machine-specific local Windows path. You should update it to:

- a valid SentenceTransformers model name, or
- a valid local model directory path

before running the detector on another machine.

## 3. Run a campaign

```powershell
leakcheck run configs/campaign.yaml
```

## 4. View top results from a prior run

```powershell
leakcheck top data\runs\<run-id>\results.jsonl -n 5
```

## 5. Start the web dashboard

```powershell
leakcheck serve --port 5000
```

Then open `http://localhost:5000`.

## CLI Commands

The CLI subcommands are defined in [src/leakcheck/cli.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/cli.py).

### `leakcheck run <config>`

Runs a full campaign from a YAML config.

### `leakcheck selftest-semantic`

Builds semantic indices for the hardcoded categories:

- `prompt_injection`
- `jailbreak`
- `data_exfil`

and prints similarity for sample prompts.

This command imports the semantic stack and therefore requires a working `sentence-transformers` and `torch` installation.

### `leakcheck ping --endpoint <url>`

Sends a simple chat completion request to the configured endpoint.

### `leakcheck top <results.jsonl> -n <count>`

Loads a results file, sorts by severity descending, and prints the top rows.

### `leakcheck report <run_dir>`

Regenerates `report.html` from `summary.json` and `config_snapshot.yaml`.

### `leakcheck serve`

Starts the Flask web app from [src/leakcheck/web/app.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/web/app.py).

## Campaign Config

The active example config is [configs/campaign.yaml](/c:/Users/user/Downloads/leak-check/leak-check/configs/campaign.yaml).

Supported sections used by the code:

### `run`

- `name`
- `seed`
- `output_root`

### `dataset`

- `path`
- `format`: `jsonl` or `csv`
- `text_field`
- `id_field`
- `category_field`

### `attack`

- `enabled`
- `mutations_per_prompt`
- `operators`

The web app also supports optional overrides for:

- `limit`
- `mutation_level`

### `llm`

- `provider`
- `endpoint`
- `timeout_s`
- `retries`
- `params.model`
- `params.temperature`
- `params.max_tokens`

### `detection`

- `enabled`
- `similarity_model`
- `similarity_threshold`
- `use_learned_anchors`
- `learned_anchors_path`

### `scoring`

- `enabled`
- `thresholds_file`

### `reporting`

- `enabled`
- `output_report_md`
- `output_report_html`
- `output_summary_json`

## Prompt Mutations

Mutation operators are defined in [src/leakcheck/attack/operators.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/attack/operators.py).

Implemented operators:

- `prefix_injection`
- `role_wrapper`
- `instruction_stack`
- `benign_rephrase_prefix`
- `benign_wrapper`
- `format_shift`
- `obfuscate_spacing`

Operator filtering is category-aware in [src/leakcheck/attack/mutate.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/attack/mutate.py):

- `benign` prompts only receive benign-safe/shared operators
- all other categories are treated as attack categories

Mutation generation is deterministic for a given `seed` and mutation index.

## Detection Logic

Detection combines three sources of evidence:

### 1. Rule hits

Rule patterns are implemented in [src/leakcheck/detect/rules.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/rules.py).

Categories with explicit regex rules:

- `prompt_injection`
- `jailbreak`
- `data_exfil`

There is also a benign-context allowlist that produces `BENIGN_*` markers.

### 2. Semantic similarity

Semantic similarity is implemented in [src/leakcheck/detect/semantic.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/semantic.py).

Important implementation details:

- similarity uses `SentenceTransformer(model_name)`
- each category gets its own cached semantic index
- static anchor texts are built into the code for `prompt_injection`, `jailbreak`, and `data_exfil`
- prompt text is sanitized before similarity scoring
- short greetings like `hi` and `hello` are whitelisted to similarity `0.0`
- prompts shorter than 15 characters require similarity at least `0.75` to count

### 3. Response signals

Response analysis is implemented in [src/leakcheck/detect/response_signals.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/response_signals.py).

It distinguishes:

- refusal signals
- attempt or mention signals
- stronger success-evidence signals

Success signals are gated so refusal text is not treated as attack success.

## Verdicts

The detector emits one of:

- `safe`
- `attack_attempt`
- `attack_success`

Current logic in [src/leakcheck/detect/detector.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/detector.py):

- `attack_success` requires explicit success evidence from the model response
- `attack_attempt` is triggered by attack rule hits or similarity above threshold
- `safe` is used otherwise

The detector also marks over-refusal cases when:

- the final verdict is `safe`
- the response contains a refusal
- no attack rules were hit

## Learned Anchors

If `use_learned_anchors` is enabled, the semantic index loads additional anchors from `learned_anchors_path`.

Current behavior:

- if the file does not exist, the loader returns an empty list
- qualifying prompts are appended automatically during detection
- the file is written as JSONL with one object per line, containing a `text` field

This is implemented in [src/leakcheck/detect/semantic.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/semantic.py) and [src/leakcheck/detect/detector.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/detect/detector.py).

Important limitation:

- learned anchors appended after an index is already cached are not retroactively re-embedded for that same cached index during the current run
- they will be available on the next run

## Scoring

Scoring is implemented in [src/leakcheck/scoring/score.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/scoring/score.py).

Inputs to severity:

- verdict
- category impact base
- confidence
- repeatability

Configured thresholds are read from [configs/thresholds.yaml](/c:/Users/user/Downloads/leak-check/leak-check/configs/thresholds.yaml):

- `low`: `0.1` to `3.9`
- `medium`: `4.0` to `6.9`
- `high`: `7.0` to `8.9`
- `critical`: `9.0` to `10.0`

## Run Outputs

Each run creates a timestamped directory under `run.output_root`, for example:

```text
data/runs/20260218_103719_Maximum Campaign
```

Files created by the pipeline:

- `config_snapshot.yaml`
- `dataset_snapshot/<original filename>`
- `logs.txt`
- `results.jsonl`
- `summary.json` if enabled
- `report.md` if enabled
- `report.html` if enabled

## Results Format

Each record appended to `results.jsonl` currently contains:

- `base_id`
- `prompt_id`
- `category`
- `operators`
- `prompt_text`
- `response_text`
- `latency_ms`
- `verdict`
- `is_attempt`
- `is_success`
- `over_refusal`
- `confidence`
- `rule_hits`
- `similarity_score`
- `response_signals`
- `severity`
- `level`
- `evidence`

## Web Dashboard

The Flask app serves four pages:

- `/`
- `/campaigns`
- `/reports`
- `/chat`

The app also exposes JSON endpoints:

- `GET /api/reports`
- `GET /api/reports/<run_id>/html`
- `GET /api/reports/<run_id>/summary`
- `POST /api/chat`
- `POST /api/campaign/run`
- `GET /api/campaign/status/<job_id>`
- `GET /api/ping`

Environment variables used by the web app:

- `LLM_ENDPOINT`
- `LLM_MODEL`

### Web-specific behavior worth knowing

- chat detection currently instantiates `Detector` with `similarity_model="all-MiniLM-L6-v2"` and `use_learned=False`
- the web campaign runner supports `mutation_level` and maps it to operator presets
- the web app keeps job state in an in-memory `_jobs` dictionary

That means job state is not persisted across process restarts.

## Reports

Markdown report generation is in [src/leakcheck/reporting/report_md.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/reporting/report_md.py).

HTML report generation is in [src/leakcheck/reporting/report_html.py](/c:/Users/user/Downloads/leak-check/leak-check/src/leakcheck/reporting/report_html.py).

The HTML report is self-contained in the sense that it writes a single HTML file, but the generated page currently references external CDNs for:

- Google Fonts
- Chart.js

So full offline rendering of the report page is not guaranteed by the code as written.

## Dataset Preparation Script

[scripts/prepare_datasets.py](/c:/Users/user/Downloads/leak-check/leak-check/scripts/prepare_datasets.py) merges several external datasets into LeakCheck JSONL files.

Important caveat:

- the script currently hardcodes `DATASETS_ROOT` to `C:\Users\mahmoud\Downloads\DATASETS to use`

Outputs written by the script:

- [data/raw/prompts_demo.jsonl](/c:/Users/user/Downloads/leak-check/leak-check/data/raw/prompts_demo.jsonl)
- [data/raw/prompts_full.jsonl](/c:/Users/user/Downloads/leak-check/leak-check/data/raw/prompts_full.jsonl)

## Tests

Current tests in [tests](/c:/Users/user/Downloads/leak-check/leak-check/tests):

- [tests/test_schemas.py](/c:/Users/user/Downloads/leak-check/leak-check/tests/test_schemas.py)
- [tests/test_mutation_determinism.py](/c:/Users/user/Downloads/leak-check/leak-check/tests/test_mutation_determinism.py)
- [tests/test_detection_smoke.py](/c:/Users/user/Downloads/leak-check/leak-check/tests/test_detection_smoke.py)

Run them with:

```powershell
pytest
```

Be aware that the detection smoke test imports `Detector`, so it also depends on a working `sentence-transformers` and `torch` installation.

## Current Limitations And Caveats

- The checked-in campaign config contains a machine-specific `similarity_model` path and is not portable as-is.
- Detection requires a working local `torch` installation.
- The web chat detection path is not config-driven; it hardcodes `all-MiniLM-L6-v2`.
- Web job state is in memory only.
- The web app duplicates pipeline logic instead of calling the CLI entrypoint or a shared service layer.
- `attack.enabled: true` in the CLI path generates mutations only; it does not currently include the original unmutated prompt in addition to mutations.
- Unknown prompt categories are treated as attack categories by mutation filtering, but rule-based detection only has explicit rules for `prompt_injection`, `jailbreak`, and `data_exfil`.

## Repository Layout

```text
configs/        YAML config files and thresholds
data/raw/       Input datasets
data/runs/      Generated run artifacts
scripts/        Utility scripts
src/leakcheck/  Application source
tests/          Basic tests
```
