# LeakCheck Agent Operating Guide

This repository uses agent-driven remediation. Agents working in this repo must modify code, run validation commands, and report concrete diffs.

## Mission

Move LeakCheck toward a production-viable LLM leakage pipeline.

Priority order:
1. Preserve or improve correctness of signoff severity.
2. Preserve backward compatibility where reasonable.
3. Prefer incremental patches over speculative rewrites.
4. Add tests for every behavior change.

## Non-negotiable rules

- Do not stop at recommendations when repository edits are possible.
- Do not output only plans or architecture prose.
- Inspect the real codebase before proposing changes.
- Prefer modifying existing files over creating new ones.
- If a subsystem is too large to fully replace, add a safe adapter layer and explicit TODOs in code.
- Never let semantic detection failures crash the full pipeline.
- Never average away a validated critical leak in signoff metrics.
- Do not confuse detector confidence with business impact.
- Do not treat regex-only secret hits as validated leaks.
- Do not escalate semantic-only suspicion to critical without corroboration.

## Primary signoff model

The v2 signoff path is the primary path for security-facing severity.

Preferred fields:
- `signoff_severity`
- `signoff_severity_label`
- `validated_critical_count`
- `review_queue_count`

Legacy severity fields may remain only for compatibility or migration support.

## Required workflow

1. Inspect repository files relevant to the task.
2. Identify the smallest high-impact patch slice that materially improves the repo.
3. Edit code in place.
4. Run focused tests for touched areas.
5. Run a broader relevant test subset if feasible.
6. Fix failures before finishing.
7. Report:
   - changed files
   - commands run
   - test results
   - remaining blockers

## Repository task defaults

When asked to continue remediation, prioritize this order unless the current task explicitly narrows scope:

1. typed evidence / finding contracts
2. scoring and aggregation correctness
3. detector normalization and adapters
4. validator registry and validator-backed findings
5. CLI / web signoff integration
6. semantic detector fail-soft behavior
7. semantic detector source-grounding
8. dynamic attack harness
9. calibration and regression harness

## Test command defaults

Use these as starting points and adapt to the actual repo structure:

### Focused tests

```bash
PYTHONPATH=src pytest -q tests/test_scoring.py tests/test_reporting.py
```

### Expanded touched-area tests

```bash
PYTHONPATH=src pytest -q tests/test_scoring.py tests/test_reporting.py tests/test_semantic.py tests/test_cli.py
```

### Full suite

```bash
PYTHONPATH=src pytest -q
```

If the repo uses a different test layout, detect and adapt.

## Implementation expectations by subsystem

### Scoring
- Score per finding, not only per response.
- Separate:
  - impact
  - evidence_confidence
  - exploitability
  - exposure_extent
- Preserve v2 as the signoff path.
- Keep compatibility shims only if required.

### Aggregation
- Worst-case preserving.
- Validated critical findings must remain visible in response/run summaries.
- Duplicate evidence must not inflate severity.

### Detection
- Existing detectors may be adapted through typed evidence adapters before full refactor.
- Every detector output should become structured evidence before scoring.

### Validators
- Prefer deterministic validators where possible.
- Minimum states:
  - validated
  - rejected
  - inconclusive
- Validation affects confidence and review paths, not raw impact.

### Semantic detection
- Must fail soft.
- No pipeline crash on model load failure.
- Unsupported semantic-only findings must stay capped and review-flagged.

## What to do when blocked

If blocked:
- identify the exact file/module causing the blocker
- implement the maximum safe partial progress around it
- leave explicit TODOs in code where appropriate
- report the blocker precisely instead of stopping with generic prose

## End-of-task response format

1. Files changed
2. What was implemented
3. Commands run
4. Test results
5. Remaining blockers
6. Recommended next patch only if still needed
