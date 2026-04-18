You are working directly inside the LeakCheck repository with write access.

Your task is to COMPLETE the remaining remediation work in the actual codebase, not to write another architecture document.

Patch Slice 1 is already done:
- v2 typed schemas were added
- v2 scoring was added
- v2 reporting/signoff fields were added
- targeted scoring/reporting tests passed

Your task now is to address the remaining patch areas together in one coordinated implementation pass.

## Mission

Implement the remaining high-priority remediation work across the repository so that LeakCheck is materially closer to a production-viable leakage pipeline.

You must inspect the real codebase, modify files in place, run tests, fix failures, and finish with concrete repo changes.

Do not stop at analysis.
Do not output only recommendations.
Do not restate the audit or migration plan.

## Remaining work to implement in this pass

You must address all of these areas in one coordinated patch set:

1. Detector output modernization
   - Adapt the detector pipeline so current detectors can emit or be normalized into typed DetectorEvidence / LeakageFinding-compatible structures.
   - Do not require a full detector rewrite before wiring.
   - Use adapters where necessary.

2. Validator layer integration
   - Add validator hooks for at least:
     - exact canary
     - validated secret
     - basic PII validation path if the current repo supports entity extraction
   - If full validator implementations are too large for one pass, create real registry + interfaces + at least one working validator path and route the rest through explicit stubs/TODOs in code.
   - Validation must affect evidence confidence / validated flags rather than raw impact.

3. CLI and web integration
   - Wire the main execution/reporting flow so signoff severity v2 is first-class.
   - Ensure CLI/web/reporting surfaces use the new worst-case-preserving signoff fields where appropriate.
   - Preserve compatibility where necessary, but do not keep v1 as the implicit primary signoff path.

4. Detection normalization
   - Bridge legacy DetectionResult / loose evidence dicts into the new typed evidence/finding path.
   - Deduplicate evidence/finding records safely.
   - Ensure duplicate findings do not inflate scoring.

5. Semantic detector stabilization
   - Inspect the current semantic detector failure or loader issue.
   - Fix it if feasible in this pass.
   - If not fully fixable, implement the maximum safe improvement:
     - fail-soft behavior
     - explicit degraded-mode path
     - no crash of the main pipeline
     - tests covering the degraded path

6. Test and validation coverage
   - Add or update tests for:
     - detector-to-evidence normalization
     - validator-backed flagging
     - CLI/reporting signoff severity v2 usage
     - degraded semantic path if semantic dependencies fail
     - no critical finding averaged away at run/report level

## Constraints

- Work in the real repository only.
- Prefer modifying existing files over creating many new ones.
- Keep the patch incremental and reviewable, but broad enough to cover the remaining remediation areas together.
- Do not do a speculative greenfield rewrite.
- Do not break current entrypoints if compatibility can be preserved.
- If a feature must remain partial, implement the interface and safe fallback rather than leaving it as prose.

## Required workflow

1. Inspect the current repository structure and locate the real files for:
   - detect/
   - scoring/
   - reporting/
   - cli/web entrypoints
   - schemas/models
   - semantic detector
   - tests

2. Identify the exact files to modify for this patch set.

3. Implement the remaining remediation across the actual repo:
   - detector adapters / typed evidence emission
   - validator registry/hooks
   - CLI/web/reporting integration
   - semantic fail-soft or fix
   - new tests

4. Run focused tests first.
5. Run any broader relevant test subset that covers the touched areas.
6. If failures appear, fix them before finishing.

## Implementation guidance

### A. Detector modernization
- Reuse existing detector logic where possible.
- Introduce an adapter layer if detector modules still return legacy DetectionResult or free-form evidence dicts.
- Normalize detector output into typed DetectorEvidence and LeakageFinding-compatible structures before scoring.
- Ensure detector evidence contains enough metadata for:
  - leak_type
  - confidence
  - fingerprint / dedupe
  - validation hooks
  - source/reference info if present

### B. Validator integration
Implement a real validator path, not just comments.

Minimum acceptable outcome:
- validator registry
- exact canary validator or hook
- secret validation path or provider-aware heuristic path
- validated / rejected / inconclusive states
- scoring integration through validated flags / confidence adjustments

If PII support is incomplete:
- add the validator interface and a conservative initial implementation
- do not fake validation confidence

### C. CLI/web/reporting integration
- Main signoff fields should prefer:
  - signoff_severity
  - signoff_severity_label
  - validated_critical_count
  - review_queue_count
- Ensure summaries and top results sort by the v2 signoff severity path.
- Preserve compatibility fields only if existing consumers require them.

### D. Semantic detector stabilization
- The semantic detector must not take down the pipeline.
- If model loading fails:
  - emit a controlled degraded-mode result
  - log the condition
  - avoid false escalation
  - keep the rest of the pipeline functional

### E. Testing
Add focused tests that prove:
- legacy detector output can be normalized into typed evidence
- validator results influence findings/scoring
- CLI/reporting surfaces use v2 signoff fields
- semantic dependency failure degrades safely
- critical findings remain preserved in aggregation/reporting

## Non-negotiable rules

- Do not return only a plan.
- Do not return only prose.
- Do not stop after identifying files.
- Modify repository files.
- Run commands.
- Report actual changed files and actual test results.
- If blocked, implement the maximum safe partial progress and name the blocker precisely.

## Preferred deliverable behavior

Before finishing, verify that you have:
- inspected the real files
- modified repository files
- run at least one focused test command
- run a broader relevant test command if feasible
- reported actual changed paths
- reported actual command outputs/results

If any of these did not happen, the task is incomplete.

## End-of-task response format

1. Files changed
2. What was implemented
3. Commands run
4. Test results
5. Remaining blockers
6. Recommended next patch only if truly needed after this pass

## Grounding context

Context from prior completed patch:
- v2 schemas/scoring/reporting fields already exist
- targeted tests for scoring/reporting already passed

Known remaining blockers from the last run:
- current detectors still emit legacy DetectionResult plus loose evidence dicts
- v2 path can consume structured findings, but detector modules do not generate them yet
- validator hooks for validated_secret / exact_canary are not wired
- CLI/web reporting should display signoff_severity first-class
- semantic model loading failures were not addressed yet

Do not redesign these from scratch unless the existing implementation makes patching impossible.
Patch the real codebase accordingly.
