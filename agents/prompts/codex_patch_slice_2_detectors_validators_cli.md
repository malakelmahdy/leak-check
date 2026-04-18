You are working directly inside the LeakCheck repository with write access.

Implement PATCH SLICE 2 only.

## Patch slice 2 scope

Your goal in this pass is to connect the post-v2 scoring pipeline to real detector outputs and real validator hooks.

You must:

1. inspect existing detector outputs, schemas, CLI/web integration, and semantic detector loading behavior
2. adapt detector outputs into typed evidence/finding structures
3. add validator registry/hooks for at least:
   - exact canary
   - secret validation
   - conservative PII validation path if supported
4. wire CLI/web/reporting so signoff severity v2 is the first-class signoff output
5. stabilize semantic detector failure behavior so it degrades safely instead of breaking the pipeline
6. add focused tests and run them

## Must-have behavior

- legacy detector output can be normalized into typed evidence
- validator-backed findings influence confidence / validated flags
- signoff severity v2 is surfaced in main execution/reporting paths
- semantic dependency failure becomes degraded mode, not pipeline crash
- duplicate findings do not inflate scoring

## Constraints

- Do not rewrite the whole detector stack.
- Use adapters where needed.
- Prefer modifying existing files.
- If a full validator is too large for one pass, implement the registry and at least one real path with safe stubs for the rest.

## End condition

Do not stop after analysis.
Stop only after:
- code is changed
- tests were run
- results are reported

At the end report:
- changed files
- key diffs
- tests run
- pass/fail
- remaining blockers
