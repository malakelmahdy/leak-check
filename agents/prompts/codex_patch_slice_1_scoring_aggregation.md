You are working directly inside the LeakCheck repository with write access.

Implement PATCH SLICE 1 only.

## Patch slice 1 scope

Your goal in this pass is to replace the current scoring + aggregation path with a v2 path while minimizing disruption.

You must:

1. inspect the existing scoring, summarize/reporting, schemas, and CLI wiring
2. add typed v2 models if missing
3. implement:
   - score_finding_v2(...)
   - aggregate_response_v2(...)
   - aggregate_run_v2(...)
4. wire the CLI/reporting path so v2 scores can be produced from existing detection outputs
5. add focused tests for scoring and aggregation
6. run the tests and fix failures

## Must-have behavior

The v2 path must support:
- impact
- evidence_confidence
- exploitability
- exposure_extent
- severity_band
- review_required
- semantic-only unsupported cap
- exact-canary override hook
- worst-case-preserving run summary

## Constraints

- Do not redesign the whole project.
- Do not touch semantic/dynamic detectors yet unless needed to adapt interfaces.
- Use adapters if current detection outputs are messy.
- Keep patch size reasonable but complete.
- Prefer modifying existing files over creating many new ones.

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
- next patch slice recommendation
