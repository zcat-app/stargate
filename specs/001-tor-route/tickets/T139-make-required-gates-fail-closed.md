---
id: "T139"
title: "Prevent required verification coverage from disappearing"
status: done
created: "2026-09-12"
last_updated: 2026-09-12
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T076", "T156", "T160"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T076"
tests_first: []
reviews: { round: 2, date: 2026-09-12, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T139: Prevent required verification coverage from disappearing

## Context

Existing findings 20260727-007/008 remain: executable-bit changes skip required scripts and go.work removal can omit a required module.

## Analysis

- Must hold (VII): required runners execute or fail despite mode changes; every present
  mandatory Go module is covered even when go.work omits it; failing tests retain diagnostics.
  Genuine absent substrate and explicitly selected cadence retain honest SKIP accounting.
- Must hold (VIII): review and commit require a complete source inventory, all changed paths
  count toward budget, and changes after review invalidate approval, including new files.
- Gated: existing workflow fixtures cover discovered modules, skip accounting and tracked
  redteam snapshot changes, but not executable-bit loss, workspace omission or untracked files.
- Residue: add hermetic negative fixtures against the real gates/driver for those omissions,
  with staged new/tracked source and ignored build output as positive controls. Independent
  review checks the inventory boundary and lifecycle transitions. Live routing guarantees
  remain outside these tooling fixtures and require their separately named cadence jobs.

## Acceptance

1. Add negative fixtures clearing each named required gate executable bit; existing checks must run through an interpreter or fail, never silently SKIP.
2. Add a required-module omission fixture for each current mandatory workspace module; removing it from go.work must fail verification while additional module discovery remains supported.
3. Preserve genuine absent-substrate and opt-in cadence skip semantics; explicitly distinguish missing mandatory coverage from optional coverage.
4. Run the gate contract tests and scripts/verify.sh; document the boundary under Constitution VII.

5. T156 review identified a related evidence gap: the driver's git-diff snapshot/count omits
   unstaged new files. Derive a failing regression adding/changing an intended untracked source
   after review; approval must not remain usable. Enforce a complete source inventory/staging
   precondition, all-path budget count and reviewer snapshot invalidation (including new files).
   Test ordinary staged tracked/new files still work and unrelated ignored build artifacts do
   not masquerade as intended source. Manual manifest checks are required until this lands.

Retain failing Go test diagnostics and test names with nonzero package results; the current
gate emitted only summary counts during the T156 bookkeeping rerun, preventing diagnosis.
A targeted unchanged rerun passed; do not fabricate a root cause or silence an intermittent failure.

## Out-of-scope

Verification-log concurrency (T120), static analyzer rollout (T114), or changing production tests to obtain green.

The maintainer authorized updating `tests/contract/workflow/run_task_test.sh` fixtures in
this session: request review before supplying approval, preserving behavioral assertions.

## Notes

### T139 tests-first evidence (2026-09-12)

- Pre-fix source: HEAD `8177b9012077055aeea5c647ce1236aac947b574`.
  `bash tests/contract/workflow/required_coverage_test.sh` exited 1: 9 test methods,
  17 failed assertions/subcases. All five runner modes and mandatory-module omissions,
  missing-workspace coverage, diagnostic retention, untracked review inputs and budget
  enforcement failed on behavior; absent substrate and staged/ignored controls passed.
- Regression file SHA-256 at red run:
  `92af171ffdd7a4e318192dd47c97c1220c6e6ea17dd33fa3d17c59add5cf1eed`.
  Full local output: `target/runs/T139-red.log` (gitignored).
- After implementation the same command exited 0 (9 methods); the existing workflow-driver
  harness passed all 12 scenarios after the authorized review-request fixture updates.
  Local outputs: `target/runs/T139-green.log`, `target/runs/T139-driver.log`.
- A follow-up pre-review falsifier deleted each runner while retaining its substrate.
  The added extension-runner deletion subcase failed before its repair (exit 1, one failed
  subcase; `target/runs/T139-missing-runner-red.log`); empty extension/Java scaffolds still SKIP.
- Boundary: these hermetic fixtures verify coverage/evidence orchestration under VII/VIII.
  Existing cadence skip tests retain Docker/live/release separation; skipped runtime checks
  remain pending and no Tor/browser privacy guarantee is established by this tooling repair.

### Round 2 — redteam M1

The first security review reproduced a delayed codereview result authorizing a newer handoff.
The pre-fix implementation is preserved by the round-1 diff/manifest
(`target/runs/T139-reviewed-r1.*`; manifest hash
`46d7f1c090d3f5db21622a6e8c9d625ae2b40f01465e5133a54a201ad446eb81`).
Two added regression methods demonstrate the delayed-response sequence and missing/duplicate/
wrong snapshot or round fields: `bash tests/contract/workflow/required_coverage_test.sh`
exited 1 with 7 failures across 11 methods before the response-binding repair
(`target/runs/T139-r2-red.log`). Code-review verdicts now carry and validate the exact handoff
identity, like redteam verdicts. Existing fixture reviewers copy these required fields.

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
