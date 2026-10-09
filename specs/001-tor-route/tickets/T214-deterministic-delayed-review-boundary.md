---
id: T214
title: "Make delayed review-boundary controls deterministic"
status: pending
created: 2026-10-09
last_updated: 2026-10-09
source: "T213 round-2 verification failure; focused evidence in target/runs/T213.verify.log and .scratch/tmp/T213/review-task-focused-repeat.transcript.txt"
phase: "Foundation verification remediation"
story: "-"
blocked_by: [T211]
parallel: false
files_budget: 4
files_scope:
  - tests/contract/workflow/review_task_test.sh
  - specs/001-tor-route/tickets/T214-deterministic-delayed-review-boundary.md
  - specs/001-tor-route/STATUS.md
  - specs/001-tor-route/evidence/T214-tests-first.json
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/spec.md §FR-016"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
decision_refs:
  - "T211 acceptance: retain delayed s13 normal/mutant controls and prove bounded cleanup"
  - "T213 verification RED: target/runs/T213.verify.log, review_task_test.sh"
remediates: T211
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T214: Make delayed review-boundary controls deterministic

## Context

The T213 round-2 candidate reproducibly fails the T142 review-boundary contract at the delayed early-unlock mutant: the timeout branch reports a successful child exit and a delayed `committing` marker appears. That branch returns before it invokes a competing reviewer, so it does not demonstrate reviewer state changes. T211 already repaired fixture ownership and cleanup; this follow-up repairs only the remaining race in its delayed s13 timeout and boundary controls, preserving the T142 lock-lifetime property and all positive and mutant controls.

## Analysis

- **Must hold:** at a readiness timeout the fixture terminates the still-owned driver before the shim can return a commit error into `run-task.sh`'s successful COMMIT-handoff path. The recorded driver exit is nonzero; `HEAD` stays unchanged; the review lock and every owned process are gone; no delayed `committing` marker appears. A separate delayed-normal driver reaches the true commit boundary, is refused by a competing review launcher while it owns the lock, then commits successfully after release. The early-unlock mutant remains admitted at that same boundary.
- **Gated:** the ordinary `scripts/run-task.sh T214` pre-review gate runs `scripts/verify.sh`; its s13 fixture asserts timeout termination/exit, lock refusal/admission, commit result, markers, `HEAD`, and owned-process cleanup. The contract harness also proves assertion or cleanup failure cannot emit a PASS marker.
- **Residue:** elapsed-time assertions alone cannot order a shim's delayed marker against abort/release and signal delivery. The regression must establish ordering with explicit fixture handshakes and independently observe process/residue state.
- **Constitution Check:** VII requires an atomic meaningful RED/GREEN regression; VIII requires exact-candidate adversarial controls. No privacy guarantee or review policy changes.

## Acceptance

1. Treat this as an atomic regression-and-fix ticket (`tests_first: []`). Stage the new invariant assertions, event capture, and PASS-output falsifier, then run `scripts/test-first-evidence.py red T214 -- bash tests/contract/workflow/review_task_test.sh` against the true T214 START. Use the same bounded, test-coordinated schedule and unchanged assertions for RED and GREEN: hold the delayed marker until cleanup begins; the legacy shim publishes `committing` only after cleanup has written abort/release and delivered TERM, which deterministically exposes the late-marker assertion. RED must fail that named invariant with normal tools available, not because a new event was missing. Stage the completed repaired fixture before GREEN; run the identical probe through `green` and stage `specs/001-tor-route/evidence/T214-tests-first.json`. Retain a separate always-legacy mutant as a load-bearing falsifier after repair. Preserve T211's historical evidence.
2. Repair only fixture coordination in `tests/contract/workflow/review_task_test.sh`; leave the existing owned-process supervisor implementation unchanged. In the timeout shim path, abort must keep the driver blocked without publishing a marker until the existing supervisor sends TERM to the direct Bash driver; on the supervisor's subsequent descendant TERM, the shim must exit without returning a failed `git commit` to `run-task.sh`'s successful COMMIT-handoff path. This unblocks Bash so its existing EXIT trap removes the normal driver's review lock during TERM cleanup, before any KILL fallback. Keep cleanup's abort → release → signal order and configured readiness/cleanup bounds; do not increase sleeps or weaken assertions. Run the exact timeout case with `launch_fixture_driver`'s existing `use_timeout=no` option so its owned child is `bash scripts/run-task.sh T900`, not the GNU `timeout` wrapper; the same unchanged supervisor still owns and bounds that child. Capture the child's PID/start identity and direct exit, and independently prove its termination. For the normal driver, require its review lock present before cleanup and removed during TERM cleanup before KILL; for the early-unlock mutant, require its lock already absent before cleanup and still absent afterward. For both, require nonzero driver exit, unchanged pre-cleanup `HEAD`, no SIGKILL in the supervisor receipt, no owned process/session residue, and no delayed marker after every owned child is reaped. A nonzero shim exit alone is insufficient because run-task handles commit failure through a successful COMMIT handoff.
3. Retain a successful delayed-normal boundary control: hold the driver at the actual commit command until the fixture explicitly releases it; while held, the normal launcher must fail specifically because the driver's lock exists, then release must complete the normal commit and preserve both expected review trailers. At the same controlled boundary the early-unlock mutant must be admitted. Assert mutant behavior and cleanup without allowing its commit to obscure the control.
4. Keep controls isolated, fake-CLI-only, bounded, and free of provider calls. Emit no case or suite PASS marker if any assertion, child-exit check, or cleanup check failed. Include the PASS-output regression assertion in the pre-fix RED phase: inject an assertion/cleanup failure and prove nonzero test exit with no PASS marker for that failed case or suite. Apply the same assertion to repaired and always-legacy-mutant schedules. Record event order and actual bash driver PID/start/exit separately from the supervisor's completion result; preserve unrelated process/resource state.
5. Use the ordinary `scripts/run-task.sh T214` pre-review transition so its canonical verify gate runs on the exact candidate; do not substitute a direct `scripts/verify.sh` invocation for that workflow gate. Obtain fresh matching native GLM/Astra review. The diff stays within the four declared paths and budget. No T142 production launcher/driver changes, T213 package-promotion paths, ticket reset/history rewrite, readiness-window increase, or assertion removal.

## Out-of-scope

No production review or run-task behavior changes, no changes to the owned-process supervisor implementation or unrelated s14/discovery fixtures, no changes to Tor packaging/T213 acceptance, and no loosening of the s13 lock, timeout, exit, marker, HEAD, or process-residue assertions. Do not amend T211 or rewrite its historical evidence.

## Notes

The separate ticket is a focused remediation because T211 is done and workflow says completed tickets retain their history; T213's package promotion does not own the review harness. T213 must remain unable to advance while this required verify gate is red.

---
