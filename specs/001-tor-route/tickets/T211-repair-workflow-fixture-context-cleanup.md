---
id: T211
title: "Repair workflow fixture context and owned child cleanup"
status: in-progress
created: 2026-10-06
last_updated: 2026-10-08
source: "T202 guest15 verification stop; reviewed repair plan final SHA256 cd5fc2e88e255bab31bfe34d34cc5e01f8200244d29d91810f588d0d190b637c; maintainer authorized prerequisite implementation"
phase: "Foundation verification remediation"
story: "-"
blocked_by: [T210]
parallel: false
files_budget: 7
files_scope:
  - tests/contract/workflow/verify_discovery_test.sh
  - tests/contract/workflow/review_task_test.sh
  - specs/001-tor-route/tickets/T211-repair-workflow-fixture-context-cleanup.md
  - specs/001-tor-route/STATUS.md
  - specs/001-tor-route/evidence/T211-tests-first.json
  - docs/process/reviewer-scorecard.md
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "V: Honest Threat Model"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/spec.md §FR-016"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
  - "docs/process/workflow.md §Evidence and atomic tests-first work (T156)"
decision_refs:
  - "Final repair plan §5 R2a; final-document hash above is distinct from the two v3 READY advisory reports"
  - 'Maintainer: "ok so if you have a plan you can be again orchestrator of the implementation"; defer/prerequisite route authorized'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T211: Repair workflow fixture context and owned child cleanup
## Context

The guest15 ordinary fixture failures identify independent environment and cleanup defects:
three implicit hermetic discovery calls inherit the outer Docker tag, and review-fixture
s13/s14 ownership paths can outlive their owner or stall on an unreleased Git shim.
Repair the test fixtures after T210, preserving FR-016 and Constitution VII/VIII's coverage
and independently reviewed candidate controls. T202 implementation remains preserved separately.

## Analysis

- **Must hold:** hermetic boundaries clear inherited named tags; failure/EXIT cleans only its
  own recorded process groups before removing its sandbox; successful assertion paths retain
  their ordering and readiness windows.
- **Gated:** discovery outer-tag matrix, broken sentinel/all-SKIP refusal and existing review
  lock, no-commit, mutant and gate-reusable controls.
- **Residue:** late readiness and owner interruption require real owned-process falsifiers,
  including descendant groups, identity reuse and independent zero-residue observation.
- **Constitution Check:** III/V protect unrelated state and truthful evidence; IV/VI retain
  tools/pins/history; VII requires atomic meaningful RED/GREEN; VIII keeps independent review.

## Acceptance

1. This is an atomic regression-and-fix ticket with `tests_first: []`, not a red-only dependency.
   Before implementation, stage the spec-derived fixture regressions/controls and record
   `scripts/test-first-evidence.py red T211 -- <exact bounded probe command>` against the
   true START baseline. Meaningful old REDs are the12s delayed-committing s14 shim hanging
   past its bound, and interruption of the fixture owner at the actual s13 commit boundary
   leaving owned children after owner exit/sandbox deletion. The >15s delayed s13 normal/mutant
   cases already exit bounded with no residue on unchanged source; retain them as controls,
   never claim historical RED from them. Rerun the identical command through `green` after the
   repair and explicitly stage `specs/001-tor-route/evidence/T211-tests-first.json`.

2. Clear STARGATE_TEST_TAGS at all three implicit hermetic go-workspace gate invocations
   in verify_discovery_test.sh, retain the explicit named leg, and assert no NAMED output from
   hermetic legs. Identical outer-unset and outer-docker matrices, broken sentinel and all-SKIP
   refusal pass with the same discovery/classification/coverage assertions. No weaker gate or skip.

3. Install ownership-aware cleanup before each s13 normal/mutant and s14 child launches.
   Use a newly owned isolated process group (e.g. setsid), record PID/PGID/start identity and
   retain GNU timeout inside that session so group signalling reaches its shim. Account for
   driver and every owned descendant group, not only a wrapper. Reject stale/reused identity;
   never signal self/parent or a broad host process-name match.

4. On readiness miss and failure/EXIT cleanup, write abort-commit then release-commit before
   TERM signalling. Bound TERM polling to5s, then KILL only verified owned groups and reap
   within another5s using a bounded ownership-aware supervisor; a plain wait after kill is not
   a bound. Reap all owned children, observe no failure commit/lock/residue, remove the sandbox
   last, and retain original and cleanup errors. Preserve foreign processes/resources.
   Normal s14 intentionally TERM-signals at its successful assertion boundary before abort/
   release; preserve that order. Keep readiness15s/10s, hold-lock, early-unlock mutant,
   SIGTERM/no-commit and gate-reusable positive/negative controls unchanged.

5. Run forced-late s14, interrupted-owner s13, delayed s13 normal/mutant, successful dialogue,
   ownership/reuse and foreign-process controls with exact command/output/exit/identity evidence.
   Use Linux owned-process enumeration, not global pgrep absence. Prefer cheap existing fixtures
   and recorded tests-first controls over slow recursive fixtures. No provider call, actual ticket
   commit, fake approval/sentinel in this filing or broad host signal is an acceptance shortcut.

6. Complete canonical ordinary `scripts/verify.sh` with actual pinned tools/authentic history
   as an ordinary user, no opt-outs, no concurrent ticket/runtime gate/live/build. Required gate
   coverage remains intact. Native GLM/Astra review binds the exact staged candidate after GREEN;
   no Fable advisory plan verdict substitutes for implementation review. Use only declared source,
   ticket/STATUS/tests-first/scorecard paths; a needed extra regression path must be named and
   reviewed before implementation and the full union stay <=7 or be split.

## Out-of-scope

Production/runtime routing, pins/security policy, Go helpers/package budgets, CI/history repairs,
T202 runner/restoration, live kernel/global fault probes and retained-asset deletion. Named fixture
changes are confined to inherited-tag isolation and owned child cleanup plus their actual regression
controls. No assertion, readiness deadline, required test, permission deny or SKIP rule is weakened.

## Implementation inventory

Six exact paths are declared in YAML, ceiling7. Existing fixture files and owned ignored raw
controls may express the regressions. The scorecard belongs only to the normal done follow-up
commit, outside the implementation review candidate and its negative-space check; the declared
inventory count is unchanged. Any further tracked source path requires an explicit
inventory refinement before implementation. R2b must re-ground on this delivered discovery fixture.
