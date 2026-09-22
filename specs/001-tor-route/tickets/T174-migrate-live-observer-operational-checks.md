---
id: "T174"
title: "Migrate live observer checks to silent operational boundaries"
status: "pending"
created: "2026-09-22"
last_updated: "2026-09-22"
source: "T152 round-2 GLM review of b0c86f2196a6e58fa02753c2ded961d06b2573245f981e8f73797beed78b9111"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T152"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md Principles II/III/V/VII", "specs/001-tor-route/contracts/foundation-boundaries.md", "specs/001-tor-route/data-model.md §4", "THREAT-MODEL.md §5.18"]
decision_refs: []
remediates: "T152"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T174: Migrate live observer checks to silent operational boundaries

## Context

T152's two round-2 reviewers approved its runtime/storage repair. GLM separately identified
stale live-cadence consumers outside that candidate: `tests/live-e2e/local-topology/observer.py`
still expects Tor's Docker HEALTHCHECK and `State.Health.Status`, and derives CP event coverage
from the DP's now-forbidden receipt journal. `test_observer.py` mirrors those expectations.
These assertions must be migrated before T155 can use fresh integrated evidence. Historical
T165 evidence remains historical; it does not validate the post-T152 operational boundary.

## Analysis

- Must hold: no Docker health history or raw operational journal is restored. Current Tor
  readiness remains authenticated and bounded; CP-down DP authentication/forwarding still works.
- Gated: T152's hermetic/real-container installer readiness tests, real Go process silence
  probes, aggregate/migration tests, and the complete `scripts/verify.sh` gate.
- Residue: the live observer harness's health and event-history consumers are incompatible
  with the current deployment. Skipped live checks cannot establish the migrated observation path.

## Acceptance

1. Reproduce the stale live observer assertions against post-T152 behavior before changing them;
   add a named regression that fails for absent Docker health metadata and an empty DP journal
   while the appropriate authenticated current observation is available.
2. Replace Docker-health assertions with bounded authenticated current readiness using the
   existing observer boundary. Preserve the actual CP-down authentication and routed-byte checks;
   a running container or open DP TCP port alone cannot stand in for Tor readiness.
3. Preserve the live CP event/failure matrix, no-duplicate/no-false-event assertions, socket
   recreation and observer stop/start coverage through an authorized ephemeral observation path.
   Do not re-enable production diagnostic receipts or persist raw lifecycle/detail streams to
   make the old harness pass. Retain positive and negative controls and summarize outcomes.
4. Update `test_observer.py` and affected live-run documentation alongside the harness. Run
   `scripts/verify.sh`, focused observer regressions and the documented live Local checks. State
   missing live prerequisites explicitly; no SKIP-to-PASS substitution or reuse of pre-T152
   evidence as proof of the changed observation mechanism.
5. Keep T155 blocked until this repair and its independent review are complete. Record the
   tested source/image identities and invalidate affected evidence after further changes.

## Out-of-scope

Constitution changes, reopening T152's completed implementation, changing auth/routing authority,
restoring Docker health history or per-event logs, and claiming live anonymity from fixture tests.

Existing health/journal expectations in `tests/live-e2e/local-topology/observer.py` and
`test_observer.py` are explicitly superseded by T152. Their underlying authentication, current
readiness, event correctness and CP-down routing coverage must be retained.

## Notes

This is the executable follow-up requested by T152's review, not a finding override or a new
permission to retain operational history. The tests-first regression is authored within this
combined test-repair ticket; `tests_first` therefore names no separate always-red test ticket.
Ground the observation mechanism and file inventory before implementation; refine the scope if
the default budget cannot contain the repair.
