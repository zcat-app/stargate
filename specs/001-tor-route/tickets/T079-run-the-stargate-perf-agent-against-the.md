---
id: T079
title: 'Run the `stargate-perf` agent against the data plane (Principle VIII);'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T079
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T079: Run the `stargate-perf` agent against the data plane (Principle VIII);

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Run the `stargate-perf` agent against the data plane (Principle VIII); verifies SC-005 (≥200 concurrent CONNECTs against the synthetic SOCKS5 backend from T019a) and the zero-retained-allocation property on the forwarding hot path.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
