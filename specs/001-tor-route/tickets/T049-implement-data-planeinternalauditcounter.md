---
id: T049
title: 'Implement `data-plane/internal/audit/counters.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T049
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
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

# T049: Implement `data-plane/internal/audit/counters.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/audit/counters.go` — in-memory `(route, hour_bucket) → (request_count, byte_count)` aggregates counted per data-model.md §3 (auth-passed requests increment `request_count`; only bytes forwarded between client and upstream contribute to `byte_count`, not the synthesised error-template body). The DP-hosted `GetStatus` RPC (T007 / T045; contract at `contracts/control-grpc.md` §"GetStatus (minimum subset)") reads from this in-memory map; the **production CP-side caller** that would flush counters to SQLite is **deferred to the admin-UI feature** per data-model.md §3, so in v1 the counters are process-memory only and are lost on DP restart. T025c (auth-fail: must-not-increment), T025d (auth-pass + happy relay: must-increment with `byte_count` accumulating forwarded bytes), and T067b (auth-pass + route-failure: must-increment with `byte_count = 0`) together gate the FR-008 counter contract from all three angles, all probing via the DP-hosted `GetStatus` RPC (rationale in plan.md tension #10 / research.md §11).

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
