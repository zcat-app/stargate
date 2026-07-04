---
id: T013
title: 'Implement `data-plane/internal/bind/check.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T013
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006, T012a]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
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

# T013: Implement `data-plane/internal/bind/check.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/bind/check.go` — the loopback-only bind-safety check (FR-010) that runs before any listener opens; returns `BIND_REFUSED` and exits non-zero on violation. Pure unit-tested function (no listener side effects). Test gate: T012a MUST be authored and failing before this task lands.

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
