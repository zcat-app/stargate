---
id: T036
title: 'Implement `control-plane/persistence/src/main/java/.../entity/AuditLog'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T036
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

# T036: Implement `control-plane/persistence/src/main/java/.../entity/AuditLog

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/persistence/src/main/java/.../entity/AuditLog.java` (Panache entity matching V001 schema) and `AuditLogService.java` exposing one `write(action, target, detailJson)` method that emits any of the five fixed-vocabulary actions enumerated in data-model.md §4: `enrolled`, `revoked`, `config_error`, `sidecar_healthy`, `sidecar_unhealthy`. `actor` is set to `tokens.yaml` for the three token actions and to `system` for the two sidecar transitions, per §4. The callers wired by this feature are T035 (`enrolled`, `revoked`, `config_error`), T039 (`sidecar_healthy`), and T074 (`sidecar_unhealthy`).

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
