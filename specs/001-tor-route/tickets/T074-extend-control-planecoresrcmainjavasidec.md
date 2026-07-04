---
id: T074
title: 'Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (fro'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T074
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
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

# T074: Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (fro

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (from T039) to emit `UNHEALTHY`, `STOPPED`, `CRASHED`, `RESTARTED` `SidecarEvent`s for the Tor sidecar; `detail` is drawn from the fixed vocabulary per `contracts/control-grpc.md` §"WatchEvents · Contract", with the v1 pairings `UNHEALTHY → healthcheck_fail`, `STOPPED → container_exit`, `CRASHED → container_exit`, `RESTARTED → container_start` (the same token used for STARTED; the contract rationale records why `detail` reuse across STARTED/RESTARTED is correct). On every transition to `UNHEALTHY`/`STOPPED`/`CRASHED`, write a `sidecar_unhealthy` row to `audit_log` via `AuditLogService` (T036) with `detail_json.kind` set to the matching state (data-model.md §4). `RESTARTED` is event-only and does **not** write an audit-log row — §4's `sidecar_unhealthy` vocabulary excludes it, and the next transition into HEALTHY emits the `sidecar_healthy` row via T039. Verified by T070b (failure-transition contract test in Phase 5) and T070 (integration test).

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
