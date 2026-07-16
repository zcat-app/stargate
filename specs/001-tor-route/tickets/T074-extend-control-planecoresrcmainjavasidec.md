---
id: T074
title: 'Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (fro'
status: pending
created: 2026-07-04
last_updated: 2026-07-16
source: tasks.md#T074
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: [T009, T094a, T039]
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
>
> **T094a amendment:** the observation channel inherited from T039 is now Tor's cookie-authenticated ControlPort (`tor:9051`), not a Docker Engine observer (the `docker-socket-proxy` that previously fed these transitions was removed). Under control-port observation, `UNHEALTHY` maps to a bootstrap/circuit stall (the `healthcheck_fail` pairing stands); `STOPPED`/`CRASHED` are detected via control-port-connection drop, and `RESTARTED` via reconnect. The v1 detail pairings (`container_exit`, `container_start`) MUST therefore be re-derived against the control-port signal at `/start` grounding. The `detail` vocabulary itself is owned by `contracts/control-grpc.md` §"WatchEvents · Contract" (unchanged by T094a); only the signal-to-detail derivation changes.

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
