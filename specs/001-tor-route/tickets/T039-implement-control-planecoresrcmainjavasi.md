---
id: T039
title: 'Implement `control-plane/core/src/main/java/.../SidecarMonitor.java`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T039
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T094]
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

# T039: Implement `control-plane/core/src/main/java/.../SidecarMonitor.java`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/core/src/main/java/.../SidecarMonitor.java` — for the Tor sidecar only, emit `STARTED` + `HEALTHY` `SidecarEvent`s (with fixed-vocabulary `detail` `container_start`, `healthcheck_pass`) over the gRPC stream when the docker-socket-proxy (T015) reports the corresponding events, **and** write a `sidecar_healthy` row to `audit_log` via `AuditLogService` (T036) on each transition into HEALTHY (`detail_json` shape per data-model.md §4). Observation channel: long-poll `GET http://docker-socket-proxy:2375/events?filters={"type":["container"]}` for the container event stream (the `type=container` filter has been stable since Engine API v1.22 and sharply reduces volume vs no filter); the SidecarMonitor then drops any event whose `Actor.Attributes.name` is not in a CP-internal allowlist (`{"tor"}` for this feature; later sidecar features add their names to the set). Keeping the container-name filter in CP code rather than the URL avoids Engine API filter-syntax versioning quirks and makes the test surface a plain Java set-membership check. On each surviving event and on a bounded interval, poll `GET /containers/{name}/json` to read `State.Health.Status` (`healthy` → `HEALTHY`; `unhealthy` is mapped in T074). SidecarMonitor MUST NOT issue any HTTP method other than `GET` to the proxy and MUST NOT call any path outside `/events` and `/containers/{name}/json` — both invariants are gated by T019c at the proxy boundary and by a per-test mock at the CP unit-test layer. UNHEALTHY/STOPPED/CRASHED/RESTARTED transitions are added in T074.

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
