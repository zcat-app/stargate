---
id: T039
title: 'Implement `control-plane/core/src/main/java/.../SidecarMonitor.java`'
status: pending
created: 2026-07-04
last_updated: 2026-07-16
source: tasks.md#T039
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T094a]
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
> Implement `control-plane/core/src/main/java/.../SidecarMonitor.java` — for the Tor sidecar only, emit `STARTED` + `HEALTHY` `SidecarEvent`s (with fixed-vocabulary `detail` `container_start`, `healthcheck_pass`) over the gRPC stream, **and** write a `sidecar_healthy` row to `audit_log` via `AuditLogService` (T036) on each transition into HEALTHY (`detail_json` shape per data-model.md §4).
>
> **Observation channel (T094a amendment):** the CP observes Tor via Tor's cookie-authenticated ControlPort at `tor:9051` over the compose-internal network, authenticating with the control cookie (`CookieAuthentication 1` + `CookieAuthFileGroupReadable 1`; `contracts/torrc.md` invariants #3–#4). This **replaces** the `docker-socket-proxy` Docker-Engine observer that T094a removed (the proxy's `CONTAINERS=1` ACL granted `GET /archive` over every container's filesystem, including Tor's entry-guard state — THREAT-MODEL §4.2). SidecarMonitor opens an authenticated control-port connection and polls Tor's bootstrap/health state on a bounded interval — the same surface the Tor Dockerfile's HEALTHCHECK probes (`GETINFO status/bootstrap-phase`, `PROGRESS=100` → `HEALTHY`). SidecarMonitor MUST connect only to `tor:9051` (never a host-published port — FR-012 forbids it), MUST authenticate with the cookie (no other control-port auth method), and MUST issue only the read-only `GETINFO`/`GETCONF` commands it needs. The narrow cookie-read volume + GID alignment that lands with this ticket MUST NOT over-grant read of Tor's entry-guard state beyond the cookie exchange (T094a §Analysis "Grounding decisions" constrains this). UNHEALTHY/STOPPED/CRASHED/RESTARTED transitions are added in T074.

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
