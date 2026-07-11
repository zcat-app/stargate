---
id: T073
title: 'In `data-plane/internal/controlclient/client.go` (from T045), wire the'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T073
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: [T009, T090]
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

# T073: In `data-plane/internal/controlclient/client.go` (from T045), wire the

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> In `data-plane/internal/controlclient/client.go` (from T045), wire the `SidecarEvent` consumer to set `routeEnableMask[TOR]=false` on `UNHEALTHY`/`STOPPED`/`CRASHED` per data-model.md §2 state machine; the forwarding path checks the mask before dialing and returns `ROUTE_DOWN` (via T071) when disabled.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
