---
id: T041
title: 'Implement `control-plane/runtime/src/main/java/.../StargateControlPlan'
status: pending
created: 2026-07-04
last_updated: 2026-07-12
source: tasks.md#T041
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T089, T092, T093, T035, T038, T039]
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

# T041: Implement `control-plane/runtime/src/main/java/.../StargateControlPlan

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/runtime/src/main/java/.../StargateControlPlane.java` (`@QuarkusMain`) — wires the startup sequence: render `torrc` (T037) → start `SidecarMonitor` (T039) → load `tokens.yaml` (T035) → push `ReloadTokens` (T038); on missing/empty token file, log warning and proceed with empty list per FR-018.

**Refined by T089 (spec-amend).** T089 amended FR-011 so the static
Tor-only slice bakes the safe `torrc` into the Tor image at build time
(T087) and the control plane does NOT render `torrc` at boot
(Constitution Principle II / sol-review B2). The **"render `torrc`
(T037)" step is removed from the startup sequence**; T037 is deferred
(`deferred_reason: spec-amend`, `deferred_on: T089`). The v1 startup
sequence is: start `SidecarMonitor` (T039) → load `tokens.yaml` (T035)
→ push `ReloadTokens` (T038); on missing/empty token file, log warning
and proceed with empty list per FR-018. The CP no longer writes to
`stargate-tor-config` in this slice.

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
