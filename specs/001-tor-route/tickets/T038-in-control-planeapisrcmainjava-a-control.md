---
id: T038
title: 'In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.jav'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T038
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T095]
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

# T038: In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.jav

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.java` hosts the `WatchEvents` gRPC server, binding `/run/stargate/control.sock` (mode 0660, owned `stargate-cp:stargate-ipc` per `contracts/control-grpc.md` §"Socket topology"); (b) `ReloadTokensClient.java` is the gRPC *client* stub that dials the data plane's `/run/stargate/dp.sock` — used by `StargateControlPlane` (T041) to push token generations. Both endpoints perform the mutual ed25519 handshake using keys from `stargate-keys`. The CP does NOT host `ReloadTokens` — that server lives in the data plane (T045) because `ReloadTokens` direction is CP→DP per `contracts/control-grpc.md` §"ReloadTokens". Verified by T022 (transport invariants on both sockets) and T021 (`WatchEvents` server-side behaviour); the `ReloadTokens` client-side push is gated against the DP server by T020.

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
