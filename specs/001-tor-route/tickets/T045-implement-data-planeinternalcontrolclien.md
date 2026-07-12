---
id: T045
title: 'Implement `data-plane/internal/controlclient/`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T045
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T090, T092, T093, T095]
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

# T045: Implement `data-plane/internal/controlclient/`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/controlclient/` — (a) `client.go`: gRPC client that dials `/run/stargate/control.sock`, consumes the server-streamed `WatchEvents` from the control plane, and applies events as **advisory status/audit hints** (data-model.md §2; Principle II — events MUST NOT gate admission; see T073 for the advisory consumption mapping); (b) `server.go`: gRPC server hosting `/run/stargate/dp.sock` (mode 0660, owned `stargate-dp:stargate-ipc` per `contracts/control-grpc.md` §"Socket topology") exposing **two** handlers — (i) `ReloadTokens` (atomic-swaps the `tokenStore` pointer and rejects stale generations with `APPLY_STATUS_STALE_GENERATION`); (ii) `GetStatus` (returns the current in-memory counter snapshot from `data-plane/internal/audit/counters.go` — the minimum-subset RPC declared in T007's proto, called by T025c, T025d, and T067b in v1; the CP does not call it in this feature). Mutual ed25519 handshake on both sockets using keys from `stargate-keys`. The package name `controlclient` is carried over from when the DP was client-only; renaming is deferred until a second gRPC service forces the issue. Verified by T020, T021, T022.

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
