---
id: T022
title: 'Contract test for inter-plane transport invariants in `tests/contract/'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T022
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T022: Contract test for inter-plane transport invariants in `tests/contract/

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for inter-plane transport invariants in `tests/contract/control-grpc/transport_test.go` — both UDS paths exist (`/run/stargate/control.sock` hosted by the CP, `/run/stargate/dp.sock` hosted by the DP); each socket is mode 0660 with the hosting plane's user as owner and `stargate-ipc` (GID 5100) as group per `contracts/control-grpc.md` §"Socket topology"; the **peer plane (in the `stargate-ipc` group) can `connect(2)`** its dial-direction socket — DP-uid succeeds dialling `control.sock`, CP-uid succeeds dialling `dp.sock` (regression gate against accidental revert to 0600 which would silently break inter-plane comms); a **same-host process outside `stargate-ipc` cannot dial either socket** (assert `EACCES`); neither plane dials TCP; each plane refuses to dial the *other* socket path with role swapped (no role swap of the *server*); mutual ed25519 auth on each socket; schema-version handshake on either socket rejects `stargate.v2` peers; plane-down survival (DP keeps serving port 8881 across a CP restart, CP re-dials `dp.sock` and re-pushes the current generation on reconnect); **production-caller-absent regression-grep** (per `contracts/control-grpc.md` §"Transport invariants" row 10 — greps the control-plane production source tree for `GetStatus(` with test-only paths excluded via globs `**/test/**` and `**/*Test.java`, asserts zero matches; gates the admin-UI feature against silently wiring a production caller before research.md §11's deferral is revisited). Per `contracts/control-grpc.md` §"Transport invariants".

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
