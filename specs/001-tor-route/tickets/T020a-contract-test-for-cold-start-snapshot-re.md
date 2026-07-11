---
id: T020a
title: 'Contract test for cold-start snapshot restore (Principle II survival; '
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T020a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T046, T090, T092, T093]
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

# T020a: Contract test for cold-start snapshot restore (Principle II survival; 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for cold-start snapshot restore (Principle II survival; FR-013 last-known-token-list invariant) in `tests/contract/control-grpc/cold_start_snapshot_test.go` — pre-populate `dp-snapshot.json` (data-model.md §1.4 shape) with a single known `{hash, salt}` for a known plaintext, boot the DP **with no CP reachable** (CP container stopped, or `/run/stargate/control.sock` absent), open an authenticated SOCKS5 CONNECT to port 8881 with the matching plaintext as the password against `fake_socks5_tor.go` (T019a, `accept-and-relay` mode); assert (a) the DP authenticates the request from the snapshot-restored generation; (b) the DP retries the `WatchEvents` dial with the exponential backoff schedule from `contracts/control-grpc.md` §"WatchEvents" but does NOT block port 8881 from serving during the wait; (c) once the CP comes up and pushes a new `ReloadTokens` generation, the DP atomic-swaps and the previous snapshot's plaintext is no longer honoured (proves the snapshot is a *cold-start cache*, not a persistent fallback layer beyond the current generation); (d) `routeEnableMask[TOR]` remains DISABLED throughout (no `HEALTHY` event has arrived), so the auth succeeds at the SOCKS5 layer but the request-phase forward path returns the SOCKS5 `ROUTE_DOWN` reply per `contracts/socks5-auth.md` §"SOCKS5 request-phase failures (post-auth)" — byte-exact `05 03 00 01 00 00 00 00 00 00`, then close — verifying the layered invariant that snapshot restore does NOT bypass the §2 state-machine. Pairs with T046 (write path), T050 (boot sequence) and T073 (mask transitions).

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
