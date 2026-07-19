---
id: T025d
title: 'Contract test for **positive** counter increments on the auth-passed f'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T025d
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T049]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T025d: Contract test for **positive** counter increments on the auth-passed f

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for **positive** counter increments on the auth-passed forwarding path (FR-008 first half; data-model.md §3 — "`request_count` incremented by 1 on each SOCKS5 or HTTP CONNECT through port 8881 that passes authentication" and "`byte_count` incremented by the total bytes forwarded between client and upstream in both directions at request close"). Uses the same in-feature DP-hosted `GetStatus` RPC from T007 / T045 that T025c uses, on the same `/run/stargate/dp.sock`. Establish a baseline `(route='TOR', hour_bucket)` snapshot. Open N=50 authenticated SOCKS5 CONNECTs and N=50 authenticated HTTP CONNECTs to port 8881 against the `accept-and-relay` mode of `fake_socks5_tor.go` (T019a); for each connection, forward a known payload of exactly `B` bytes in each direction (`2B` bytes round-trip per connection) and then close cleanly. Take a second snapshot. Assert (a) `request_count` delta equals exactly 100; (b) `byte_count` delta equals exactly `100 × 2B` — the synthesised error-template body is excluded by data-model.md §3, but this test never triggers an error so the exclusion is degenerate (asserted for completeness via a side-channel that captures any DP-emitted template bytes and confirms the captured byte count is zero); (c) the `hour_bucket` key matches the wall-clock hour at the time of the run, with an allowance to sum two adjacent rows if the run crosses an hour boundary; (d) the T025a shared log allowlist applies — counter writes emit no per-request log line. File: `tests/contract/socks5/auth_passed_counter_test.go`. Pairs with T049's implementation; together with T025c (must-not-increment on auth-fail) and T067b (must-increment on auth-pass + route-failure), this task gates the FR-008 counter contract from all three angles — see T067b for the complete three-test mapping. Rationale for the v1-proto `GetStatus` declaration that makes this test possible is in plan.md §"Plan-level tensions surfaced for review" #10 / research.md §11.

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
