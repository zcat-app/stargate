---
id: T079a
title: 'PR-cadence regression gate for SC-005''s pool-fill + steady-state prope'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T079a
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T009, T019a]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T079a: PR-cadence regression gate for SC-005's pool-fill + steady-state prope

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> PR-cadence regression gate for SC-005's pool-fill + steady-state property in `tests/integration/concurrent_connects_test.go`. Uses `fake_socks5_tor.go` (T019a) in `accept-and-relay` mode as the upstream — same backend T079 uses, so the two tasks measure consistent surfaces. The test (a) brings up the data plane with a one-token in-memory generation; (b) opens 200 concurrent authenticated CONNECTs through port 8881 (mix of SOCKS5 and HTTP CONNECT inbound framing to exercise both surfaces); (c) asserts the pool reaches 200 established connections within 30 s wall-clock (the fill-time floor from plan.md §"Performance Goals" measurement model, with the upper bound chosen to absorb argon2id-auth latency at N=1 and reasonable CI hardware variance); (d) holds all 200 connections open for ≥60 s while exchanging interleaved frames in both directions; (e) asserts none of the 200 connections dropped, were starved, or hit a deadline during that hold window; (f) asserts the T025a shared log allowlist applies — no per-connection log line is emitted during fill or hold. Scope boundary: this task **does NOT** verify the zero-retained-allocation property (that requires heap profiling and stays with the milestone `stargate-perf` agent run, T079) — it is a PR-cadence regression line against bottlenecks, deadlocks, or accidental serialization in the listener/auth/forward path, complementing rather than replacing T079. CI runs this test on every PR touching `data-plane/` (gated alongside the six contract-test directories per T076's glob, by adding `tests/integration/` to the same workflow path filter). Depends on T019a (synthetic backend), T044 (auth), T047 (forward), T049 (counters), T050 (main).

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
