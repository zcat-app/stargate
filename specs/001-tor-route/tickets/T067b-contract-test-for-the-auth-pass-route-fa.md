---
id: T067b
title: 'Contract test for the auth-pass + route-failure counter-increment asym'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T067b
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
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

# T067b: Contract test for the auth-pass + route-failure counter-increment asym

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for the auth-pass + route-failure counter-increment asymmetry (FR-008 second half; data-model.md §3 — "Route failures (`ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`) DO increment `request_count` once authentication has passed"; the synthesised error-template body is NOT included in `byte_count`) in `tests/contract/socks5/route_failure_counter_test.go`. Uses the same DP-hosted `GetStatus` RPC from T007 / T045 that T025c and T025d use, on the same `/run/stargate/dp.sock`. Three sub-cases, each opening N=20 authenticated CONNECTs through port 8881 (mix of SOCKS5 and HTTP CONNECT inbound framing per sub-case so both protocol surfaces are exercised):

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
