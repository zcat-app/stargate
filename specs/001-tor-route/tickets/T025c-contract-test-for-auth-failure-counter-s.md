---
id: T025c
title: 'Contract test for auth-failure counter side-channel resistance (FR-006'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T025c
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

# T025c: Contract test for auth-failure counter side-channel resistance (FR-006

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for auth-failure counter side-channel resistance (FR-006, FR-008; data-model.md §3 — "auth failures leave `request_count` unchanged"; counting them would be a side channel for token-guessing attacks since an attacker can submit tokens at will). Establish a baseline `request_count` snapshot for `route='TOR'` via a direct gRPC probe to the data plane's status surface (arch §5.2 `GetStatus`, used here as a test-only probe; this is why the test lives next to the SOCKS5 leak tests rather than under `tests/contract/control-grpc/` — the property under test is at the SOCKS5/auth boundary, not the inter-plane RPC contract). Send N=100 SOCKS5 CONNECTs and N=100 HTTP CONNECTs with malformed bearer tokens to port 8881 — mix of: missing password, all-zero token, wrong-length token, correct-length token absent from current generation. Take a second snapshot. Assert (a) `request_count` delta is exactly zero; (b) `byte_count` delta is exactly zero (the synthesised AUTH_REQUIRED template body is excluded by data-model.md §3); (c) the gRPC probe itself does not increment any counter — verified by a no-traffic sandwich: snapshot, sleep ≥1s, snapshot again, assert no change. File: `tests/contract/socks5/auth_failure_counter_test.go`. Pairs with T049's implementation; T025 gates the log/journal side channel and T025c gates the counter side channel — both must hold or the auth-failure path leaks.

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
