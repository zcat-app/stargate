---
id: T025
title: 'Contract test for SOCKS5 leak invariants in `tests/contract/socks5/lea'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T025
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

# T025: Contract test for SOCKS5 leak invariants in `tests/contract/socks5/lea

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 leak invariants in `tests/contract/socks5/leak_test.go` — per `contracts/socks5-auth.md` §"Invariants enforced by the contract test". Covers: (a) no token bytes in any response capture; (b) constant-time comparison latency distribution — two distinct invalid passwords of the same length yield close-to-equal latency distributions (best-effort, per contract); (c) **slot-invariance under the v1 N≤4 cost model** (data-model.md §1.5: "authentication against N stored tokens requires N argon2id operations to keep the comparison constant-time; short-circuiting on the first match would leak which slot matched") — load a generation of N=4 distinct token hashes, then drive authentication latency measurements with the matching token placed at slot index 0, 1, 2, 3 respectively, plus the all-fail case, and assert the five latency distributions are statistically indistinguishable at the test's significance threshold (an implementation that early-exits on the first hash match would produce monotonically increasing latency by slot index and fail this assertion); (d) no per-request journal entry on auth failure; (e) rejection of same-host NO_AUTH-only clients.

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
