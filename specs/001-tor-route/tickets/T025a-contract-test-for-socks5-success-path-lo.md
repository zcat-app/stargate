---
id: T025a
title: 'Contract test for SOCKS5 success-path log invariants'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T025a
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

# T025a: Contract test for SOCKS5 success-path log invariants

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 success-path log invariants — drive 100 sequential authenticated CONNECTs through port 8881 to an in-process upstream (the `accept-and-relay` mode of `fake_socks5_tor.go` from T019a); capture the data plane's stderr / journal output for the duration of the run; assert (a) no destination hostname, full URL, request or response header value, or body byte appears anywhere in the captured log; (b) no per-request timestamp at finer resolution than the ≥1-hour aggregate-counter bucket (FR-008, arch §6.4); (c) the only emitted lines belong to a fixed allowlist: startup, shutdown, `SidecarEvent` consumption, `ReloadTokens` apply, snapshot-write events. Expose the allowlist used by assertion (c) as a small shared Go helper (e.g. `tests/internal/loginvariants/`) so T025b and T070a reference the same canonical set rather than duplicate it — `tests/contract/socks5/no_per_request_logs_test.go`.

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
