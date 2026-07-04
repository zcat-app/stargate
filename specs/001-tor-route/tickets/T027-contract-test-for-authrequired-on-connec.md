---
id: T027
title: 'Contract test for `AUTH_REQUIRED` on CONNECT path in `tests/contract/e'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T027
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

# T027: Contract test for `AUTH_REQUIRED` on CONNECT path in `tests/contract/e

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for `AUTH_REQUIRED` on CONNECT path in `tests/contract/error-template/auth_required_test.go` — per `contracts/error-template.md` §"Contract tests" row 1 and `contracts/socks5-auth.md` §"HTTP CONNECT path · Invariants". Cases: (a) missing `Proxy-Authorization` → 407 + template; (b) malformed token → 407 + template with **no distinguishing substring** from the missing-header case (i.e. byte-for-byte identical *except for the `LOCAL_REFERENCE_ID` substitution slot*, which is freshly generated per response per error-template.md §"Response body" and is asserted distinct by T069). The test either mocks `crypto/rand` so both responses get a deterministic `LOCAL_REFERENCE_ID` and asserts literal byte equality, or compares the two responses structurally with the 16 hex-byte ref-ID slot excluded — whichever T048's render path more cleanly accommodates; (c) leak-corpus scan over response bytes for each of (a) and (b).

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
