---
id: T026
title: 'Contract test for HTTP CONNECT auth success'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T026
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

# T026: Contract test for HTTP CONNECT auth success

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for HTTP CONNECT auth success — `CONNECT host:443 HTTP/1.1` + `Proxy-Authorization: Bearer <valid>` returns `HTTP/1.1 200 Connection Established\r\n\r\n` then bridges to upstream — in `tests/contract/socks5/connect_auth_success_test.go`. (Lives under `socks5/` per the directory convention: that path holds all port-8881 inbound-surface tests, including CONNECT-framed traffic that does **not** emit the privacy-safe error template. `tests/contract/error-template/` is scoped to template-emitting responses only; see `contracts/socks5-auth.md` §"Two inbound protocols, one port".)

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
