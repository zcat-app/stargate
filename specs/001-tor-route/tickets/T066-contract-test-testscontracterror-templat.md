---
id: T066
title: "Test SOCKS5 ROUTE_REFUSED failure reply"
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T066
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
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

# T066: Test SOCKS5 ROUTE_REFUSED failure reply

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test `tests/contract/error-template/route_refused_test.go` — Tor up, CONNECT targets a non-resolvable `.onion`; assert 502 + template + `ROUTE_REFUSED`; leak-corpus scan passes (in particular, no Tor SOCKS5 reason text in the body).

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

## T172 selected acceptance (supersedes conflicting historical task text)

Implement authenticated SOCKS5 `ROUTE_REFUSED` under `tests/contract/socks5/`: upstream refusal yields exactly `05 04 00 01 00 00 00 00 00 00`, then EOF, with no upstream reason or corpus hit. Use the real/fake upstream control needed to prove a dial occurred.
