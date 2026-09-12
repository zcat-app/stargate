---
id: T067a
title: 'Contract test for SOCKS5 request-phase failure replies (FR-009 SOCKS5 '
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T067a
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

# T067a: Contract test for SOCKS5 request-phase failure replies (FR-009 SOCKS5 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 request-phase failure replies (FR-009 SOCKS5 path; `contracts/socks5-auth.md` §"SOCKS5 request-phase failures (post-auth)") in `tests/contract/socks5/request_phase_failures_test.go`. Three sub-cases, all over an authenticated SOCKS5 connection on port 8881:

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
