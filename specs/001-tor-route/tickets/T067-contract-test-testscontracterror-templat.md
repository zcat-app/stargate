---
id: T067
title: "Test SOCKS5 ROUTE_TIMEOUT failure reply"
status: pending
created: 2026-07-04
last_updated: "2026-10-05"
source: tasks.md#T067
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

# T067: Test SOCKS5 ROUTE_TIMEOUT failure reply

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test `tests/contract/error-template/route_timeout_test.go` — substitute the synthetic slow SOCKS5 backend (`tests/integration/fake_socks5_tor.go` from T019a, configured in `slow` mode); CONNECT to a hung target; assert 504 + template + `ROUTE_TIMEOUT`.

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

Implement authenticated SOCKS5 `ROUTE_TIMEOUT` under `tests/contract/socks5/`: slow fake SOCKS backend exceeding the bounded dial/handshake deadline (250 s since T208; this ticket decides whether the test waits out the production value or runs the data plane with a shortened deadline, `contracts/socks5-auth.md` §Deadlines) yields exactly `05 06 00 01 00 00 00 00 00 00`, then EOF; no idle deadline is introduced after success.
