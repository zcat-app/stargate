---
id: T070
title: "Test integrated SOCKS5 Tor failure response"
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T070
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

# T070: Test integrated SOCKS5 Tor failure response

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Integration test `tests/integration/error_template_test.go` — end-to-end version of T065: bring up the stack, stop the Tor sidecar mid-session, request a `.onion` URL through the data plane, capture the full response, run the leak-corpus scan.

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

Run the actual Local stack with Tor stopped and send an authenticated SOCKS5 CONNECT to a controlled onion destination. Assert exact 10-byte `ROUTE_DOWN` reply, EOF, no leak-corpus/log hit and no Direct fallback; use a live Tor/SOCKS positive control. No HTTP template is expected.
