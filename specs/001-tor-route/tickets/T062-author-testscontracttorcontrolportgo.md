---
id: T062
title: 'Author `tests/contract/tor/control_port.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T062
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T087]
parallel: false
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

# T062: Author `tests/contract/tor/control_port.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/contract/tor/control_port.go` — cookie-authenticated Tor control-port client (helper consumed by T058, T058a, and the integration tests T059–T061); reads the cookie from the `stargate-tor-state` volume mount.

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
