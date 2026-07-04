---
id: T019a
title: 'Author `tests/integration/fake_socks5_tor.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T019a
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T019a: Author `tests/integration/fake_socks5_tor.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/integration/fake_socks5_tor.go` — synthetic SOCKS5 backend that mimics the Tor sidecar's accept-and-relay surface (research.md §7). Configurable modes: `accept-and-relay` (default — used by SC-005 load runs via T079), `slow` (used by T067 to trigger `ROUTE_TIMEOUT`), `hung` (reserved for negative leak-corpus tests). Pure Go, no docker-compose dependency. Apache 2.0 header.

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
