---
id: T021
title: 'Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for '
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T021
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

# T021: Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for `tor`, fixed-vocabulary `detail` `container_start` then `healthcheck_pass`) in `tests/contract/control-grpc/watch_events_test.go` — per `contracts/control-grpc.md` §"WatchEvents · Tests" rows 1–3. Scope is intentionally just the happy-path pairings; the failure-transition pairings (`UNHEALTHY`/`STOPPED`/`CRASHED`/`RESTARTED`) are covered by T070b in Phase 5 alongside T074's implementation — keeping test/impl ordering aligned within each user story.

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
