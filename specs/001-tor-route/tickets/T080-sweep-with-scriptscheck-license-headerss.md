---
id: T080
title: 'Sweep with `scripts/check-license-headers.sh` (from T006); verify Apac'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T080
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T080: Sweep with `scripts/check-license-headers.sh` (from T006); verify Apac

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Sweep with `scripts/check-license-headers.sh` (from T006); verify Apache 2.0 headers on every new file; update CLAUDE.md "Current plan" pointer if downstream specs land before this feature merges.

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
