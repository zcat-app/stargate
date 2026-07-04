---
id: T034c
title: 'Unit test for `extension/popup/popup.js` per-tab indicator (Principle '
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T034c
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

# T034c: Unit test for `extension/popup/popup.js` per-tab indicator (Principle 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `extension/popup/popup.js` per-tab indicator (Principle VII for routing-decision *display* logic; the indicator is how US1 acceptance scenario 1's "extension's per-tab indicator shows route = Tor" is observable to the user — wrong-label drift would make the privacy property invisible). Same `vm.runInNewContext()` + handwritten `browser` mock pattern as T034b (no third-party JS deps). Cases:

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
