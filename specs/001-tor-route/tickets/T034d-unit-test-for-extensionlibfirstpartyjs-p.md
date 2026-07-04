---
id: T034d
title: 'Unit test for `extension/lib/firstparty.js` (Principle VII'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T034d
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: false
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

# T034d: Unit test for `extension/lib/firstparty.js` (Principle VII

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `extension/lib/firstparty.js` (Principle VII — FR-002 stream isolation is driven by the *first-party-domain string* this module computes; an incorrect computation collapses two distinct origins onto one Tor circuit and breaks the privacy property the entire feature exists to deliver). Pure-logic test; no browser mock needed for the function itself (the module takes a `requestDetails`-shaped object and returns a string), so the test imports it via `vm.runInNewContext()` per the T034b pattern with an empty `browser` global. Cases (each a separate `it()`):

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
