---
id: T056
title: 'Author `extension/options/options.html` and `extension/options/options'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T056
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T034e]   # T034e is the Principle-VII test-first gate (T096)
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
tests_first: [T034e]   # T096/M6: T034e MUST be done before this impl (Constitution VII)
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

# T056: Author `extension/options/options.html` and `extension/options/options

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/options/options.html` and `extension/options/options.js` — single bearer-token field with `^[0-9a-f]{32}$` client-side validation; visible warning about `storage.local` per research.md §6 and FR-019. The canonical user-facing warning string is pinned in data-model.md §5.1. **Verified by T034e** (three-way drift assertion: html ↔ data-model §5.1 ↔ quickstart Step 4); T034e MUST be authored and failing before this task lands.

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
