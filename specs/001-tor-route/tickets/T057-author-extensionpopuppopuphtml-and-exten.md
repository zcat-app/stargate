---
id: T057
title: 'Author `extension/popup/popup.html` and `extension/popup/popup.js`'
status: pending
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T057
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T034c]   # T034c added 2026-09-03 per T096/M6 (T034e precedent):
                            # the Principle-VII test gates this impl
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
tests_first: [T034c]   # the popup.test.js suite that self-skips until this ticket lands
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T057: Author `extension/popup/popup.html` and `extension/popup/popup.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/popup/popup.html` and `extension/popup/popup.js` — per-tab indicator reading the routing decision from `webRequest.onBeforeRequest` cache for the active tab; surfaces the literal string `Route: Tor` for `.onion` tabs and `Route: Direct (unrouted)` for everything else (these two strings are the canonical labels; drift between them and T034c's assertions fails CI). **Verified by T034c.**

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
