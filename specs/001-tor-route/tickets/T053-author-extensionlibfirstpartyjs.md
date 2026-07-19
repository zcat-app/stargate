---
id: T053
title: 'Author `extension/lib/firstparty.js`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T053
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

# T053: Author `extension/lib/firstparty.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/lib/firstparty.js` — first-party-domain computation per arch §14.3 (prefer `requestDetails.documentUrl`/`originUrl` eTLD+1), **extended for this feature with `.onion`-specific rules** that arch §14.3 does not carry: for top-level `.onion` navigation, return the onion address itself; for subresources under a `.onion` document, return the parent page's onion address. **Verified by T034d.**

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
