---
id: T034b
title: 'Unit test for `extension/background/hardening.js` (Principle VII; FR-0'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T034b
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T091]
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

# T034b: Unit test for `extension/background/hardening.js` (Principle VII; FR-0

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `extension/background/hardening.js` (Principle VII; FR-004) — pure-logic test using Node.js built-in `node:test` runner (no third-party deps; aligned with extension's no-build-step constraint per plan.md §"Technical Context" and research.md §10) against a thin handwritten mock of the `browser.privacy.network.*`, `browser.proxy.settings`, and `browser.notifications` APIs. Because MV2 background scripts are loaded by the browser as global scripts (not ES modules), the test loads `hardening.js` via Node's `vm.runInNewContext()` with a synthesized `browser` global — no source-code contortion (UMD wrapper, conditional `module.exports`, etc.) is added to the extension to make it testable. Cases:

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
