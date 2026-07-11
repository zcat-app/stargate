---
id: T034e
title: 'Unit test for the canonical `storage.local` warning text (Principle VI'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T034e
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # T096/M6: removed inverted T056 dep — the test must NOT wait on its impl (Constitution VII)
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

# T034e: Unit test for the canonical `storage.local` warning text (Principle VI

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for the canonical `storage.local` warning text (Principle VII; FR-019). Same `vm.runInNewContext()` + handwritten `browser` mock pattern as T034b (no third-party JS deps). Asserts byte-for-byte presence of the data-model.md §5.1 canonical string in **all three** of: (a) `extension/options/options.html`'s rendered text; (b) `specs/001-tor-route/data-model.md` §5.1 (the source of truth); (c) `specs/001-tor-route/quickstart.md` Step 4 (the operator-facing quote). The test extracts (b) and (c) via blockquote-fence matching and fails if any of the three drift. data-model.md §5.1 is the single source of truth; the test gates drift in either of the two replicas. Mock + test live at `extension/options/options.test.js`; picked up automatically by the T034b discovery script. Pairs with T056 (impl) — T034e MUST be authored and failing before T056 lands; never bundle the failing-test signal with its implementation in a single commit (tasks.md §"Notes").

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
