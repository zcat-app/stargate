---
id: T063
title: 'Author `tests/integration/synthetic_onion_corpus.txt`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T063
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
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

# T063: Author `tests/integration/synthetic_onion_corpus.txt`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/integration/synthetic_onion_corpus.txt` — 100 distinct onion-style address *strings* (well-formed but not necessarily reachable; the property under test is circuit selection, not reachability, per research.md §7 / spec Assumptions).

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
