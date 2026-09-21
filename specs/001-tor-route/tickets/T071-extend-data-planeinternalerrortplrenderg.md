---
id: T071
title: "Extend future HTTP error renderer only"
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T071
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T065", "T066", "T067", "T068", "T069", "T156"]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
tests_first: ["T065", "T066", "T067", "T068", "T069"]
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T071: Extend future HTTP error renderer only

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Extend `data-plane/internal/errortpl/render.go` (from T048) to cover `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT` per the status/reason table in `contracts/error-template.md` §"Status line"; verify the `LOCAL_REFERENCE_ID` generation is shared across all codes. Verified by T065–T069.

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

## T172 selected acceptance (supersedes conflicting historical task text)

Limit `render.go` extension to direct future-format renderer calls for all four codes; preserve status/reason, four-header order, body, reference-ID and leak-corpus tests. Do not wire HTML responses to Tor port 8881 or claim they are an implementation of FR-009.
