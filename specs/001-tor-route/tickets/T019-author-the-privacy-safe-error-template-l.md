---
id: T019
title: 'Author the privacy-safe error template **literal** in `data-plane/inte'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T019
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T019: Author the privacy-safe error template **literal** in `data-plane/inte

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author the privacy-safe error template **literal** in `data-plane/internal/errortpl/template.go` — the exact byte sequence from `contracts/error-template.md` §"Response body" stored as a single Go string constant; LF line endings; placeholder tokens `{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}` only. The renderer that substitutes the placeholders lives in T048 / T071.

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
