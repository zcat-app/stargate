---
id: T064
title: 'Author the curated leak corpus `tests/contract/error-template/leak-cor'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T064
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
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

# T064: Author the curated leak corpus `tests/contract/error-template/leak-cor

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author the curated leak corpus `tests/contract/error-template/leak-corpus.txt` (**SC-004** anchor — this corpus is the substring set every error-template response is scanned against by T065–T068, gating SC-004's "no leak-corpus match in any of the four error-code responses") per `contracts/error-template.md` §"Leak-corpus invariant" — the SC-001/002 reference target onion; the 100-domain synthetic corpus from T063; placeholder lines for the data plane's egress IP and a representative Tor exit IP filled in at test time; version-string fragments (`Tor`, `Quarkus`, `Hibernate`, `SQLite`, `Mandrel`); backtrace fragments (`panic:`, `goroutine`, `stack trace`, `at line`).

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
