---
id: T006
title: 'Author `licenses/APACHE-2.0-HEADER.txt` and a `scripts/check-license-h'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T006
phase: "1: Setup (Shared Infrastructure)"
story: '-'
blocked_by: []   # TODO: derive from phase ordering + prose deps
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

# T006: Author `licenses/APACHE-2.0-HEADER.txt` and a `scripts/check-license-h

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `licenses/APACHE-2.0-HEADER.txt` and a `scripts/check-license-headers.sh` invoked by CI to verify every new `.go`, `.java`, `.js`, `.proto`, `.sh`, `Dockerfile`, and `.sql` file under this feature's footprint carries the Apache 2.0 header (Principle VI / constitution Open and Auditable).

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
