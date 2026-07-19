---
id: T004
title: 'Author `data-plane/Makefile` (or equivalent) wiring the byte-reproduci'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T004
phase: "1: Setup (Shared Infrastructure)"
story: '-'
blocked_by: []   # TODO: derive from phase ordering + prose deps
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

# T004: Author `data-plane/Makefile` (or equivalent) wiring the byte-reproduci

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `data-plane/Makefile` (or equivalent) wiring the byte-reproducible build flags `-trimpath -buildvcs=false -ldflags="-buildid="` and `CGO_ENABLED=0`, per arch §12.1.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
