---
id: T077
title: 'Run the `quickstart.md` walkthrough on a clean Linux x86_64 reference '
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T077
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T009", "T155", "T071", "T072", "T073", "T126", "T156"]
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

# T077: Run the `quickstart.md` walkthrough on a clean Linux x86_64 reference 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Run the `quickstart.md` walkthrough on a clean Linux x86_64 reference workstation with a fresh Mullvad Browser profile and a fresh git clone; measure SC-001 wall-clock time; record result in `tests/integration/quickstart_walkthrough.md` (a markdown artefact, not a Go test — the SC-001 measurement is intentionally hand-driven against a real browser, per plan.md §"Performance Goals").

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
