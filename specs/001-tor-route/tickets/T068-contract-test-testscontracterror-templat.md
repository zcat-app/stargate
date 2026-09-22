---
id: T068
title: 'Contract test `tests/contract/error-template/body_byte_match_test.go` '
status: deferred
created: 2026-07-04
last_updated: "2026-09-21"
source: tasks.md#T068
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
deferred_on: T071
deferred_reason: decomposed
replaced_by: T071
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T068: Contract test `tests/contract/error-template/body_byte_match_test.go` 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test `tests/contract/error-template/body_byte_match_test.go` — for one failure of each of the four codes, assert the body matches the template byte-for-byte after substituting the three permitted fields; no other bytes present.

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

Test all four future HTTP renderer code bodies directly, byte-for-byte after only the permitted substitutions. Make no port-8881 ingress or browser-visible HTML claim; T173 moves existing ingress fixtures to renderer-only calls.

## T173 authorized refinement — superseded by T071

This unimplemented test-only unit is consolidated into T071's atomic tests-first renderer
change. Its complete assertions remain required there; it is not a done dependency and
must not be delivered through permanent skips or a standalone red commit. T071 replaces
this ticket in downstream blockers. Historical task text above records the original scope.
