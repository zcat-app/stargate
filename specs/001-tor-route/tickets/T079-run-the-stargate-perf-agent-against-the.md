---
id: T079
title: 'Run the `stargate-perf` agent against the data plane (Principle VIII);'
status: pending
created: 2026-07-04
last_updated: "2026-09-21"
source: tasks.md#T079
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T009", "T155", "T034a", "T034f", "T064", "T065", "T066", "T067", "T067a", "T067b", "T070", "T070a", "T070b", "T071", "T072", "T073", "T075", "T077", "T079a", "T080", "T081", "T109", "T110", "T111", "T112", "T114", "T117", "T119", "T120", "T121", "T123", "T124", "T126", "T132", "T134", "T135", "T136", "T137", "T138", "T139", "T160", "T141", "T142", "T143", "T144", "T145", "T146", "T147", "T148", "T149", "T150", "T151", "T152", "T153", "T156", "T157", "T158", "T159", "T161"]
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

# T079: Run the `stargate-perf` agent against the data plane (Principle VIII);

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Run the `stargate-perf` agent against the data plane (Principle VIII); verifies SC-005 (≥200 concurrent CONNECTs against the synthetic SOCKS5 backend from T019a) and the zero-retained-allocation property on the forwarding hot path.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

### Required planning refinement


Run on the completed candidate after implementation and live/reproducibility prerequisites.
Record the snapshot and environment, SC-005 concurrency and retained-allocation evidence.
File and resolve blocking findings, then remeasure affected paths; T155 does not satisfy this review.

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T173 renderer dependency refinement

T071 owns the consolidated T068/T069 tests and renderer implementation. Retain T071 as
the blocker; the superseded deferred test tickets must not independently block this consumer.
