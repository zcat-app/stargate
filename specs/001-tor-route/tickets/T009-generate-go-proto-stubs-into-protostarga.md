---
id: T009
title: 'Generate Go proto stubs into `proto/stargate/v1/grpcpb/` (in the separ'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T009
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T009: Generate Go proto stubs into `proto/stargate/v1/grpcpb/` (in the separ

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Generate Go proto stubs into `proto/stargate/v1/grpcpb/` (in the separate `proto/` Go module per the Option-D resolution recorded in the T007/T008 follow-up commit — keeps the data-plane module internal-only and lets `tests/contract/control-grpc/` import the stubs without violating Go's `internal/` rule) via `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`; commit generated files; add a regeneration script (location to be confirmed when this task runs — top-level `scripts/regen-proto.sh` is the leading candidate now that codegen is no longer scoped to the data-plane module) to make the step deterministic and auditable.

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
