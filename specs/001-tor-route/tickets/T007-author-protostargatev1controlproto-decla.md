---
id: T007
title: 'Author `proto/stargate/v1/control.proto` declaring `package stargate.v'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T007
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

# T007: Author `proto/stargate/v1/control.proto` declaring `package stargate.v

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `proto/stargate/v1/control.proto` declaring `package stargate.v1`, `option go_package = ".../grpcpb"`, and the two RPCs this feature uses on the CP→DP direction: the `ReloadTokens` RPC with messages `ReloadTokensRequest`, `ReloadTokensResponse`, `TokenHash`, `ApplyStatus` — exactly per `contracts/control-grpc.md` §"ReloadTokens"; and the **minimum-subset `GetStatus` RPC** with messages `StatusRequest`, `StatusResponse`, `RouteCounter` — exactly per `contracts/control-grpc.md` §"GetStatus (minimum subset)". Both RPCs are hosted by the DP on `/run/stargate/dp.sock` per T045; `ReloadTokens` is called by the CP, `GetStatus` is called only by the test harness (T025c, T025d, T067b) in v1. Rationale for shipping `GetStatus` in v1's proto despite the production caller being deferred to the admin-UI feature lives in plan.md §"Plan-level tensions surfaced for review" #10 / research.md §11.

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
