---
id: T046
title: 'Implement `data-plane/internal/controlclient/snapshot.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T046
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093]
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

# T046: Implement `data-plane/internal/controlclient/snapshot.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/controlclient/snapshot.go` — atomic `os.Rename` write of `dp-snapshot.json` per data-model.md §1.4 on every successful `ReloadTokens`; restore on cold start when the control plane is unreachable.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.** The DP
gRPC server + snapshot path must: (a) accept `TokenVerifier{verifier}`
(32-byte HMAC tag; no salt) and apply atomically per
`ReloadTokens` contract (`contracts/control-grpc.md` §"ReloadTokens");
(b) on `generation <= current`, return
`APPLY_STATUS_STALE_GENERATION` AND echo `current_generation` in the
response so the CP reconciles and retries with `current + 1`
(`data-model.md` §1.3); (c) persist `dp-snapshot.json` as
`schemaVersion: 2` with `verifiers[]` only — NEVER the pepper, and ignore
a stale `schemaVersion: 1` snapshot rather than misparsing it
(`data-model.md` §1.4). The regenerated `grpcpb` stubs land with T093.
T093 (blocked_by T092) gates this ticket test-first.
