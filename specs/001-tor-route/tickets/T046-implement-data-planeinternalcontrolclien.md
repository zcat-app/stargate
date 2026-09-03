---
id: T046
title: 'Implement `data-plane/internal/controlclient/snapshot.go`'
status: pending
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T046
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true   # /start 2026-09-03: lint PRIVACY-FLAG-MAYBE-MISSET verified — persists/restores bearer-token verifiers (auth surface, Principle VII); matches T043/T044/T045
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/data-model.md §1.3 (generation / atomic swap)
  - specs/001-tor-route/data-model.md §1.4 (dp-snapshot.json schema v2)
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens" (persist-before-OK row 4)
  - specs/000-architecture/spec.md §5.5 (control plane down at startup)
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

Quick pass (complexity: low). The snapshot is the auth material's
persistence layer — `privacy_critical` flipped to true at /start (lint
PRIVACY-FLAG-MAYBE-MISSET verified: the body handles verifier bytes, and
all sibling auth-plane tickets T043/T044/T045 carry the flag).

- **Property map**
  - Persist content = verifiers only, base64, schemaVersion 2, generation,
    loadedAt (RFC 3339) — never the pepper, never plaintext (§1.4; T092).
    → Caught by: `tests/contract/control-grpc/reload_tokens_test.go`
    (harness `readSnapshot` shape + fidelity asserts; skip-gated on T050).
  - Atomic write via `os.Rename`, temp file in the same dir; a failed
    persist leaves the previous snapshot intact and the RPC still OK
    (contract row 4). → Caught by: `SnapshotPersistFailureStillOK`
    (read-only parent dir), `reload_tokens_test.go` stale/invalid rows.
  - Cold-start restore: valid v2 → generation installed; stale v1 /
    unknown version / corrupt JSON / wrong-length verifier → warn + serve
    no tokens (empty generation), never misparse, never block boot
    (§1.4 T092 note; arch §5.5; Principle II).
  - No secret in logs: journal lines carry generation + count + path/OS
    error only (loginvariants `snapshot_write` class: msg `snapshot
    written` / `snapshot write failed`).
- **Residue (no gate catches yet)** — unit-level restore semantics for
  v1-ignore/corrupt/missing (T020a covers them end-to-end only after
  T050 lands). Closed by the in-package `snapshot_test.go` this ticket
  authors; T020a lifts the end-to-end gate at T050.

## Acceptance

- `TestWriteSnapshotAtomicAndShaped` (in-package): write → file at
  `<dir>/dp-snapshot.json` with `schemaVersion: 2`, base64 verifiers
  byte-faithful, no temp files left behind; a failing write (read-only
  dir) leaves the previous content intact and returns an error.
- `TestRestoreSnapshot` (in-package): v2 snapshot → generation restored;
  missing file → empty generation, no error; v1 snapshot → ignored with
  a journal warning; corrupt JSON / unknown version / wrong-length
  verifier → ignored, store stays empty; restored verifier authenticates
  via `auth.TokenVerifier` (round-trip with the pepper, never persisted).
- `scripts/verify.sh` green from repo root.

## Out-of-scope

- Wiring into the boot sequence and env resolution (`STARGATE_STATE_DIR`,
  default `/var/lib/stargate`) — T050 constructs `SnapshotWriter` /
  calls `RestoreSnapshot` and owns the "restore when CP unreachable"
  policy (arch §5.5).
- End-to-end cold-start contract test (`tests/contract/control-grpc/
  cold_start_snapshot_test.go`) — T020a.
- The v1 → v2 snapshot migration (v1 is ignored, not migrated — §1.4).
- `client.go`/`server.go` changes — T045's surface is stable; server.go
  already consumes the `SnapshotFunc` seam this file implements.

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
