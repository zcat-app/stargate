---
id: T020
title: 'Contract test for `ReloadTokens` (happy / stale / invalid / snapshot-p'
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T020
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens"
  - specs/001-tor-route/contracts/socks5-auth.md §"Username/password sub-negotiation (RFC 1929)"
  - specs/001-tor-route/data-model.md §1.3–1.5
decision_refs:
  - specs/001-tor-route/research.md §5
reviews: { round: 2, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - { id: 20260706-001-leakscan-encoding-gaps, severity: major, status: fixed-pre-merge, review: reviews/redteam-20260706-b906efb.md }
clarity_check: {}
---

# T020: Contract test for `ReloadTokens` (happy / stale / invalid / snapshot-p

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for `ReloadTokens` (happy / stale / invalid / snapshot-persist-failure / concurrency) in `tests/contract/control-grpc/reload_tokens_test.go` — per `contracts/control-grpc.md` §"ReloadTokens · Tests".

## Analysis

- **Must hold:**
  - Each of the five `ReloadTokens` contract clauses
    (`contracts/control-grpc.md` §"ReloadTokens · Contract") is pinned by a
    named test case: (1) atomic swap + `APPLY_STATUS_OK` with subsequent
    inbound SOCKS5 auth honouring the NEW hashes and rejecting the old;
    (2) `request.generation <= current` → `APPLY_STATUS_STALE_GENERATION`,
    state unchanged; (3) hash ≠ 32 B or salt ≠ 16 B →
    `APPLY_STATUS_INVALID`, state unchanged; (4) snapshot-persist failure →
    still `APPLY_STATUS_OK` (in-memory truth wins) + a snapshot-write-failure
    journal line; (5) two concurrent generations converge on the higher one,
    the lower is stale on retry.
  - The test observes the DP **externally only**: gRPC on `dp.sock`, SOCKS5
    auth bytes on the 8881 listener (`0x01 0x00` / `0x01 0xFF` per
    `contracts/socks5-auth.md`), `dp-snapshot.json` bytes (data-model.md
    §1.4 shape), and captured stderr journal. No import of
    `data-plane/internal/...` — Go's internal-package rule makes this
    structural (tests/contract is a separate module).
  - No hash bytes, salt bytes, or token label in any captured journal output
    (contract §"ReloadTokens · Contract" final bullet): the test scans
    captured stderr for hex and base64 encodings of every hash/salt it sent.
  - Principle VII (tests-first): this test lands BEFORE T045 (DP gRPC
    server) and T050 (DP main). It content-gates on
    `data-plane/internal/controlclient/server.go` AND
    `data-plane/cmd/stargate-proxy/main.go` and self-skips with a precise
    message until both exist (T019b sub-test (c) precedent); once present, a
    broken build or failing contract is FAIL, not SKIP.
  - The argon2id parameters used to mint test `TokenHash` entries mirror
    data-model.md §1.5 exactly (time=3, memory=65536 KiB, parallelism=4,
    hashLen=32, saltLen=16) so the happy-path plaintext auth probe is valid
    against the real DP. The test-local mirror is itself a cross-plane
    params-agreement check (it cannot import `data-plane/internal/auth`).
- **Gated:**
  - License-header check (verify.sh gate 1) gates SPDX headers on new files.
  - The data-plane module's gofmt/vet/test gates are untouched — this
    ticket adds files only under `tests/contract/`.
  - T015's `local_compose_test.sh` continues to gate the compose-file shape;
    nothing here touches compose.
- **Residue:**
  - verify.sh does not compile or run Go tests under `tests/contract/`
    (gate 2 is data-plane-only; gate 4 is shell-only) and the host has no Go
    toolchain. Validation is the container command in §Acceptance (T019b
    precedent); PR-cadence CI wiring is T076's scope, not promoted here to
    avoid cross-ticket conflicts with in-flight [P] siblings.
  - The harness env-var interface (`STARGATE_IPC_DIR`, `STARGATE_STATE_DIR`,
    `STARGATE_KEYS_DIR`, `STARGATE_LISTEN_ADDR`) is **test-defined ahead of
    the implementation**: no spec pins a local-process config surface for
    the DP (compose uses fixed absolute paths). T045/T050 must conform or
    amend the single choke point (`dpharness_test.go`); drift surfaces as a
    test failure when those tickets land, never silently.
  - Mutual-ed25519 credentials on `dp.sock` are NOT exercised here — the
    transport-invariant contract (incl. the auth mechanism) is T022's scope.
    The harness dials with insecure transport credentials over the UDS and
    documents that dial site as the single seam where CP credentials attach.
    Once T045 enforces mutual auth this dial fails → fail-not-skip → forces
    the harness update loudly.
  - Case (4) is sub-skipped when `os.Geteuid() == 0` (a read-only parent
    dir does not block root writes), with a precise skip message.
  - Case (5) asserts convergence + stale-on-retry, not a specific
    interleaving — the contract requires only convergence; a scheduler
    cannot be forced from outside the process.
  - The snapshot-write-failure journal assertion matches the substring
    `snapshot` (case-insensitive) — the exact line shape is T046/T050
    implementation detail; the harness doc records this as the minimum
    contract (a line class T025a's allowlist already reserves).

## Acceptance

1. New file `tests/contract/control-grpc/reload_tokens_test.go` defines
   `TestReloadTokens` with five sub-tests, each mapping 1:1 to
   `contracts/control-grpc.md` §"ReloadTokens · Tests" rows 1–5:
   - `HappyPathAppliesNewGeneration`: push generation N+1 with one valid
     `{hash: 32 B, salt: 16 B}` minted from a known plaintext via the §1.5
     argon2id params → response is `APPLY_STATUS_OK` with
     `applied_generation == N+1`; `dp-snapshot.json` is rewritten with
     `generation == N+1` and base64 hash/salt matching what was sent
     (data-model.md §1.4 shape, `schemaVersion: 1`); a SOCKS5
     username/password sub-negotiation on the 8881 listener succeeds
     (`0x01 0x00`) with the NEW plaintext and fails (`0x01 0xFF`) with the
     OLD generation's plaintext.
   - `StaleGenerationRejected`: push `generation == current` →
     `APPLY_STATUS_STALE_GENERATION`; `applied_generation` still reports the
     current generation; the current generation's plaintext still
     authenticates; snapshot file unchanged.
   - `InvalidHashLengthRejected`: table over {hash 31 B, hash 33 B,
     salt 15 B, salt 17 B} → each returns `APPLY_STATUS_INVALID`; current
     generation unchanged (old plaintext still auths; snapshot unchanged).
   - `SnapshotPersistFailureStillOK`: chmod the snapshot parent dir 0o555 →
     push a valid next generation → response still `APPLY_STATUS_OK`; the
     captured DP stderr contains a snapshot-write-failure journal line
     (substring `snapshot`); the NEW plaintext authenticates (in-memory
     truth wins). Sub-skips with a precise message when euid is 0.
   - `ConcurrentReloadsConverge`: push generations N+1 and N+2 from two
     goroutines in parallel; after both return, a retry of the lower
     generation returns `APPLY_STATUS_STALE_GENERATION` and the DP reports
     `applied_generation == N+2`; the N+2 plaintext authenticates.
   - Every sub-test asserts the captured stderr contains no hex or base64
     encoding of any hash or salt bytes it sent (contract's no-logging
     bullet).
2. New file `tests/contract/control-grpc/dpharness_test.go` — the package
   harness: (a) content-gate skip until BOTH
   `data-plane/internal/controlclient/server.go` and
   `data-plane/cmd/stargate-proxy/main.go` exist; (b) `go build` of the DP
   binary into `t.TempDir()`; (c) starts the DP with the documented
   env-var interface (`STARGATE_IPC_DIR`, `STARGATE_STATE_DIR`,
   `STARGATE_KEYS_DIR`, `STARGATE_LISTEN_ADDR` with a pre-probed free
   loopback port) and captures stderr; (d) gRPC client over
   `unix://<ipc>/dp.sock` using `proto/stargate/v1/grpcpb` stubs;
   (e) SOCKS5 auth probe helper implementing the RFC 1929 byte sequence
   from `contracts/socks5-auth.md`; (f) argon2id mint helper mirroring
   data-model.md §1.5 params with a comment linking back to
   `data-plane/internal/auth/params.go`. The harness comment block records
   the env-var interface as the test-defined contract T045/T050 must
   satisfy, and marks the dial site as the seam for T022's mutual-ed25519
   credentials.
3. `tests/contract/go.mod` gains `google.golang.org/grpc`,
   `google.golang.org/protobuf`, `golang.org/x/crypto` (argon2), and
   `github.com/zcat-app/stargate/proto` (workspace-resolved; `replace`
   directive with a relative path if required for module resolution);
   `go.sum` updated alongside.
4. License header `// SPDX-License-Identifier: Apache-2.0` on every new
   file (incl. go.mod additions staying under the existing header).
5. Container validation (host has no Go toolchain), from the repo root:
   ```
   docker run --rm -v "$PWD":/src -w /src/tests/contract \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c 'gofmt -l . && go vet ./... && go test -race -count=1 ./control-grpc/'
   ```
   Expected today: compile green, `TestReloadTokens` SKIPs on the content
   gate. The digest pin mirrors `data-plane/Dockerfile` exactly
   (Principle IV; T019b precedent — a rotation lands there first).

## Out-of-scope

- `tests/contract/control-grpc/watch_events_test.go` is T021;
  `transport_test.go` (incl. mutual ed25519, socket mode/ownership,
  TCP-refusal, plane-down survival) is T022;
  `cold_start_snapshot_test.go` is T020a.
- The DP implementation this test gates: `ReloadTokens` server + tokenStore
  atomic swap (T045), snapshot write path (T046), DP main/boot order (T050).
- No change to `compose/**`, `data-plane/**`, `proto/**`, or verify.sh.
- CI workflow wiring for `tests/contract/` Go tests is T076.

## Notes

- Why a locally-exec'd DP process rather than compose: `dp.sock` lives in
  the `stargate-ipc` named volume — unreachable from a host test process;
  and tasks.md's sibling tests (T020a "boot the DP with no CP reachable",
  T025a "capture the data plane's stderr") already assume the same
  local-process harness model. The compose runtime topology is T019b/T022
  territory.
- Why no upstream (no `fake_socks5_tor.go`) here: the happy-path
  observability is the RFC 1929 sub-negotiation byte (`0x01 0x00` vs
  `0x01 0xFF`), which completes BEFORE the request-phase forward path.
  With no CP and no `HEALTHY` event, the forward path still attempts the
  fixed `tor:9050` upstream (admission is not CP-gated — data-model.md
  §2; Principle II; sol-review B3; remediated by T090) — irrelevant to
  auth (T020a pins that layering).
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance derived at `/start` 2026-07-06 against HEAD `b906efb`.
- Redteam pass (2026-07-06, `reviews/redteam-20260706-b906efb.md`) found
  Major 20260706-001: the journal leak scan's four-encoding set missed
  base64url and the decimal-slice rendering slog/`%v` produce for
  `[]byte`. Fixed pre-merge: the scan core is now the pure
  `findSecretLeaks` with eight encodings, negative-controlled by
  `tests/contract/control-grpc/leakscan_test.go` (runs even while the
  content gate skips `TestReloadTokens`). Minors fixed alongside:
  snapshot hash/salt content now matched against the pushed bytes (happy
  path), plaintexts included in every sub-test's leak scan, and
  `readSnapshot`'s failure output redacts snapshot content.
