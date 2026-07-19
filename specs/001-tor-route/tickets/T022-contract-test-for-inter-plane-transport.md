---
id: T022
title: 'Contract test for inter-plane transport invariants in `tests/contract/'
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T022
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
  - specs/001-tor-route/contracts/control-grpc.md §"Transport invariants"
  - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"
  - specs/000-architecture/spec.md §5.5 (schema-version handshake row 4)
decision_refs: []
reviews: { round: 1, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T022: Contract test for inter-plane transport invariants in `tests/contract/

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for inter-plane transport invariants in `tests/contract/control-grpc/transport_test.go` — both UDS paths exist (`/run/stargate/control.sock` hosted by the CP, `/run/stargate/dp.sock` hosted by the DP); each socket is mode 0660 with the hosting plane's user as owner and `stargate-ipc` (GID 5100) as group per `contracts/control-grpc.md` §"Socket topology"; the **peer plane (in the `stargate-ipc` group) can `connect(2)`** its dial-direction socket — DP-uid succeeds dialling `control.sock`, CP-uid succeeds dialling `dp.sock` (regression gate against accidental revert to 0600 which would silently break inter-plane comms); a **same-host process outside `stargate-ipc` cannot dial either socket** (assert `EACCES`); neither plane dials TCP; each plane refuses to dial the *other* socket path with role swapped (no role swap of the *server*); mutual ed25519 auth on each socket; schema-version handshake on either socket rejects `stargate.v2` peers; plane-down survival (DP keeps serving port 8881 across a CP restart, CP re-dials `dp.sock` and re-pushes the current generation on reconnect); **production-caller-absent regression-grep** (per `contracts/control-grpc.md` §"Transport invariants" row 10 — greps the control-plane production source tree for `GetStatus(` with test-only paths excluded via globs `**/test/**` and `**/*Test.java`, asserts zero matches; gates the admin-UI feature against silently wiring a production caller before research.md §11's deferral is revisited). Per `contracts/control-grpc.md` §"Transport invariants".

## Analysis

The 10 invariants in `contracts/control-grpc.md` §"Transport invariants"
split into three testability tiers. T022 covers the first two; the third
is compose-level and deferred (see §Out-of-scope).

- **Must hold:**
  - Row 10 (production-caller-absent regression-grep): the control-plane
    production source tree (excluding `**/test/**` and `**/*Test.java`)
    MUST contain zero occurrences of the literal `GetStatus(`. Gates the
    admin-UI feature against silently wiring a production caller before
    research.md §11's deferral is revisited. This is the SOLE invariant
    in the transport table testable NOW (no DP/CP implementation needed)
    and is the highest-value deliverable in this ticket.
  - Row 1 (no TCP transport): the DP creates no TCP listener for gRPC —
    the only TCP LISTEN is the proxy port 8881. The DP's gRPC surface is
    exclusively UDS (`dp.sock`). Asserted by reading `/proc/<pid>/net/tcp`
    and verifying the only LISTEN entry matches `proxyAddr`.
  - Row 2 (role separation via bind): the DP binds `dp.sock` and does NOT
    bind `control.sock` — asserted by stat-ing the IPC dir after DP boot
    (`dp.sock` exists as a socket; `control.sock` does not exist).
  - Row 8 (schema-version handshake): a `stargate.v2` peer offering an
    unknown major-version marker is rejected (arch §5.5 row 4). DEFERRED
    to T045/T050 — the v2-marker wire shape is implementation detail that
    cannot be test-pinned before it exists; a placeholder that fails on
    gate-lift would not pin any specific behaviour. See §Out-of-scope.
- **Gated:**
  - License-header check (verify.sh gate 1) gates SPDX headers on the new
    file.
  - The production-caller-absent grep runs as a Go test under
    `tests/contract/control-grpc/` — NOT in verify.sh's gate 4 (which is
    shell-only). Validated via the container command in §Acceptance
    (T019b/T020 precedent); CI wiring is T076's scope.
  - Local-process invariants reuse T020's harness (`startDP`, `dpHarness`,
    `waitFor`, `findRepoRoot`) unchanged. T022 adds a `pid int` field to
    `dpHarness` (2-line change: field + assignment in `startDPWith`) so
    row 1 can read `/proc/<pid>/net/tcp`. No other harness change.
- **Residue:**
  - Rows 3-7 (socket mode `0660`, owner `stargate-cp`/`stargate-dp`,
    group `stargate-ipc` GID 5100, peer-plane UID `connect(2)` success,
    non-group UID `EACCES`, mutual ed25519 auth) are compose-level: the
    local-process harness runs everything as one UID and cannot reproduce
    the UID/GID/mode separation or the key-material handshake. These
    invariants MUST be tested at compose level (real users, real key
    material). Deferred to §Out-of-scope — a compose-level shell test or
    Docker-SDK Go test that runs the real `docker compose up` stack. The
    stargate-cp (5101) / stargate-dp (5102) / stargate-ipc (5100) UID/GID
    scheme exists only in the Dockerfiles (T002a/T003a), not in the
    local-process test environment.
  - Row 9 (plane-down survival) is covered by T020 (DP serves with no CP
    from cold start) and T021 row 3 (DP reconnects after server-side
    stream close). An explicit sub-test here would be redundant; noted in
    §Out-of-scope rather than re-asserted.
  - The no-TCP assertion (row 1) is only as strong as the DP's observable
    surface: the test asserts no TCP LISTEN exists beyond the proxy port
    at test time, but a future code change that adds an outbound TCP dial
    (not a LISTEN) would slip past. The egress-consensus integration test
    (T034f) is the release-cadence backstop for outbound dials.

## Acceptance

1. New file `tests/contract/control-grpc/transport_test.go` defines
   `TestTransportInvariants` with sub-tests mapping to the
   testable-now / local-process tiers of `contracts/control-grpc.md`
   §"Transport invariants" (compose-level rows 3-7 and redundant row 9
   are §Out-of-scope):
   - `ProductionCallerAbsent_GetStatus`: walk `control-plane/` under the
     repo root; skip any path containing `/test/` or matching `*Test.java`;
     grep the remaining `.java` files for the literal `GetStatus(` (proto/
     Go PascalCase) AND `getStatus(` (Java gRPC lowerCamelCase — proto
     `rpc GetStatus` generates Java `getStatus`); assert zero matches for
     either. Failure message lists each match path + which casing matched.
     Runs NOW — no content gate (static source-tree regression gate).
     Currently zero matches (T035-T041 not yet landed); goes red the
     moment a production caller is added in either casing.
   - `SocketTopology_DPBindsOnlyDpSock`: `startDP`; assert `${ipcDir}/dp.sock`
     exists and `os.Stat` reports a socket (`mode & os.ModeSocket != 0`);
     assert `${ipcDir}/control.sock` does NOT exist (the DP binds only its
     own socket — role separation via `bind(2)`). Self-skips via
     `startDP`'s T045/T050 content gate.
   - `NoTCPTransport_OnlyProxyListener`: `startDP`; read BOTH
     `/proc/<pid>/net/tcp` (IPv4) and `/proc/<pid>/net/tcp6` (IPv6);
     parse the hex `local_address` port and `st` (state `0x0A` = LISTEN);
     assert `len(listenPorts) >= 1` (sanity: the proxy listener MUST be
     visible, preventing a vacuous pass on an empty table); assert every
     LISTEN port is `proxyAddr`'s port — no additional TCP listener for
     gRPC (the DP's gRPC surface is UDS-only). Assert `dp.sock` is a Unix
     domain socket (stat). Self-skips via `startDP`'s T045/T050 content
     gate AND on non-Linux (the `/proc` path is Linux-specific; the
     container is Linux so this always runs when the impl gate lifts).
2. `tests/contract/control-grpc/dpharness_test.go` gains TWO fields:
   `pid int` (set from `cmd.Process.Pid`) and `ipcDir string` (set from
   the local `ipcDir` variable) on `dpHarness`. Four lines added (two
   field declarations + two assignments in the return struct). No other
   change. T020/T021 call sites unaffected (zero-value safe).
3. License header `// SPDX-License-Identifier: Apache-2.0` on the new file.
4. No change to `tests/contract/go.mod` (all deps already present from
   T020/T021).
5. Container validation (host has no Go toolchain), from the repo root:
   ```
   docker run --rm -v "$PWD":/src -w /src/tests/contract \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c 'gofmt -l . && go vet ./... && go test -race -count=1 ./control-grpc/'
   ```
   Expected today: compile green; `ProductionCallerAbsent_GetStatus` PASSes
   (zero matches); the three runtime sub-tests SKIP on the T045/T050
   content gate. The digest pin mirrors `data-plane/Dockerfile` exactly
   (Principle IV; T019b/T020 precedent — a rotation lands there first).

## Out-of-scope

- **Rows 3-7 of the transport-invariants table** (socket mode `0660`,
  owner `stargate-cp`/`stargate-dp`, group `stargate-ipc` GID 5100,
  peer-plane UID `connect(2)` success, non-group UID `EACCES`, mutual
  ed25519 auth). These are compose-level: the UID/GID/mode separation
  and the ed25519 key material exist only in the Dockerfiles (T002a/T003a)
  and the compose stack (T015), not in the local-process test environment.
  A follow-up ticket (T022a or a compose-level shell test in
  `tests/contract/compose/`) should run the real `docker compose up` stack
  and stat/dial the sockets as the real `stargate-cp` / `stargate-dp` /
  arbitrary UIDs. Listed in §Residue as the compose-level backstop.
- **Row 8 (schema-version handshake)**: the v2-marker wire shape is
  T045/T050 implementation detail. A placeholder test that fails on
  gate-lift without pinning specific behaviour violates Principle VII's
  "meaningful test" requirement. When T045 defines the marker shape
  (response metadata key? stream header? connection-level?), the test
  can be authored against it. Listed in §Residue.
- **Row 9 (plane-down survival)**: covered by T020 (DP serves auth with
  no CP from cold start) and T021 row 3 (DP reconnects after server-side
  WatchEvents stream close). An explicit sub-test here would re-assert
  what those two tickets already pin.
- The DP/CP implementation this test gates: T045 (DP gRPC server + client),
  T050 (DP main), T038 (CP gRPC server), T039 (CP SidecarMonitor). The
  schema-version handshake impl (row 8) is part of T045/T050.
- No change to `data-plane/**`, `control-plane/**`, `proto/**`, `compose/**`,
  or verify.sh.
- CI workflow wiring for `tests/contract/` Go tests is T076.

## Notes

- Why the transport table splits across T022 (local-process + static) and
  a future compose-level test: the local-process harness (`startDP`)
  boots the DP as the test process's own UID — it cannot reproduce the
  `stargate-cp`/`stargate-dp`/`stargate-ipc` UID/GID scheme that the
  mode/owner/peer-dial invariants depend on. Trying to test those locally
  would either (a) be a tautology (asserting the test process's own UID)
  or (b) require `setuid` syscalls that need root and break on most CI
  runners. The compose stack is the right home for those checks.
- The `ProductionCallerAbsent_GetStatus` sub-test is the most valuable
  deliverable in this ticket: it is a regression gate that runs NOW (before
  any DP impl lands) and catches the admin-UI feature silently wiring a
  production `GetStatus` caller — the exact scenario the contract's row 10
  exists for. Zero matches today (T035-T041 not yet landed); the test goes
  red the moment a production caller appears, regardless of whether the DP
  side is implemented.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance derived at `/start` 2026-07-06 against HEAD `417ca54`,
  grounded on `contracts/control-grpc.md` §"Transport invariants" +
  §"Socket topology", arch §5.5, and T020/T021 harness precedents.
