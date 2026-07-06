---
id: T021
title: 'Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for '
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T021
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
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents"
  - specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"
  - specs/001-tor-route/data-model.md §2
decision_refs: []
reviews: { round: 2, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - { id: 20260706-002-detail-rejected-echo-false-pass, severity: major, status: fixed-pre-merge }
clarity_check: {}
---

# T021: Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for `tor`, fixed-vocabulary `detail` `container_start` then `healthcheck_pass`) in `tests/contract/control-grpc/watch_events_test.go` — per `contracts/control-grpc.md` §"WatchEvents · Tests" rows 1–3. Scope is intentionally just the happy-path pairings; the failure-transition pairings (`UNHEALTHY`/`STOPPED`/`CRASHED`/`RESTARTED`) are covered by T070b in Phase 5 alongside T074's implementation — keeping test/impl ordering aligned within each user story.

## Analysis

- **Must hold:**
  - `WatchEvents` is server-streamed by the control plane; the data plane
    is the gRPC **client** that dials `/run/stargate/control.sock`
    (`contracts/control-grpc.md` §"WatchEvents", §"Socket topology"). The
    test therefore HOSTS a fake control plane on `control.sock` before the
    DP boots — the inverse of T020, where the DP hosted the RPC under test.
  - Row 1 happy path: a `STARTED/container_start` then
    `HEALTHY/healthcheck_pass` pairing for `sidecar="tor"` transitions
    `routeEnableMask[TOR]` from cold-start DISABLED to ENABLED
    (`data-model.md` §2 state machine). `STARTED` alone MUST NOT transition
    the mask — only `HEALTHY` does — so the test probes BETWEEN the two
    events to assert the mask is still DISABLED after `STARTED`, then again
    after `HEALTHY` to assert the flip. The observable is the SOCKS5
    request-phase reply byte (RFC 1928 §6 REP): DISABLED → `0x03`
    (byte-exact `05 03 00 01 00 00 00 00 00 00` per
    `contracts/socks5-auth.md`); ENABLED → REP ≠ `0x03` (the exact post-
    HEALTHY reply is forward-path/T072-dependent, not T021's claim — T021
    asserts only that the mask is no longer DISABLED).
  - Row 2 forbidden detail: the data plane treats any `detail` value
    outside the closed set `{"healthcheck_pass", "healthcheck_fail",
    "container_exit", "container_start", "config_render"}` as a contract
    violation (§"WatchEvents · Contract"). The regression gate sends
    `detail = "could not bind 0.0.0.0:9050"` (the canonical log-line-in-
    detail shape the gate exists to catch) and asserts the DP (a) closes
    the stream and (b) journals a violation marker. Shared helper is
    reused by T070b sub-test (e).
  - Row 3 disconnect/reconnect: the stream is long-lived; on disconnect
    the DP reconnects with exponential backoff (initial 1 s, cap 30 s,
    jitter ±20 %). The test closes the first server-side stream after one
    event, waits for the DP to re-dial (observed server-side as
    `dialCount` incrementing), and asserts events on the second stream are
    applied (route transition observed via the same SOCKS5 probe as row 1).
  - The test observes the DP **externally only**: gRPC client to `dp.sock`
    (for `ReloadTokens` setup pushes), the fake CP gRPC server on
    `control.sock`, the SOCKS5 bytes on the 8881 listener, and the
    captured stderr journal. No import of `data-plane/internal/...` — Go's
    internal-package rule makes this structural (tests/contract is a
    separate module, same wall T020 relies on).
  - Principle VII (tests-first): this test lands BEFORE T045 client.go,
    T042, and T047. It content-gates (fail-not-skip once the gate files
    exist) on the union of files its assertions touch:
    `data-plane/internal/controlclient/{server,client}.go`,
    `data-plane/cmd/stargate-proxy/main.go` (all via `startDP`/T020's
    gate), plus `data-plane/internal/listener/socks5.go` and
    `data-plane/internal/forward/tor.go` for rows 1 and 3 (route
    observation). Row 2 (forbidden detail) needs only `client.go` and
    sub-gates itself accordingly so it can run as soon as the consumer
    lands, without waiting on the forward path.
  - No `detail` value, `sidecar` string, or event-field content from any
    emitted `SidecarEvent` is logged verbatim by the DP outside the
    contract's fixed-vocabulary surface. The test reuses T020's
    `assertNoSecretLeak` over the captured journal as a sanity gate (the
    plaintext password used for auth probes is the one secret in scope).
- **Gated:**
  - License-header check (verify.sh gate 1) gates SPDX headers on new files.
  - The data-plane module's gofmt/vet/test gates are untouched — this
    ticket adds files only under `tests/contract/`.
  - T020's harness (`dpharness_test.go`) gates the shared DP boot; T021
    adds one surgically-scoped extension point (`startDPWith`, below) and
    otherwise reuses `startDP`, `mintToken`, `reload`, `waitFor`, and
    `assertNoSecretLeak` unchanged.
- **Residue:**
  - The bounded backoff schedule (initial 1 s, cap 30 s, jitter ±20 %) is
    asserted only by this test at the contract level — no static check
    enforces it. The lower bound (≥ 0.8 s) is falsifiable; the upper bound
    (≤ 30 s) is a sanity check only, since the first reconnect after one
    server-close is structurally near the initial step (~1 s ± 20 %), not
    near the 30 s cap — the cap itself is T045's unit-test territory.
  - The closed-vocabulary `detail` enforcement at the DP consumer is
    gated ONLY by row 2 of this test. A regression that loosens the
    vocabulary check (or drops it) would slip past unless row 2 runs.
    Promoted into the gated set by row 2 itself — T070b sub-test (e)
    reuses the same helper for the failure-transition pairings.
  - The `(kind, detail)` pairing correctness (`STARTED → container_start`,
    `HEALTHY → healthcheck_pass`) is asserted only by row 1's happy-path
    send. The contract does not require the DP to ENFORCE the pairing
    (only the vocabulary); row 1 sends the correct pairings and asserts
    the route effect, which is the contract-level claim.

## Acceptance

1. New file `tests/contract/control-grpc/watch_events_test.go` defines
   `TestWatchEvents` with three sub-tests, each mapping 1:1 to
   `contracts/control-grpc.md` §"WatchEvents · Tests" rows 1–3 (happy-path
   pairings only; failure-transition pairings are T070b):
   - `HappyPathTransitionsRouteToEnabled`: with a fake CP hosted on
     `control.sock` and a known-plaintext token pushed via `ReloadTokens`
     on `dp.sock`, (a) assert the DP dials `control.sock` (fake CP
     `dialCount` ≥ 1 within a bounded wait); (b) send
     `SidecarEvent{sidecar:"tor", kind:STARTED, detail:"container_start"}`
     and POLL SOCKS5 CONNECT for ~2 s — assert reply stays byte-exact
     `05 03 00 01 00 00 00 00 00 00` throughout (mask still DISABLED,
     proving `STARTED` alone does not transition; polling catches a
     spurious flip any time in the window, not just at one point); (c)
     send `SidecarEvent{sidecar:"tor", kind:HEALTHY,
     detail:"healthcheck_pass"}` and probe SOCKS5 CONNECT — assert reply
     REP ≠ `0x03` (mask flipped to ENABLED). Row sub-gates on
     `listener/socks5.go` AND `forward/tor.go` existence and self-skips
     with a precise message until both land.
   - `ForbiddenDetailRejected`: send a `SidecarEvent` with `detail =
     "could not bind 0.0.0.0:9050"` (out-of-vocabulary); assert (a) the DP
     closes the stream (fake CP observes `stream.Context().Done()` within
     a bounded wait) and (b) the captured journal contains a contract-
     violation marker — the scan checks a set of plausible violation-line
     phrasings (`"violation"`, `"unknown detail"`, `"invalid detail"`,
     `"forbidden detail"`, `"rejected"`) rather than the bare substring
     `"detail"`, which an event-receipt line could also match. Reusable
     helper `assertDetailRejected(t, h, fakeCP, detail)` is defined at
     package level for T070b sub-test (e) to call.
   - `DisconnectReconnectAppliesEvents`: (a) fake CP accepts the first
     `WatchEvents` dial, sends `STARTED/container_start`, then closes the
     stream from the server side; (b) assert the DP re-dials within
     [0.8 s, 30 s] (lower bound proves backoff-not-immediate-retry; upper
     bound is the contract's cap — observed server-side as `dialCount`
     incrementing to 2; the `waitFor` timeout is 35 s so the upper-bound
     assertion is reachable rather than dead code); (c) on the second
     stream, send `HEALTHY/healthcheck_pass` and assert the route
     transitions to ENABLED via the same SOCKS5 probe as
     `HappyPathTransitionsRouteToEnabled`. The reconnect-timing assertion
     (b) needs ONLY `client.go` and runs even if the forward path is
     absent — `requireForwardPath` is called AFTER the timing assertion,
     gating only the route-observation tail.
   - `HappyPathTransitionsRouteToEnabled` and
     `DisconnectReconnectAppliesEvents` additionally call
     `assertNoSecretLeak` over the captured journal with the auth-plaintext
     bytes (the only secret in scope — `SidecarEvent` fields are
     fixed-vocabulary, not secret).
2. The fake control plane lives in `watch_events_test.go` as
   `fakeEventsServer` (embeds `grpcpb.UnimplementedEventsServer`,
   overrides `WatchEvents`): a programmable server-side stream controller
   exposing `dialCount`, the latest `controlledStream`, a `send` helper,
   and a server-initiated `close`. Hosted by `startFakeCP(t, ipcDir)`,
   which binds `${ipcDir}/control.sock` (the same path the DP dials per
   `STARGATE_IPC_DIR`), `grpc.NewServer`, `RegisterEventsServer`, and
   `Serve` in a goroutine, with `GracefulStop` on `t.Cleanup`.
3. `tests/contract/control-grpc/dpharness_test.go` gains ONE
   surgically-scoped extension point: `startDPWith(t *testing.T, beforeBoot
   func(ipcDir string)) *dpHarness`, called by the existing `startDP` as
   `startDPWith(t, nil)` (T020's call sites unchanged). `beforeBoot` runs
   after the IPC dir is created and before `cmd.Start()`, so T021 can host
   the fake CP on `control.sock` in that dir before the DP's first dial.
   No other change to the harness.
4. `tests/contract/control-grpc/dpharness_test.go` does NOT gain a SOCKS5
   request-phase helper — the helper (`socks5ConnectReply`) lives in
   `watch_events_test.go` because T021 is its only caller this batch
   (T020a/T067 will move it to the harness when they need it; YAGNI now).
5. License header `// SPDX-License-Identifier: Apache-2.0` on the new file.
6. No change to `tests/contract/go.mod` (all deps — `google.golang.org/grpc`,
   `google.golang.org/protobuf` (transitive), `github.com/zcat-app/stargate/proto`
   — already present from T020).
7. Container validation (host has no Go toolchain), from the repo root:
   ```
   docker run --rm -v "$PWD":/src -w /src/tests/contract \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c 'gofmt -l . && go vet ./... && go test -race -count=1 ./control-grpc/'
   ```
   Expected today: compile green, `TestWatchEvents` SKIPs on the content
   gate. The digest pin mirrors `data-plane/Dockerfile` exactly (Principle
   IV; T019b/T020 precedent — a rotation lands there first).

## Out-of-scope

- Failure-transition `WatchEvents` pairings (`UNHEALTHY`/`STOPPED`/
  `CRASHED`/`RESTARTED`) and their `(kind, detail)` table — T070b's
  scope (Phase 5, paired with T074 implementation). T021's
  `assertDetailRejected` helper is reused by T070b sub-test (e).
- Transport-invariant contract on `control.sock` (mode/owner, TCP-refusal,
  mutual-ed25519, plane-down survival) — T022's scope.
- Cold-start snapshot restore with CP-absent dial retry — T020a's scope.
- The DP implementation this test gates: `WatchEvents` consumer + closed-
  vocabulary enforcement + reconnect backoff (T045 `client.go`), route
  state machine wiring (T050 main, T073 failure transitions), SOCKS5
  request-phase listener (T042), forward path (T047).
- No change to `data-plane/**`, `proto/**`, `compose/**`, or verify.sh.
- CI workflow wiring for `tests/contract/` Go tests is T076.

## Notes

- Why host a fake CP rather than reuse T020's no-CP harness: `WatchEvents`
  is server-streamed BY the control plane. With no CP, the DP's dial
  retries forever (Principle II) and no events are delivered — useless for
  testing event consumption. The fake CP is the test-side stand-in for the
  real CP (T038/T039), just as T020's gRPC client is the test-side stand-in
  for the real CP's `ReloadTokens` caller.
- Why the route observation is loose (REP ≠ `0x03`, not byte-exact): the
  exact post-HEALTHY reply depends on the forward path's failure mapping
  (T072 maps `tor:9050` dial failure → `ROUTE_REFUSED 0x04`), which is
  Phase 5 work. T021 asserts only the mask-flip — the only claim row 1
  makes. T067a will pin the byte-exact failure replies later.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance derived at `/start` 2026-07-06 against HEAD `b906efb`,
  grounded on `contracts/control-grpc.md` §"WatchEvents",
  `data-model.md` §2, `contracts/socks5-auth.md` §"SOCKS5 request-phase
  failures", and T020's harness precedent.
