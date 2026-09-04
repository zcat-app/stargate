---
id: T050
title: 'Implement `data-plane/cmd/stargate-proxy/main.go`'
status: pending
created: 2026-07-04
last_updated: 2026-09-04
source: tasks.md#T050
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T090, T095]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/wire-auth.md (consumed verbatim — DO NOT redefine the wire shape)
  - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"
  - specs/000-architecture/spec.md §5.4
  - specs/000-architecture/spec.md §5.5
decision_refs:
  - SECURITY-DECISIONS.md 2026-07-12 (cert validity policy)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T050: Implement `data-plane/cmd/stargate-proxy/main.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/cmd/stargate-proxy/main.go` — run `bind/check.go` (T013) FIRST; load `dp-snapshot.json` (T046); dial the control plane (T045); open the port-8881 listener (T042 + T043); begin forwarding immediately — admission is NOT gated on a `SidecarEvent` (data-model.md §2; Principle II; sol-review B3); `WatchEvents` runs concurrently and its events are advisory. Verified end-to-end by T033, T034.

## Analysis

Required (`privacy_critical: true`) — full property map. Grounded
2026-09-04 against wire-auth.md, control-grpc.md §"Socket topology",
arch §5.4/§5.5, SECURITY-DECISIONS.md (T095), and the landed seams:
`bind/check.go` (T013), `auth/token.go` (T044), `controlclient/`
server/client/snapshot/tls (T045/T046), `listener/` (T042/T043),
`forward/tor.go` (T047), `errortpl/render.go` (T048), `audit/counters.go`
(T049). The tests-first env-var contract is pinned in
`tests/contract/control-grpc/dpharness_test.go` §header and mirrored by
`tests/contract/internal/dpharness/dpharness.go` (STARGATE_IPC_DIR /
STARGATE_STATE_DIR / STARGATE_KEYS_DIR / STARGATE_LISTEN_ADDR /
STARGATE_TOR_SOCKS_ADDR). Dependency note (grounding finding): the boot
is also the composition root for `listener.ConnectDeps.Renderer`
(non-nil by the seam's doc), so T048 (render.go) is a de-facto
prerequisite — tasks.md's dev-order line already sequences T048 before
T050; T048 landed 2026-09-04.

- **Must hold (property map)**
  - Boot order is fixed and load-bearing (Principle II; data-model.md
    §2; sol-review B3): (1) `bind.Check` FIRST, fatal `BIND_REFUSED`
    exit before ANY listener; (2) token store + `RestoreSnapshot`
    (T046 — never fatal, §1.4); (3) TLS material via
    `controlclient.DeriveDPTLS(keysDir)` (§2: dp.priv → in-memory
    self-signed Ed25519 cert, never persisted; pin anchor cp.pub);
    (4) DP gRPC server on dp.sock via `controlclient.Listen` (mode 0660
    past umask; bind(2) role separation) + `NewGRPCServer` (the §5.3
    interceptor chain — the only server shape T050 may boot);
    (5) WatchEvents client via `controlclient.NewClient` + `Run`
    goroutine — the §"WatchEvents" backoff loop, never fatal, events
    advisory; (6) port-8881 listener + `listener.Deps` wiring —
    forwarding begins at the first `Accept`, no `SidecarEvent`
    precondition; (7) SIGINT/SIGTERM graceful teardown (harness
    stop() sends SIGINT with a 3 s grace). → Gated by the lifted
    process suites (below); the cold-start property specifically by
    `cold_start_snapshot_test.go` (T020a).
  - Degraded mode (acceptance #3; wire-auth §2.2/§3.3; arch §5.4): a
    `DeriveDPTLS` failure (unreadable dp.priv, parse error, missing
    cp.pub pin) journals the `control_channel` degraded line once
    (loginvariants allowlist class; same vocabulary client.go uses at
    runtime) and the DP boots the listener + forwarding WITHOUT the
    inter-plane surface — never degraded into an unauthenticated
    inter-plane socket (tls.go §2.2 doc). `cold_start_snapshot_test.go`
    `seedInterPlaneKeys`' doc pins the absence semantics: "without it
    the boot degrades before the client starts".
  - Pepper: `auth.LoadPepper` failure is FATAL (corrupt install fails
    loudly at boot, §1.5 — a wrong-length pepper silently
    authenticating nothing is the designed non-fatal surface, a
    wrong-SIZE file is not). Env resolution: the five STARGATE_*
    variables with the harness-contract defaults; production compose
    leaves them unset.
  - Journal discipline (FR-008; loginvariants): main emits only
    allowlisted lines — `startup` (field: listener) after the port-8881
    listener is open; `shutdown` (field: reason) on signal/fatal-boot
    exit; the degraded line via the `control_channel` class. The slog
    TextHandler runs with `time=` stripped (AssertNoSubHourTimestamp).
    No per-request line anywhere in the accept loop.
  - Principle I/III: the accept loop opens no outbound socket (forward
    seam dials only the constructor-pinned upstream), resolves no
    names, parses no payload; STARGATE_TOR_SOCKS_ADDR is the
    test-defined choke point (production default tor:9050).
  - Inter-plane transport: `unix://` only, no TCP gRPC surface
    (acceptance #5) — the only TCP listener is port 8881.
- **Gated (verify.sh catches fail-closed once main.go lands)**
  - The dpharness gates (`RequireFile` on main.go) self-lift the whole
    process-level tier: control-grpc (T020/T020a/T021/T022 harness
    suites), socks5 (T023/T024/T025a–d, T026), error-template
    (T027/T068a AUTH_REQUIRED surfaces — lifting on the T048 render.go
    gate), tor/port_exposure and compose/network_hardening gates.
  - `go vet` / gofmt / race / staticcheck / gosec / secret-scan under
    verify.sh; container validation per acceptance #6.
- **Residue (no gate catches; scoped for review/redteam)**
  - **dp.sock mTLS attach is NOT wired.** wire-auth §4 mandates
    client-auth TLS on BOTH sockets, and T045's tls.go builds the
    server half (`ServerTLSConfig`), but the landed
    `controlclient.NewGRPCServer` hosts no transport credentials and
    exposes no way to add them, and every done local-process test
    (T020/T022/T025c/d/T045's own harness) dials dp.sock with
    `insecure.NewCredentials()` at the seam the harness doc reserves
    ("T022 seam: mutual-ed25519 client credentials attach at this
    dial"). Forcing TLS there without that reserved harness update
    would flip the done local tier red. The kernel-enforced gates
    (mode 0660, stargate-dp:stargate-ipc, distinct UIDs) remain the
    active local-tier defense; the mTLS second gate lands with the
    controlclient credentials API + harness credential attach (the
    live-stack R4/R8/R9 rows force it). Recorded as the ticket's
    principal residue; NOT silently papered over.
  - **Forced fixture lift (wire-auth §4 convergence).** Five done
    test fixtures predate wire-auth.md (T095, 2026-07-12): they host a
    PLAINTEXT fake control plane and seed NO inter-plane keys, yet
    assert the DP dials and consumes WatchEvents (watch_events ×3,
    userpass_success, long_lived_connect, no_per_request_logs,
    auth_passed_counter). T045's landed client is TLS-mandatory
    (NewClient rejects nil TLS per §4), so these fixtures cannot pass
    against a contract-conforming boot. The harness docs reserve
    exactly this update ("forces that update" — dpharness_test.go
    §header). T050 lands the fixture modernization — TLS fake CP +
    coherent seeded keypair (dp.priv/dp.pub/cp.priv/cp.pub) at the
    reserved seams — with ZERO assertion changes (mirroring T045's
    forced T095-lift precedent; files touched stay within budget).
  - Advisory-event application is a no-op sink: client.go journals
    receipt (`sidecar_event` class); the audit/status application is
    T073's scope.
  - Stale-socket crash-loop: after SIGKILL, a leftover dp.sock in the
    persistent ipc volume would fail `Listen`; main removes its OWN
    socket path before bind (role separation makes this safe) — the
    same belt-and-braces the test fakes do.
  - dp.sock `GetStatus`/`ReloadTokens` behavior, Tor egress realism,
    and live-sidecar properties remain with T032/T033/T034/T058+ and
    the milestone redteam sweep.

## Acceptance

1. Boot order per §Analysis (bind → snapshot → TLS material → dp.sock
   server → CP client → listener → forward), signals tear down
   gracefully (SIGINT exits 0 within the harness's 3 s grace, closing
   dp.sock + port 8881). `bind.Check` failure exits non-zero BEFORE any
   listener (FR-010; arch §10.1 BIND_REFUSED).
2. Cert derivation per wire-auth §2 via `DeriveDPTLS`; the cert never
   touches disk; `NotBefore`/`NotAfter`/SAN/ExtKeyUsage per §2.2 are
   tls.go's landed values (T045-gated), consumed verbatim.
3. A cert-derivation or pepper-pin failure journals the
   `control_channel` degraded line once and the listener + forwarding
   still come up (`cold_start_snapshot_test.go` sub-test (b) drives the
   keys-present variant; the keys-absent variant is exercised by every
   keyless harness boot).
4. WatchEvents consumer runs the §"WatchEvents" backoff, advisory only;
   port 8881 accepts and forwards regardless of channel state
   (`watch_events_test.go` AdmissionNotGatedBySidecarEvents;
   `cold_start_snapshot_test.go` Port8881ServesDuringWatchEventsBackoff).
5. No TCP transport for inter-plane: only the port-8881 TCP listener
   exists (`transport_test.go` row 1; wire test R7 at live-stack time).
6. Named tests, all previously SKIP-gated on this file and now lifting
   FAIL-forcing (run from `tests/contract`): `go test ./control-grpc/
   ./socks5/ ./error-template/ -count=1` — specifically
   `TestReloadTokens*` (T020), `TestColdStartSnapshot*` (T020a),
   `TestWatchEvents*` (T021), `TestTransportLocal*` (T022),
   `TestDemux*`/`TestUserPassSuccess*` (T023/T025a),
   `TestSOCKS5SuccessPathLogInvariants` (T025a), `TestLongLived*`
   (T025b), `TestAuthFailureCounter*`/`TestAuthPassedCounter*`
   (T025c/d), `TestHTTPConnectAuthSuccess` (T026),
   `TestAUTHRequired` + `TestHeaderSet/AUTH_REQUIRED` (T027/T068a).
   The four plaintext-fake-CP fixtures move to the TLS control plane
   (fixture-only change; every assertion untouched — diff-reviewable).
7. Container validation (host has no Go toolchain), from the repo root:
   ```
   docker run --rm -v "$PWD":/src -w /src/data-plane \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c 'gofmt -l . && go vet ./... && go test -race -count=1 ./...'
   bash tests/contract/compose/inter_plane_wire_test.sh
   ```
   Expected: data-plane gates PASS; wire test structural tier PASS with
   the runtime tier LIFTED (markers authored at T045) and its rows
   SKIPping loudly without a live `stargate init` stack.

## Out-of-scope

- The wire-shape definition itself — T095's `contracts/wire-auth.md`,
  consumed verbatim. A gap found during impl lands as a wire-auth.md fix
  (T095 rework round), not a T050 invention.
- The DP gRPC server/client implementation (`server.go`, `client.go`) —
  T045. T050 wires them into the boot order.
- The CP-side server — T038.
- Automated certificate rotation — deferred per wire-auth.md §6.2 and
  SECURITY-DECISIONS.md (T095 entry).
- The dp.sock mTLS transport attach (controlclient credentials API +
  harness insecure-dial-site update) — the principal §Analysis residue;
  forced later by the live-stack runtime rows, not this ticket.
- Advisory-event application (audit/status mapping) — T073.

## Notes

- T095 §Acceptance #5 mandates verbatim consumption. The §Analysis +
  §Acceptance reference wire-auth.md section numbers; no wire shape is
  restated here.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance refined 2026-07-12 against T095's `contracts/wire-auth.md`.
