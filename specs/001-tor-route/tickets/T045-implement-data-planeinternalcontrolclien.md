---
id: T045
title: 'Implement `data-plane/internal/controlclient/`'
status: pending
created: 2026-07-04
last_updated: 2026-07-12
source: tasks.md#T045
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T090, T092, T093, T095]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/wire-auth.md (consumed verbatim — DO NOT redefine the wire shape)
  - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens"
  - specs/001-tor-route/contracts/control-grpc.md §"GetStatus (minimum subset)"
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents"
  - specs/000-architecture/spec.md §5.3
  - specs/000-architecture/spec.md §5.4
decision_refs:
  - SECURITY-DECISIONS.md 2026-07-12 (cert validity policy)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T045: Implement `data-plane/internal/controlclient/`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/controlclient/` — (a) `client.go`: gRPC client that dials `/run/stargate/control.sock`, consumes the server-streamed `WatchEvents` from the control plane, and applies events as **advisory status/audit hints** (data-model.md §2; Principle II — events MUST NOT gate admission; see T073 for the advisory consumption mapping); (b) `server.go`: gRPC server hosting `/run/stargate/dp.sock` (mode 0660, owned `stargate-dp:stargate-ipc` per `contracts/control-grpc.md` §"Socket topology") exposing **two** handlers — (i) `ReloadTokens` (atomic-swaps the `tokenStore` pointer and rejects stale generations with `APPLY_STATUS_STALE_GENERATION`); (ii) `GetStatus` (returns the current in-memory counter snapshot from `data-plane/internal/audit/counters.go` — the minimum-subset RPC declared in T007's proto, called by T025c, T025d, and T067b in v1; the CP does not call it in this feature). Mutual ed25519 handshake on both sockets using keys from `stargate-keys`. The package name `controlclient` is carried over from when the DP was client-only; renaming is deferred until a second gRPC service forces the issue. Verified by T020, T021, T022.

## Analysis

T045 is the **data-plane half** of the inter-plane wire contract. The
contract itself is binding in `specs/001-tor-route/contracts/wire-auth.md`
(completed by T095) — T045 consumes it verbatim and adds NO wire-shape detail
of its own (T095 §Acceptance #5).

- **Must hold** —
  - `server.go` hosts `ReloadTokens` + `GetStatus` on `/run/stargate/dp.sock`
    (mode `0660`, owner `stargate-dp:stargate-ipc` per arch §4.3); it does
    NOT bind `control.sock` (role separation via `bind(2)`).
  - `client.go` dials `/run/stargate/control.sock` for `WatchEvents` with
    the §"WatchEvents" backoff (initial 1s, cap 30s, jitter ±20%); events
    are advisory and MUST NOT gate admission (Principle II; data-model.md
    §2; sol-review B3; T090).
  - The DP TLS listener derives its self-signed Ed25519 X.509 cert from
    `/etc/stargate/keys/dp.priv` at startup, in-memory only, per
    wire-auth.md §2. Field values per §2.2.
  - Peer auth on BOTH sockets is the byte-equal public-key pin against
    `/etc/stargate/keys/cp.pub` (control.sock, dialed as client) /
    `/etc/stargate/keys/dp.pub` is NOT the DP's anchor — the DP validates
    the CP's cert against `cp.pub` when connecting to `control.sock`, and
    validates CP-client certs against `cp.pub` when accepting on `dp.sock`.
    Per wire-auth.md §3 (NOT CA-chain, NOT hostname).
  - The DP installs the §5.3 server interceptor (rejecting unknown major
    before app handlers run) AND the §5.3 client interceptor (setting the
    three metadata keys on every `WatchEvents` call). A `protoversion`
    package declares `Major=1`, `Minor=0`,
    `Capabilities="reload-tokens,watch-events,get-status-minimum"` per
    wire-auth.md §5.4 — single source so a future major bump touches one
    constant.
  - The DP MUST keep routing (port 8881) if the TLS handshake to the CP
    fails or the CP is unreachable (Principle II; arch §5.4; T090). A
    handshake failure is degraded-mode warning, not fatal.

- **Gated** —
  - `tests/contract/compose/inter_plane_wire_test.sh` (T095) lifts its
    runtime tier (R1-R8) when T038 + T045 + T050 all land. R5 (unknown
    major rejected) and R6 (additive minor accepted) pin the §5
    interceptor behaviour.
  - T020 (cold-start no-CP auth) and T021 (reconnect after stream close)
    gate the plane-down survival and `WatchEvents` advisory properties.
  - T022's local-process tier gates the no-TCP-transport and
    role-separation rows.

- **Residue** —
  - Cert validity (30-day window) and no-automated-rotation are
    operator-visible; recorded in THREAT-MODEL.md §5.13 + SECURITY-DECISIONS.md
    (T095 entry). T045 adds no residue beyond T095's.
  - The `controlclient` package name is a known misnomer (it also hosts
    the server); renaming is deferred (task body).

## Acceptance

1. `server.go` hosts `ReloadTokens` and `GetStatus` on
   `/run/stargate/dp.sock` (mode `0660`, owner `stargate-dp:stargate-ipc`).
   `ReloadTokens` atomic-swaps the `tokenStore` pointer and rejects stale
   generations with `APPLY_STATUS_STALE_GENERATION` per
   `contracts/control-grpc.md` §"ReloadTokens". `GetStatus` returns the
   in-memory counter snapshot per §"GetStatus (minimum subset)"; the CP
   production caller is absent (T022 row 10 regression grep).
2. `client.go` dials `/run/stargate/control.sock` and consumes `WatchEvents`
   as advisory hints per `contracts/control-grpc.md` §"WatchEvents" and
   data-model.md §2; admission is NOT gated on any event (T090).
3. The TLS configuration on BOTH the listener and the client follows
   `contracts/wire-auth.md` verbatim:
   - Cert derived from `dp.priv` at startup (§2.1), field values per §2.2.
   - Peer-pin verifier byte-equal-compares the peer cert's extracted public
     key against the matching `*.pub` (§3.1).
   - `InsecureSkipVerify` set only if Go's `crypto/tls` couples the knob
     to the custom `VerifyPeerCertificate` verifier; the §4 comment cited.
4. A `protoversion` package declares `Major=1`, `Minor=0`,
   `Capabilities="reload-tokens,watch-events,get-status-minimum"` (§5.4).
   `server.go` installs the §5.3 server interceptor (rejects unknown major
   with `FailedPrecondition` per §5.2). `client.go` installs the §5.3
   client interceptor setting the three metadata keys on every call.
5. No TCP transport for the inter-plane channel (wire-auth.md §4, arch
   §5.4); `unix://` dial/listen only.
6. TLS handshake failure to the CP logs a degraded-mode warning and the
   DP keeps routing port 8881 (Principle II; T090).
7. Container validation (host has no Go toolchain), from the repo root:
   ```
   docker run --rm -v "$PWD":/src -w /src/tests/contract \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c 'gofmt -l . && go vet ./... && go test -race -count=1 ./control-grpc/ ./compose/…'
   bash tests/contract/compose/inter_plane_wire_test.sh
   ```
   Expected today: structural tier PASS; runtime tier SKIP (T045 impl
   absent — the runtime gate lifts when T038 + T045 + T050 ALL land;
   see T095 §Notes for the R1-R8 FAIL-forcing gate).

## Out-of-scope

- The wire-shape definition itself — T095's `contracts/wire-auth.md`,
  consumed verbatim. A gap found during impl lands as a wire-auth.md fix
  (T095 rework round), not a T045 invention.
- The CP-side server (`ControlGrpcService` hosting `WatchEvents` on
  `control.sock`) — T038.
- The DP main boot order (cert derivation at startup, listener open,
  forwarding start) — T050.
- Automated certificate rotation — deferred per wire-auth.md §6.2 and
  SECURITY-DECISIONS.md (T095 entry).
- Renaming the `controlclient` package (task body notes the carry-over).

## Notes

- T095 §Acceptance #5 mandates verbatim consumption. The §Analysis +
  §Acceptance reference wire-auth.md section numbers; no wire shape is
  restated here.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance refined 2026-07-12 against T095's `contracts/wire-auth.md`.
