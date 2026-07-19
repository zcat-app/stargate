---
id: T038
title: 'In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.jav'
status: pending
created: 2026-07-04
last_updated: 2026-07-12
source: tasks.md#T038
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T095]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/wire-auth.md (consumed verbatim — DO NOT redefine the wire shape)
  - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"
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

# T038: In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.jav

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.java` hosts the `WatchEvents` gRPC server, binding `/run/stargate/control.sock` (mode 0660, owned `stargate-cp:stargate-ipc` per `contracts/control-grpc.md` §"Socket topology"); (b) `ReloadTokensClient.java` is the gRPC *client* stub that dials the data plane's `/run/stargate/dp.sock` — used by `StargateControlPlane` (T041) to push token generations. Both endpoints perform the mutual ed25519 handshake using keys from `stargate-keys`. The CP does NOT host `ReloadTokens` — that server lives in the data plane (T045) because `ReloadTokens` direction is CP→DP per `contracts/control-grpc.md` §"ReloadTokens". Verified by T022 (transport invariants on both sockets) and T021 (`WatchEvents` server-side behaviour); the `ReloadTokens` client-side push is gated against the DP server by T020.

## Analysis

T038 is the **control-plane half** of the inter-plane wire contract. The
contract itself is binding in `specs/001-tor-route/contracts/wire-auth.md`
(completed by T095) — T038 consumes it verbatim and adds NO wire-shape detail
of its own (T095 §Acceptance #5).

- **Must hold** —
  - `ControlGrpcService` binds `/run/stargate/control.sock` (mode `0660`,
    owner `stargate-cp:stargate-ipc` per arch §4.3); it does NOT bind
    `dp.sock` (role separation via `bind(2)`, contracts/control-grpc.md
    §"Socket topology").
  - The CP TLS listener derives its self-signed Ed25519 X.509 cert from
    `/etc/stargate/keys/cp.priv` at startup, in-memory only, per
    wire-auth.md §2. Field values (NotBefore/NotAfter, SAN, ExtKeyUsage)
    are exactly as specified in wire-auth.md §2.2.
  - Peer auth is the byte-equal public-key pin against
    `/etc/stargate/keys/dp.pub` per wire-auth.md §3 (NOT CA-chain, NOT
    hostname).
  - The CP server installs the §5.3 interceptor that rejects an
    unknown `x-stargate-proto-major` with `FailedPrecondition` before any
    application handler runs. The CP client (`ReloadTokensClient`) sets
    the three metadata keys (`x-stargate-proto-major`, `-minor`,
    `-capabilities`) from a single `StargateProtoVersion` constants class
    on every call (wire-auth.md §5.1, §5.3).
  - The CP refuses to dial TCP for the inter-plane channel (wire-auth.md
    §4, arch §5.4).

- **Gated** —
  - The compose-level regression test
    `tests/contract/compose/inter_plane_wire_test.sh` (T095) pins the
    contract rows T038 must satisfy; its runtime tier lifts when this
    ticket + T045 + T050 all land.
  - T022's local-process tier (`tests/contract/control-grpc/transport_test.go`)
    gates the production-caller-absent `GetStatus` regression grep (row 10).

- **Residue** —
  - Cert validity (30-day window) and no-automated-rotation are
    operator-visible; recorded in THREAT-MODEL.md §5.13 + SECURITY-DECISIONS.md
    (T095 entry). T038 does NOT add residue beyond what T095 already
    carried.

## Acceptance

1. `ControlGrpcService.java` hosts the `WatchEvents` server-streamed RPC on
   `/run/stargate/control.sock` (mode `0660`, owner `stargate-cp:stargate-ipc`).
   Per `contracts/control-grpc.md` §"Socket topology" and `contracts/wire-auth.md`
   §2.1 (CP-hosted TLS listener).
2. `ReloadTokensClient.java` dials `/run/stargate/dp.sock` (the DP-hosted
   server from T045) and invokes `ReloadTokens` per `contracts/control-grpc.md`
   §"ReloadTokens" semantics (atomic swap, stale-generation rejection,
   `APPLY_STATUS_*`).
3. The TLS configuration on BOTH the listener and the client follows
   `contracts/wire-auth.md` verbatim:
   - Cert derived from `cp.priv` at startup (§2.1), field values per §2.2.
   - Peer-pin verifier byte-equal-compares the peer's extracted public key
     against `/etc/stargate/keys/dp.pub` (§3.1). `InsecureSkipVerify` is set
     ONLY if the chosen Java gRPC/TLS stack couples the knob to the custom
     verifier; the §4 comment is cited in the TLS-config code.
4. A `StargateProtoVersion` constants class declares `MAJOR=1`, `MINOR=0`,
   `CAPABILITIES="reload-tokens,watch-events,get-status-minimum"` per
   wire-auth.md §5.4. The CP server installs a gRPC server interceptor
   (unary + streaming) enforcing the §5.2 rejection rule. The
   `ReloadTokensClient` installs a client interceptor setting the three
   metadata keys on every call.
5. No TCP transport is configured for the inter-plane channel (wire-auth.md
   §4, arch §5.4). The CP uses `unix://` dial/listen addresses only.
6. Container validation (host has no JDK), from the repo root:
   ```
   STARGATE_SKIP_CP=0 bash scripts/verify.sh
   ```
   plus the contract gate:
   ```
   docker compose -f compose/docker-compose.local.yml config >/dev/null &&
   bash tests/contract/compose/inter_plane_wire_test.sh
   ```
   Expected today: structural tier PASS; runtime tier SKIP (T038 impl
   absent — the runtime gate lifts when T038 + T045 + T050 ALL land;
   see T095 §Notes for the R1-R8 FAIL-forcing gate that blocks the last
   impl ticket from completing with the runtime auth properties dark).

## Out-of-scope

- The wire-shape definition itself — that is T095's `contracts/wire-auth.md`,
  consumed verbatim here. If T038's implementer finds a gap in wire-auth.md,
  the fix lands in wire-auth.md (via a T095 rework round), NOT as a T038
  wire-shape invention.
- The DP-side server (`controlclient/server.go` hosting `ReloadTokens` +
  `GetStatus` on `dp.sock`) — T045.
- The DP main boot order (cert derivation at startup, listener open) — T050.
- Automated certificate rotation — deferred per wire-auth.md §6.2 and
  SECURITY-DECISIONS.md (T095 entry).
- TCP transport for the inter-plane channel — wire-auth.md §4.1 / §8
  (future feature, requires a major-version bump consideration).

## Notes

- T095 §Acceptance #5 mandates that this ticket consume the wire contract
  verbatim. The §Analysis + §Acceptance above reference wire-auth.md section
  numbers; no wire shape is restated here.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance refined 2026-07-12 against T095's `contracts/wire-auth.md`.
