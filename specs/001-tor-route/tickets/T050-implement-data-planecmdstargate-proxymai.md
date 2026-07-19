---
id: T050
title: 'Implement `data-plane/cmd/stargate-proxy/main.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-12
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

T050 is the **data-plane boot-order** ticket. The wire contract it consumes
at boot (cert derivation, peer-pin, version metadata) is binding in
`specs/001-tor-route/contracts/wire-auth.md` (completed by T095) — T050
consumes it verbatim and adds NO wire-shape detail of its own (T095
§Acceptance #5).

- **Must hold** —
  - Boot order is fixed: (1) `bind/check.go` loopback-only bind check
    (T013) FIRST; (2) load `dp-snapshot.json` (T046); (3) read
    `/etc/stargate/keys/dp.priv` and derive the self-signed Ed25519 X.509
    cert in-memory per wire-auth.md §2; (4) bring up the DP gRPC server
    on `dp.sock` (T045); (5) dial `control.sock` for `WatchEvents` (T045);
    (6) open the port-8881 listener (T042 + T043); (7) begin forwarding
    IMMEDIATELY — admission is NOT gated on a `SidecarEvent` (Principle II;
    data-model.md §2; sol-review B3; T090).
  - Cert derivation failures (unreadable `dp.priv`, parse error, cert-gen
    error) are degraded-mode warnings — the DP MUST keep routing port 8881
    (Principle II; arch §5.4; wire-auth.md §2.1). The cold-start path
    (arch §5.5) remains in effect for proxy traffic.
  - The DP MUST NOT resolve hostnames locally, parse payloads, or terminate
    TLS for proxy traffic (Constitution Principle I — dumb router).

- **Gated** —
  - `tests/contract/compose/inter_plane_wire_test.sh` (T095) lifts its
    runtime tier (R7 no-TCP, R8 plane-down survival) when T038 + T045 +
    T050 all land.
  - T020 (cold-start no-CP auth) and T033/T034 (end-to-end forwarding)
    gate the boot-order + admission-not-gated properties.

- **Residue** —
  - Cert validity (30-day window) and no-automated-rotation are
    operator-visible; recorded in THREAT-MODEL.md §5.13 + SECURITY-DECISIONS.md
    (T095 entry). T050 adds no residue beyond T095's.

## Acceptance

1. `main.go` runs the boot sequence in the order stated in §Analysis (bind
   check → snapshot → cert derivation → DP server up → CP dial → listener
   open → forward). The order is load-bearing: a regression that gates
   admission on `WatchEvents` or on a successful CP dial fails T090 and
   T020 (Principle II).
2. Cert derivation reads `/etc/stargate/keys/dp.priv` and produces the
   in-memory self-signed cert per `contracts/wire-auth.md` §2 (field values
   per §2.2: NotBefore = now − 5 min, NotAfter = now + 30 days, Ed25519
   sig, URI SAN `spiffe://stargate.local/dp`, ExtKeyUsage ServerAuth +
   ClientAuth). The cert is NEVER written to disk.
3. A cert-derivation failure logs a degraded-mode warning and the DP
   continues to boot the listener + forwarding path (Principle II).
4. The DP dials `control.sock` for `WatchEvents` with the §"WatchEvents"
   backoff; events are advisory. The listener on port 8881 accepts and
   forwards requests regardless of `WatchEvents` state.
5. No TCP transport for the inter-plane channel (wire-auth.md §4); `unix://`
   dial/listen only.
6. Container validation (host has no Go toolchain), from the repo root:
   ```
   docker run --rm -v "$PWD":/src -w /src/data-plane \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c 'gofmt -l . && go vet ./... && go test -race -count=1 ./...'
   bash tests/contract/compose/inter_plane_wire_test.sh
   ```
   Expected today: structural tier PASS; runtime tier SKIP (T050 impl
   absent — the runtime gate lifts when T038 + T045 + T050 ALL land;
   see T095 §Notes for the R1-R8 FAIL-forcing gate).

## Out-of-scope

- The wire-shape definition itself — T095's `contracts/wire-auth.md`,
  consumed verbatim. A gap found during impl lands as a wire-auth.md fix
  (T095 rework round), not a T050 invention.
- The DP gRPC server/client implementation (`server.go`, `client.go`) —
  T045. T050 wires them into the boot order.
- The CP-side server — T038.
- Automated certificate rotation — deferred per wire-auth.md §6.2 and
  SECURITY-DECISIONS.md (T095 entry).

## Notes

- T095 §Acceptance #5 mandates verbatim consumption. The §Analysis +
  §Acceptance reference wire-auth.md section numbers; no wire shape is
  restated here.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance refined 2026-07-12 against T095's `contracts/wire-auth.md`.
