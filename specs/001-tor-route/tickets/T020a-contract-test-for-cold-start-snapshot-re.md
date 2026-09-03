---
id: T020a
title: 'Contract test for cold-start snapshot restore (Principle II survival; '
status: done
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T020a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T046, T090, T092, T093]
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/data-model.md §1.4 (dp-snapshot.json schema v2; stale-v1 ignored)
  - specs/001-tor-route/data-model.md §1.5 (HMAC-SHA-256 verifier under the shared pepper)
  - specs/001-tor-route/data-model.md §2 (no CP-driven admission; upstream dial is the sole ground truth)
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents" (backoff; events advisory — never gate admission)
  - specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" (byte-exact ROUTE_DOWN reply)
  - specs/001-tor-route/spec.md FR-013 (last-known token list survival)
  - specs/001-tor-route/spec.md FR-009 (upstream dial alone decides success or route error)
  - specs/000-architecture/spec.md §5.5 (control plane down at startup)
decision_refs:
  - SECURITY-DECISIONS.md §"Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)"
reviews: { round: 1, date: 2026-09-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T020a: Contract test for cold-start snapshot restore (Principle II survival; 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for cold-start snapshot restore (Principle II survival; FR-013 last-known-token-list invariant) in `tests/contract/control-grpc/cold_start_snapshot_test.go` — pre-populate `dp-snapshot.json` (data-model.md §1.4 shape) with a single known `{hash, salt}` for a known plaintext, boot the DP **with no CP reachable** (CP container stopped, or `/run/stargate/control.sock` absent), open an authenticated SOCKS5 CONNECT to port 8881 with the matching plaintext as the password against `fake_socks5_tor.go` (T019a, `accept-and-relay` mode); assert (a) the DP authenticates the request from the snapshot-restored generation; (b) the DP retries the `WatchEvents` dial with the exponential backoff schedule from `contracts/control-grpc.md` §"WatchEvents" but does NOT block port 8881 from serving during the wait; (c) once the CP comes up and pushes a new `ReloadTokens` generation, the DP atomic-swaps and the previous snapshot's plaintext is no longer honoured (proves the snapshot is a *cold-start cache*, not a persistent fallback layer beyond the current generation); (d) with no `HEALTHY` event ever arriving, the request-phase forward path **forwards through the reachable fake Tor upstream** (bridge engages; admission is not CP-gated — data-model.md §2; Constitution Principle II; sol-review B3); a separate sub-case with an **unreachable** upstream returns the SOCKS5 `ROUTE_DOWN` reply per `contracts/socks5-auth.md` §"SOCKS5 request-phase failures (post-auth)" — byte-exact `05 03 00 01 00 00 00 00 00 00`, then close, with no leaked reason text — proving the upstream dial alone decides success or the privacy-safe route error. Pairs with T046 (write path), T050 (boot sequence) and T073 (advisory event consumption).

## Analysis

Analyze gate (required: `privacy_critical: true` — the test drives the
bearer-token auth surface from persisted verifier material). Verified on
disk: `data-plane/internal/controlclient/snapshot.go` (T046: `RestoreSnapshot`
warns + ignores stale v1 / corrupt shapes, never fails the boot),
`data-plane/internal/listener/socks5.go` (T042), `data-plane/internal/
controlclient/server.go` + `client.go` (T045), `tests/integration/
fake_socks5_tor.go` (T019a `AcceptAndRelay`), the `tests/contract/internal/`
harnesses. NOT on disk: `data-plane/cmd/stargate-proxy/main.go` (T050,
pending) and `data-plane/internal/forward/tor.go` (T047, pending) — the
suite content-gates and self-skips until they land (the established
tests-first pattern of this package; T020/T021 skip identically today).

- **Property map (must-hold → gate)**
  - Cold start with the CP unreachable serves port 8881 from the
    snapshot-restored generation; the snapshot's plaintext authenticates,
    a never-loaded one does not (FR-013; arch §5.5; Principle II).
    → Caught by: new `TestColdStartSnapshotRestore/
    RestoresSnapshotWithCPUnreachable`.
  - The restored generation NUMBER is live, not just the verifier set:
    a `ReloadTokens` proposal equal to the snapshot's generation is
    STALE with `current_generation` echoed (§1.3; T092 reconciliation).
    → Same sub-test (stale-probe leg).
  - The WatchEvents dial failing at cold start is non-fatal and blocks
    nothing: port 8881 keeps authenticating across ≥2 backoff steps
    (contracts/control-grpc.md §"WatchEvents"; Principle II). Schedule
    precision (1s/30s/±20%) is client-unit-test territory (controlclient
    package, injected rng) + T021 row 3's live reconnect.
    → Caught by: `Port8881ServesDuringWatchEventsBackoff`.
  - The snapshot is a cold-start CACHE, not a fallback layer: a fresh
    generation pushed after boot atomic-swaps and the snapshot's
    plaintext stops authenticating (§1.3 replacement semantics).
    → Caught by: `NewGenerationReplacesColdStartSnapshot`.
  - Admission is never CP-gated: with NO `HEALTHY` event ever arriving
    (no CP at all), a request-phase CONNECT forwards through a reachable
    upstream (REP `0x00` + echo round-trip proves the bridge engages)
    (data-model.md §2; FR-009; Principle II; sol-review B3).
    → Caught by: `ForwardsWithoutHealthyEvent` (gated additionally on
    T047 `forward/tor.go`).
  - The upstream dial alone decides the route error: unreachable
    upstream → byte-exact `05 03 00 01 00 00 00 00 00 00`, then close,
    zero trailing bytes — no reason text, no template bytes on the
    SOCKS5 path (contracts/socks5-auth.md §"SOCKS5 request-phase
    failures (post-auth)"; FR-009).
    → Caught by: `RouteDownByteExactWhenUpstreamUnreachable` (T047-gated).
  - A stale `schemaVersion: 1` snapshot is ignored, never misparsed:
    warning journaled, NO tokens served until the CP pushes a fresh
    generation (§1.4 T092 amendment; SECURITY-DECISIONS T092 entry).
    → Caught by: `StaleV1SnapshotIgnoredServesNoTokens`.
  - No secret reaches the journal: verifier bytes and plaintexts are
    absent from every captured log, in every sub-test.
    → Caught by: `assertNoSecretLeak` after each sub-test (loginvariants
    scanner — raw/hex/base64 encodings).
- **Residue (no gate catches)** — (1) runtime correctness against the
  real boot wiring first exercises when T050 lifts the content gate;
  T050's review must run this suite green. (2) WatchEvents retry
  liveness against a *TLS-capable* fake CP is unobservable in this
  harness (the established fake CP is plain gRPC; the DP client requires
  wire-auth §4 TLS) — the schedule stays pinned client-side; integration
  residue lands with T038/T050. (3) Real-network behaviour (live Tor) is
  live-e2e territory by doctrine, not contract-test scope.

## Acceptance

Named sub-tests under `TestColdStartSnapshotRestore` in
`tests/contract/control-grpc/cold_start_snapshot_test.go` (package
`controlgrpc`, same harness as T020/T021). All plaintexts are 32-char
lowercase hex (FR-017 format gate — the auth path rejects anything
else); the seeded snapshot is schemaVersion 2 carrying the base64
HMAC-SHA-256 tag minted under the harness pepper (data-model.md §1.4/§1.5,
T092 — superseding the task body's pre-T092 `{hash, salt}` wording).

1. `RestoresSnapshotWithCPUnreachable` — seed `dp-snapshot.json`
   (generation 7, single verifier for plaintext P1), boot the harness
   with NO `control.sock`; journal records the restore; SOCKS5 auth:
   P1 passes, P2 (never loaded) fails; a `ReloadTokens` push at
   generation 7 returns `APPLY_STATUS_STALE_GENERATION` with
   `current_generation = 7` (the restored generation is live).
2. `Port8881ServesDuringWatchEventsBackoff` — same cold boot with the
   inter-plane key material seeded (`dp.priv`/`cp.pub` per tls.go, so
   the WatchEvents client actually runs); the degraded-mode warning
   appears; auth probes succeed continuously across ≥2 backoff steps —
   the retry wait never blocks port 8881.
3. `NewGenerationReplacesColdStartSnapshot` — from the cold-start state,
   the CP role pushes generation 8 {P2} over `dp.sock` (the production
   ReloadTokens path, exactly as T020's harness does): P2 authenticates,
   P1 stops authenticating, and `dp-snapshot.json` is rewritten to
   generation 8 carrying P2's verifier (cold-start cache, not a
   persistent fallback).
4. `ForwardsWithoutHealthyEvent` — cold boot from the snapshot with a
   reachable `fake_socks5_tor` (`AcceptAndRelay`) upstream and no CP
   ever: authenticated CONNECT returns REP `0x00` and an echo round-trip
   succeeds (bridge engages; admission not CP-gated).
5. `RouteDownByteExactWhenUpstreamUnreachable` — same cold boot, no
   upstream override (`tor:9050` unreachable in the hermetic env):
   authenticated CONNECT receives exactly `05 03 00 01 00 00 00 00 00
   00`, then EOF with zero further bytes (no reason text, no template).
6. `StaleV1SnapshotIgnoredServesNoTokens` — seed a `schemaVersion: 1`
   `{hash, salt}` snapshot: boot warns ("snapshot restore ignored"), NO
   plaintext authenticates; a fresh generation-1 push then applies and
   its plaintext authenticates (serve-no-tokens **until the CP pushes**).

Harness: `startDPWithSeed` added to `dpharness_test.go` (one choke
point) — the existing `startDPWithUpstream` plus a `seed(stateDir,
keysDir)` callback invoked after pepper write, before `cmd.Start()`;
`startDPWithUpstream` delegates with nil. Runnable:
`go test ./tests/contract/control-grpc/ -run TestColdStartSnapshotRestore -v`
from repo root; `bash scripts/verify.sh` green. Sub-tests 4–5
additionally gate on T047 (`requireForwardPath`) and the whole suite on
T050 (harness boot gate) — skips self-lift, per package precedent.

## Out-of-scope

- Warm plane-down survival (CP stopped AFTER a live `ReloadTokens`) —
  the "Plane-down survival" row of contracts/control-grpc.md §"Transport
  invariants"; T022's `transport_test.go` scope. This ticket is cold
  start (CP down before boot).
- Backoff-schedule arithmetic (1s initial, 30s cap, ±20% jitter) —
  controlclient unit tests with injected rng; T021 row 3 owns the live
  reconnect-timing window.
- Snapshot write-path fidelity (shape, atomic rename, persist-failure) —
  T020 / T046 suites.
- The v1 → v2 migration (v1 is ignored, never migrated — §1.4) and any
  CP-side (Java) push implementation — T038.
- Boot-sequence implementation itself — T050 (this suite is one of its
  verification gates).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**Done record (2026-09-03).** Round-1 `stargate-codereview`: **APPROVE**
(1 Minor — recorded below, not blocking). All six §Acceptance sub-tests
verified against the already-implemented units (snapshot.go, server.go,
client.go, token.go, socks5.go, tls.go), each with a named non-vacuity
mutation the test would catch. Suite compiles and self-skips on the
T050/T047 content gates per the acceptance's own design.
- **r1 Minor (determinism; T050-lifetime):** the two T047-gated route
  sub-tests (`ForwardsWithoutHealthyEvent`,
  `RouteDownByteExactWhenUpstreamUnreachable`) should call
  `t020aWaitRestored` after boot before their first auth probe, matching
  sub-tests 1/3/6. Cannot produce a wrong pass and cannot manifest until
  T050 lifts the gate; apply alongside the T050-lift reconciliation
  (a code change, so not an APPLY-FIXES item — recorded, not self-applied
  post-APPROVE).
- **Follow-ups surfaced (outside this diff — file as tickets):**
  (a) the harness `reload` dial (dpharness_test.go) carries no §5.3
  `x-stargate-proto-*` metadata, so the implemented server interceptor
  rejects every harness ReloadTokens call once T050 lifts — fold into
  T022/T050; (b) sibling T020/T021 fixtures authenticate non-hex
  plaintexts the implemented FR-017 format gate rejects — those suites
  fail on first real run; this ticket's 32-hex fixtures are the fix
  pattern.

**T092 amendment (2026-07-15).** The snapshot shape this test must assert
changed: `dp-snapshot.json` is now `schemaVersion: 2` carrying
`verifiers[]` (32-byte HMAC-SHA-256 tags), NOT the v1 `hashes[]` of
`{hash, salt}` pairs, and NEVER the pepper (`specs/001-tor-route/data-model.md`
§1.4). A cold-start read of a stale `schemaVersion: 1` snapshot MUST be
ignored (log a warning, serve no tokens until the CP pushes a fresh
generation) rather than misparsed — add a sub-test for that. The cold-start
Principle-II property under test (DP serves from snapshot when CP is
unreachable) is unchanged.
