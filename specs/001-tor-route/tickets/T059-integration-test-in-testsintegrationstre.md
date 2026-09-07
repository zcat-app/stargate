---
id: T059
title: 'Integration test in `tests/integration/stream_isolation_test.go`'
status: pending
created: 2026-07-04
last_updated: 2026-09-07
source: tasks.md#T059
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062]   # manual edge: circuit IDs are asserted via the T062 control-port helper (derive-deps missed prose deps; tightened 2026-09-07). Implementation note: tests/integration is a separate Go module, so the helper's FUNCTION re-lands here as the T033 exec/nc probe pattern; the dependency satisfied is the probe capability, not an import.
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md §"User Story 2 - Stream isolation per first-party domain" acceptance scenario 1   # primary anchor: two parallel CONNECTs, two distinct .onion destinations, per-request usernames → distinct circuit IDs at the control port
   - specs/001-tor-route/spec.md#FR-002   # username = first-party domain; "a privacy-critical test MUST verify that distinct first-party domains produce distinct Tor circuits in the running stack"
   - specs/001-tor-route/spec.md#FR-007   # DP forwards via SOCKS5h to tor:9050; inbound UNAME is the IsolateSOCKSAuth key (forward/tor.go dialUpstream sends it verbatim)
   - specs/001-tor-route/contracts/socks5-auth.md   # UNAME=first-party domain / PASSWD=bearer token mapping the test's SOCKS5 handshake must reproduce
   - specs/001-tor-route/contracts/torrc.md §"isolate_socks_auth_effect_test.go"   # tor-level isolation contract (T058) this test re-proves end-to-end through port 8881
   - specs/001-tor-route/tasks.md#T059   # source body
decision_refs:
   - .specify/memory/constitution.md#Principle-VII   # tests-first: FR-002's privacy-critical test clause; the named test IS the deliverable
   - .specify/memory/constitution.md#Principle-III   # the test drives only the routed path (8881 → DP → tor:9050); control-port reads ride the compose-internal channel
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T059: Integration test in `tests/integration/stream_isolation_test.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test in `tests/integration/stream_isolation_test.go` — through port 8881 (not directly against the sidecar), issue parallel CONNECTs to two distinct `.onion` targets with different SOCKS5 usernames; assert distinct circuit IDs at the control port. (Spec US2 acceptance scenario 1.)

## Analysis

**Required** — `privacy_critical: true`. Property map per
`docs/process/analysis.md`.

### Goal restated for grounding

Bring up the full local-profile stack (`compose/docker-compose.local.yml`),
seed a run-time-generated bearer token into the stack (FR-017 shape), wait
for Tor bootstrap, then issue **two parallel** SOCKS5 CONNECTs **through the
data plane's host-published loopback port 8881** to two distinct, real
`.onion` destinations — UNAME = each target's own onion address (the
first-party domain per FR-002's top-level-navigation rule), PASSWD = the
bearer token per contracts/socks5-auth.md — hold both streams open, and
assert via the cookie-authenticated Tor control port that the two streams
attached to **distinct, non-zero circuit IDs**, each cross-checked BUILT in
`GETINFO circuit-status`. This is US2 acceptance scenario 1: the end-to-end
re-proof, through the DP, of the isolation T058 pins at the torrc level.

### Grounding facts (verified on disk / live, 2026-09-07)

- `tests/integration` is a **separate Go module** from `tests/contract`
  (own `go.mod`), so the T062 helper cannot be imported. Its *function*
  re-lands in-module as T033's exec/nc control-port probe pattern
  (`onion_load_test.go` t033BootstrapProbe/t033CircuitStatusProbe shape),
  extended with a `GETINFO stream-status` probe (the 4-field
  `<StreamID> <Status> <CircID> <Target>` line, matched by target string
  and counted exactly — T058a's `ulStreamsAtTarget` machinery re-implemented).
- The DP forwards the inbound UNAME **verbatim** as the upstream SOCKS5
  username with an empty password (`data-plane/internal/forward/tor.go`
  `dialUpstream`; FR-007 comment: "the US2 IsolateSOCKSAuth key"). The
  inbound PASSWD (bearer token) is auth-layer material and is never
  re-sent upstream. So distinct inbound UNAMEs ⇒ distinct upstream
  credentials ⇒ tor's image-baked `IsolateSOCKSAuth` builds distinct
  circuits — the exact chain under test.
- Both targets must be **real, reachable v3 onion services**: scenario 1
  asserts circuit IDs *for the two streams* (stream-level attribution), and
  a synthetic `.example.onion` never attaches a stream — the descriptor
  fetch fails before rendezvous (T058a live evidence). The spec's
  synthetic-corpus allowance (§"out of scope": "reachability is not
  required") serves T061's SC-002 string sweep, not stream-level
  attribution, and is not relied on here.
- **Second target provenance.** The spec pins only DuckDuckGo. The second
  destination is `shr6xwb55x7q4atmwjohlo4op6lxogpl5do26ptpoo2cf6hg3tsuqzad.onion`
  (port 80) — **operator-supplied 2026-09-07**, v3-shape valid
  (`^[a-z2-7]{56}\.onion$`), and live-verified during this grounding: raw
  SOCKS5 CONNECT through a throwaway `stargate/tor:local` sidecar returned
  REP=0 (rendezvous complete, stream attached). The test live-verifies both
  targets on every run — a dead address fails loudly at CONNECT, never as a
  false green. Per the spec's DuckDuckGo note, an unreachable pinned target
  is fixed by updating the harness and recording the change in
  `SECURITY-DECISIONS.md` (NYT's onion was rejected: service shut down
  2025-03; TPO's self-published `2gzyxa5…wid.onion` is the documented
  fallback candidate).
- **Token self-provisioning.** T033's residue anticipated a fixture
  replacing `STARGATE_TEST_TOKEN` "when T035/T038 land" — both are done.
  The test generates its own 32-hex token (`crypto/rand`), writes
  `tokens.yaml` (FR-017 shape: `tokens: [- label, token]`) into the
  project-scoped `stargate-control-config` volume via a short-lived
  container from the already-built `stargate/tor:local` image (no external
  pull), restarts `stargate-control`, and lets the request-retry window
  absorb the CP's argon2id load + `ReloadTokens` push to the DP. The token
  lives only in run-time memory/pipe; never in source, argv, or logs.

### Must hold

- Both CONNECTs traverse the full vertical: host test → `127.0.0.1:8881`
  (host-published DP loopback) → DP → `tor:9050` → Tor network → onion
  service. Direct-to-sidecar dialing (the T058a transport) would not test
  the DP hop and is out of scope here.
- The two CONNECTs are issued **in parallel** (concurrent, barrier-start),
  per scenario 1's "in parallel".
- Each CONNECT carries SOCKS5 user/pass auth with UNAME = its target's
  onion address and PASSWD = the seeded bearer token
  (contracts/socks5-auth.md). Reversed mapping would fail auth (token in
  UNAME is ignored) or isolation (first-party in PASSWD is not the
  IsolateSOCKSAuth key).
- Asserted at the control port: per-target `GETINFO stream-status` CircIDs
  are non-zero and **distinct**; each reported circuit exists with status
  BUILT in `GETINFO circuit-status` (stream-level and circuit-level
  surfaces agree — T058a parity). A shared circuit across distinct
  first-party usernames is FR-002 broken at runtime and must FAIL the test.
- Control-port access is cookie-authenticated, inside the tor container
  only (FR-012: 9050/9051 never host-published; `find` for the cookie per
  the T087 DataDirectory note).
- No token or destination-identifying material in test-emitted logs beyond
  what the pinned targets already are (targets are test constants, not
  secrets); the generated token is never logged.

### Gated (no standing human vigilance needed)

- License-header gate + `go vet`/gofmt via the go-workspace gate compile
  and vet this file every PR (hermetic run env-skips the live body).
- T058 gates the torrc isolation flags; T058a pins the NO_AUTH share
  behaviour; T019b gates tor-port non-exposure; T025a gates DP log
  restraint. This test adds the missing runtime gate for the full-vertical
  hop (Principle VII: the named test is the promoted residue check).

### Residue

- **Live Tor network + both onion services reachable** (release-tag
  opt-in via `STARGATE_RUN_NETWORK_TESTS=1`; same cadence as T033).
  Environmental, not a contract gap; a dead target fails loudly.
- **Compose/volume mechanics of token seeding** (volume subpath write via
  short-lived container + CP restart). If compose semantics change, the
  seed step fails at run time (loud), and the hermetic gate still
  compiles the file.
- **`stream-status` line-shape parsing** (4-field control-spec line).
  A tor control-surface change breaks parsing loudly at poll time
  (short lines skipped, exact-count assertion gates the read).
- **N=2 only**: exactly-two-stream isolation could in principle degrade
  at larger N. T061's corpus sweep (SC-002, ≥95/100) covers that axis;
  deliberately not duplicated here.

## Acceptance

1. **Named test** `TestStreamIsolationPerFirstPartyDomain` in
   `tests/integration/stream_isolation_test.go`: brings up the full
   local-profile stack under project `stargate-t059-test`; self-provisions
   the bearer token (generated `crypto/rand` 32-hex, FR-017 `tokens.yaml`
   shape, CP restart, retry-until-pushed); waits for Tor bootstrap
   (PROGRESS=100 via the in-container probe); issues two **parallel**
   SOCKS5 CONNECTs through `127.0.0.1:8881` to
   `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443`
   and `shr6xwb55x7q4atmwjohlo4op6lxogpl5do26ptpoo2cf6hg3tsuqzad.onion:80`
   with UNAME = each target's own onion address and PASSWD = the seeded
   token; holds both streams; then asserts: (a) each target's
   `GETINFO stream-status` match set has exactly one live (non-terminal)
   stream with non-zero CircID; (b) the two CircIDs are **distinct**;
   (c) both circuits appear BUILT in `GETINFO circuit-status`. Failures
   name the broken link (auth / route / isolation) with tor log tail
   attached.
2. **Runnable (live, release-tag cadence):**
   `cd tests/integration && STARGATE_RUN_NETWORK_TESTS=1 go test -run TestStreamIsolationPerFirstPartyDomain -v -timeout 25m`
3. **Hermetic gate:** `bash scripts/verify.sh` green — the test compiles
   and vets in the go-workspace gate and env-skips its live body.

## Out-of-scope

- **Sibling tickets' assertions**: T060 (same first-party domain ⇒ SAME
  circuit — scenario 3) and T061 (100-string corpus ⇒ ≥95 distinct —
  SC-002). This ticket asserts only the two-distinct-targets scenario and
  touches only its own test file plus this ticket.
- **No production-code changes** (data plane, control plane, compose,
  torrc). If the live run exposes a DP forwarding bug, file a follow-up —
  the test pins the spec, and fixing the product is a different ticket.
- **No import of the T062 helper** (separate Go modules — see Analysis);
  the in-module exec/nc probe re-implementation follows the landed T033
  pattern.
- **No HTTP/TLS payload exchange**: CONNECT + hold only; page-load success
  is T033's assertion, not repeated here.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

- Second target provenance and the no-import rationale for the T062
  helper are recorded in §Analysis (grounding, 2026-09-07).
- Run in worktree `/home/claudia/stargate-t059` (branch `t059`) in
  parallel with T060/T061 sessions; lands on `001-tor-route` by
  cherry-pick, per the T058a worktree precedent.
