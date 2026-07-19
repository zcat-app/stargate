---
id: T019a
title: 'Author `tests/integration/fake_socks5_tor.go`'
status: done
created: 2026-07-04
last_updated: 2026-07-05
source: tasks.md#T019a
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: { round: 2, date: 2026-07-05, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T019a: Author `tests/integration/fake_socks5_tor.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/integration/fake_socks5_tor.go` — synthetic SOCKS5 backend that mimics the Tor sidecar's accept-and-relay surface (research.md §7). Configurable modes: `accept-and-relay` (default — used by SC-005 load runs via T079), `slow` (used by T067 to trigger `ROUTE_TIMEOUT`), `hung` (reserved for negative leak-corpus tests). Pure Go, no docker-compose dependency. Apache 2.0 header.

## Analysis

Built at `/start` (privacy-critical: this synthetic backend stands in
for the Tor sidecar in load tests (T079 / T079a's 200-concurrent-
CONNECT run), cold-start survival tests (T020a), success-path log
invariants (T025a/b/d), and the ROUTE_TIMEOUT gate (T067/T067a/T067b).
A misbehaving fake that diverges from Tor's actual accept-and-relay
surface would let data-plane regressions slip through; a fake that
crashes under load would itself become the flake source). Grounded
against `contracts/socks5-auth.md`, `research.md §7`, and the seven
downstream consumers named in tasks.md (T020a, T025a, T025b, T025d,
T067, T067a/b, T079a).

### Must hold

- **M1 — Surface mimicry.** The fake exposes the same SOCKS5 surface
  the data plane dials in production: SOCKS5 (RFC 1928 + RFC 1929 for
  user/pass auth), `NO_AUTH=0x00` ONLY is rejected per Tor's behavior
  (Tor's SocksPort accepts USERNAME/PASSWORD purely for stream isolation
  and does not validate them; the fake matches — it accepts any
  USERNAME/PASSWORD sub-negotiation as success without inspecting the
  bytes). Critical: the fake MUST accept `ATYP=0x03` (DOMAINNAME) CONNECT
  requests because `.onion` destinations come in as domain strings
  (FR-003 SOCKS5h; data plane never resolves `.onion` locally per
  Principle III).
- **M2 — Three configurable modes (per tasks.md T019a).**
  - `accept-and-relay` (default): complete the SOCKS5 handshake, return
    `REP=0x00` success, then bidirectionally pipe bytes between the
    client and an in-memory upstream. The "echoes back a known byte
    pattern" wording in research.md §7 is operationalized as: each
    direction carries whatever bytes the peer writes; consumers
    asserting echo behavior send a known pattern themselves and read
    it back. (The fake is a byte-pipe, not a hardcoded echo responder;
    this is what T025b's "every byte round-trips unmodified" and
    T079a's "interleaved frames in both directions" require.)
  - `slow`: handshake proceeds through method selection + RFC 1929
    sub-negotiation + CONNECT request, then the fake delays the BND
    reply (the SOCKS5 success reply) by a configurable latency
    (WithLatency, default sized to exceed the data plane's 30 s
    dial-and-handshake deadline per `contracts/socks5-auth.md §"Deadlines"
    row 193). The delay lands BEFORE writeReply so the data plane's
    ROUTE_TIMEOUT fires; placing it after writeReply would only delay
    the post-handshake byte pipe (row 194 marks that phase deadline-
    free / long-lived) and would never trigger `REP=0x06`. Consumers
    observe i/o timeout on the BND-reply read — this is the surface
    T067/T067a/T067b use to trigger the data plane's ROUTE_TIMEOUT.
  - `hung`: the SOCKS5 handshake itself never completes — the fake
    accepts the TCP connection and reads the client's greeting but
    never writes the method-selection reply. Reserved for negative
    leak-corpus tests; consumers terminate via their own context
    deadline.
- **M3 — Stream-isolation mimicry.** The fake allocates a logical
  "circuit id" per DISTINCT SOCKS5 username (mirroring Tor's
  `IsolateSOCKSAuth` SOCKS5-isolation flag, which is on by default in
  the rendered torrc per `contracts/torrc.md`). The fake exposes the
  observed username set via an accessor (e.g. `CircuitIDs()`) so
  T059/T060/T061 integration tests can assert that distinct SOCKS5
  usernames map to distinct logical circuits at the upstream side.
  (T059/T060/T061 are NOT T019a-blocked — they target the live Tor
  sidecar via the control port — but the fake's `CircuitIDs()` keeps
  the API symmetric with the real sidecar for any future synthetic-
  only variants.)
- **M4 — Pure Go, no docker-compose dependency.** The fake brings up
  its own `net.Listener` on a kernel-assigned port (loopback-only by
  default) and runs in the test process. No external process spawn, no
  container requirement. Consumers (T020a in `tests/contract/control-
  grpc/`, T025a in `tests/contract/socks5/`, T067 in `tests/contract/
  error-template/`, T079a in `tests/integration/`) import the package
  directly.
- **M5 — Concurrency-safe under load.** T079a drives 200 concurrent
  CONNECTs against the fake; the fake MUST serialize no per-connection
  state under a global lock (per-connection state under a per-conn
  mutex is fine; the `CircuitIDs()` accessor may take a brief global
  read lock). A deadlock or HoL block in the fake would manifest as a
  spurious failure in T079a and mask a real data-plane regression.
- **M6 — Clean shutdown.** `Close()` stops the listener, signals
  in-flight handler goroutines to terminate via context cancellation,
  and returns only after all goroutines have exited (or a short
  bounded grace period). Goroutine leaks across repeated `Start` /
  `Close` cycles would accumulate under `go test -count=N` and surface
  as flake.
- **M7 — Apache 2.0 SPDX header** in the first 15 lines (per
  `scripts/check-license-headers.sh`, gated by verify gate 1).

### Gated

- M7 license header: gated by verify gate 1 (check-license-headers.sh
  scans `*.go`).
- Go vet / gofmt / staticcheck / gosec: gated by verify gate 2 ONLY
  for files under `data-plane/`. **The fake lives under
  `tests/integration/` — verify gate 2 does NOT cover it.** T076
  later wires `tests/integration/` into CI as a separate workflow;
  until then, the fake is hand-validated in a throwaway
  `golang:1.26.3-bookworm` container at `/start` (gofmt + go vet +
  go test -race against the self-test). The self-test
  (`fake_socks5_tor_test.go`) is the regression gate.
- Self-test pass: `tests/integration/fake_socks5_tor_test.go`
  exercises all three modes against a real SOCKS5 client
  (`golang.org/x/net/proxy`) and asserts: (a) `accept-and-relay`
  round-trips bytes bidirectionally and records the username for
  `CircuitIDs()`; (b) `slow` delays the first upstream write past a
  control deadline; (c) `hung` never completes the handshake before
  the client's deadline. Plus a concurrency case: 50 parallel
  CONNECTs with distinct usernames → `CircuitIDs()` reports 50
  distinct entries.

### Residue

- **R1 — No real-Tor behavioral parity claim.** The fake mimics the
  SOCKS5 *surface*, not Tor's circuit-building, cell-level encryption,
  or consensus-tracking. Any data-plane property that depends on Tor-
  internal behavior (e.g. T070a's mid-stream CLOSECIRCUIT handling,
  SC-001's real-onion load) requires the live sidecar; the fake is
  out of scope for those tests. T019a's `§Out-of-scope` records this.
- **R2 — Stream-isolation mimicry is approximate.** Tor's
  `IsolateSOCKSAuth` also keys on other tokens (client addr, auth-
  ctx) under specific configurations; the fake keys ONLY on the
  SOCKS5 username. A data-plane regression that depended on the
  wider key set would slip past T019a. Mitigation: the live-side
  integration tests (T059/T060/T061) are the authoritative gate;
  T019a's `CircuitIDs()` is symmetric for symmetry's sake.
- **R3 — `hung` mode leaks the accepted connection until `Close()`.**
  By design (consumer kills via context deadline; the kernel keeps
  the accepted socket until the fake shuts down). If a future
  consumer spawns thousands of `hung`-mode fakes, fd exhaustion is
  possible. Mitigation: `Close()` terminates all in-flight hung
  connections; documented in the package doc. Not a follow-up ticket
  unless T019a's consumers actually hit this.
- **R4 — Self-test uses `golang.org/x/net/proxy` SOCKS5 client,
  which sets `NO_AUTH=0x00` only by default.** The fake must accept
  `NO_AUTH` (unlike the data plane, which rejects it per
  `contracts/socks5-auth.md`); otherwise the self-test fails at
  method negotiation. The fake is the *upstream* (Tor stand-in), not
  the data plane; Tor's SocksPort also accepts `NO_AUTH` connections
  without isolation. The contract's `NO_AUTH` rejection is a DATA-
  PLANE property, not a sidecar property — T023/T028 gate it there.

## Acceptance

T019a ships library code + a self-test. No contract test in
`tests/contract/` lands under T019a (the existing contract gate scans
`tests/contract/*/*_test.sh`, not Go files in `tests/integration/`).

### Named tests

1. **NEW: `tests/integration/fake_socks5_tor_test.go`** — self-test
   exercising all three modes against a real SOCKS5 client
   (`golang.org/x/net/proxy`). Cases:
   - **(a) `accept-and-relay` round-trip**: Start the fake in
     `AcceptAndRelay` mode; connect a SOCKS5 client; perform
     USERNAME/PASSWORD sub-negotiation; issue a CONNECT to a
     `.onion`-style domain (ATYP=0x03); read SOCKS5 success
     (`VER=0x05 REP=0x00 RSV=0x00 ATYP=0x01 BND.ADDR=0.0.0.0
     BND.PORT=0`); write `2 * N` bytes of a known pattern; read them
     back unmodified; assert `CircuitIDs()` returns exactly one entry
     matching the USERNAME sent.
   - **(b) `slow` triggers handshake-phase deadline**: Start the fake
     in `Slow` mode with a 500 ms pre-BND-reply latency; connect via
     raw TCP + hand-driven SOCKS5 (proxy.SOCKS5 does not expose per-
     phase deadlines); complete method negotiation + RFC 1929 sub-
     negotiation + CONNECT request; set a 50 ms handshake-phase read
     deadline; assert the BND-reply read returns `i/o timeout`
     (proving the Slow delay is observable at the dial-and-handshake
     deadline the data plane translates to ROUTE_TIMEOUT — T067's
     `REP=0x06` gate depends on this).
   - **(c) `hung` blocks the handshake**: Start the fake in `Hung`
     mode; connect; write the SOCKS5 greeting; set a 50 ms read
     deadline; assert the read returns `i/o timeout` (no method-
     selection reply was ever written).
   - **(d) concurrency**: Start the fake in `AcceptAndRelay` mode;
     open 50 parallel SOCKS5 CONNECTs with 50 distinct USERNAMEs;
     each connection round-trips a known pattern; assert all 50
     round-trip; assert `CircuitIDs()` returns 50 distinct entries.

2. **NEW: `tests/integration/go.mod`** — module declaration so the
   package compiles standalone. Module path:
   `github.com/zcat-app/stargate/tests/integration`. Requires
   `golang.org/x/net` (for the SOCKS5 client used in the self-test).
   Added to `go.work`.

3. **NEW: `tests/integration/fake_socks5_tor.go`** — the library.
   `package integration`. Exported API:
   ```go
   type Mode int
   const (
       AcceptAndRelay Mode = iota  // default
       Slow
       Hung
   )
   type Server struct { /* unexported */ }
   func NewServer(mode Mode, opts ...Option) *Server
   type Option func(*config)
   func WithLatency(d time.Duration) Option      // Slow mode: first-write delay
   func WithListenAddr(addr string) Option       // default "127.0.0.1:0"
   func (s *Server) Start() (addr string, err error)
   func (s *Server) Close() error
   func (s *Server) CircuitIDs() []string        // observed SOCKS5 usernames
   ```

### Behavioral assertions (PR-time verification at `/start`)

- File at `tests/integration/fake_socks5_tor.go`, `package integration`,
  Apache 2.0 SPDX header in first 15 lines.
- `tests/integration/go.mod` present and added to `go.work`.
- All three modes implemented per §Analysis M2.
- SOCKS5 server accepts ATYP=0x03 (DOMAIN) requests (FR-003 SOCKS5h).
- SOCKS5 server accepts ATYP=0x01 (IPv4) requests (parity with Tor's
  SocksPort which accepts both forms).
- SOCKS5 server accepts both NO_AUTH (`0x00`) and USERNAME/PASSWORD
  (`0x02`) at method negotiation (the data plane is the AUTH gate, not
  the upstream sidecar; R4).
- USERNAME/PASSWORD sub-negotiation always succeeds (`0x01 0x00`) —
  the fake does not validate credentials (Tor's SocksPort uses them
  only for stream isolation, not auth).
- `accept-and-relay` relays bytes bidirectionally with no
  insertion/deletion/reordering/rewriting (T025b's byte-pipe
  invariant is what this fake lets consumers test FOR THE DATA PLANE;
  the fake itself must be byte-transparent).
- `CircuitIDs()` returns the observed SOCKS5 USERNAMEs (M3).
- `Close()` terminates listener + in-flight goroutines (M6).

### Runnable command

```
# Validate in a throwaway container (no Go toolchain on host):
docker run --rm -v "$PWD":/src -w /src golang:1.26.3-bookworm \
  sh -c 'cd tests/integration && go test -race -v ./...'

# Repo gate:
scripts/verify.sh
```

Expected after T019a lands: verify PASS=8 SKIP=2 FAIL=0 (the self-test
runs only inside the container validation; verify gate 2 is scoped to
`data-plane/` so tests/integration is not yet auto-gated — T076 wires
it). License-headers gate still PASS (new `.go` file carries SPDX).

## Out-of-scope

- **Do NOT mimic Tor's circuit-building, cell-level encryption, or
  consensus-tracking.** The fake is a SOCKS5 byte-pipe that mimics the
  *surface* of Tor's SocksPort, not Tor's internals. R1.
- **Do NOT implement Tor control-port surface.** T059/T060/T061/
  T070a use the *live* Tor sidecar's control port via the cookie-
  auth helper at T062; the fake does not expose a control port.
  `CircuitIDs()` returns the observed SOCKS5 usernames as a
  best-effort proxy for stream-isolation assertions; the live-side
  circuit-status check is the authoritative gate.
- **Do NOT validate bearer tokens at the fake.** The fake is the
  *upstream* (Tor stand-in). Bearer-token auth is the DATA PLANE's
  job (contracts/socks5-auth.md §"Username/password sub-negotiation");
  the fake accepts any USERNAME/PASSWORD sub-negotiation as success
  because Tor's SocksPort does the same (PASSWORD bytes are stream-
  isolation tokens, not credentials, at the upstream layer).
- **Do NOT wire `tests/integration/` into CI yet.** T076 owns the CI
  workflow authoring. T019a ships the library + self-test; T076 adds
  the path filter that runs `go test` under `tests/integration/` on
  PRs touching `data-plane/`.
- **Do NOT implement stream-isolation keying beyond the SOCKS5
  username.** Tor's `IsolateSOCKSAuth` keys on additional tokens under
  specific configurations; the fake keys ONLY on USERNAME. R2; the
  live-side integration tests are the authoritative gate for the full
  key set.
- **Do NOT add the fake to verify.sh gate 2.** Gate 2 is scoped to
  `data-plane/` for the v1 PR cadence; widening it to `tests/` is a
  scope decision owned by T076 / T080.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
