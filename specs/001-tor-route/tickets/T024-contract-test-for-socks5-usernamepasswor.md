---
id: T024
title: 'Contract test for SOCKS5 username/password sub-negotiation success (`0'
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T024
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
  - specs/001-tor-route/contracts/socks5-auth.md §"Username/password sub-negotiation"
  - specs/001-tor-route/spec.md §"FR-007"
decision_refs:
  - research.md §5 (Contract-test harness language — Go)
  - research.md §7 (synthetic SOCKS5 backend — fake_socks5_tor)
reviews: { round: 1, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T024: Contract test for SOCKS5 username/password sub-negotiation success (`0

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 username/password sub-negotiation success (`0x01 0x00`) and forwarding of `UNAME` verbatim into upstream SOCKS5 in `tests/contract/socks5/userpass_success_test.go` — per `contracts/socks5-auth.md` §"Username/password sub-negotiation".

## Analysis

T024 is tests-first (Constitution Principle VII) for T042
(listener RFC 1929 framing), T044 (argon2id token verification),
and T047 (forward path with UNAME passed verbatim to upstream).
The test self-skips until those land; the byte-exact contract below
is what their implementations get driven to satisfy.

- **Must hold:**
  - On RFC 1929 sub-negotiation success, the data plane replies
    EXACTLY `0x01 0x00` (RFC 1929 §2; `contracts/socks5-auth.md`
    §"Username/password sub-negotiation").
  - The reply is exactly 2 bytes; no extra bytes; the connection
    stays open and the DP proceeds to the SOCKS5 request phase
    (RFC 1928 §4). A `0x01 0x00`-then-close or a `0x01 0x00 <extra>`
    shape is a contract breach.
  - `UNAME` is parsed correctly across the full RFC 1929 length
    range (1–255 bytes). The framing correctness is observable via
    the success reply: if the listener misparsed `ULEN`, the password
    would land at the wrong offset and auth would fail (`0x01 0xFF`)
    instead of succeeding.
  - `UNAME` is forwarded VERBATIM to the upstream SOCKS5 connection
    as the upstream's SOCKS5 username (FR-007 — stream-isolation
    key). The data plane MUST NOT mutate, truncate, or drop UNAME.
    This is the property `IsolateSOCKSAuth` on the Tor side depends
    on for per-first-party circuit isolation (contracts/torrc.md).
  - `PASSWD` (the bearer-token plaintext) is verified via argon2id
    against the current generation with
    `crypto/subtle.ConstantTimeCompare`; the comparison MUST be
    constant-time across all stored hashes (data-model.md §1.5).
    Constant-time statistical properties are T025's scope; T024
    gates only the success/fail byte-shape dichotomy.
- **Gated:**
  - `tests/contract/socks5/userpass_success_test.go` (this ticket)
    is itself the fail-closed gate for the byte shapes above; once
    T042/T044 land the test flips SKIP → RED, driving the listener
    implementation.
  - The shared `tests/contract/internal/dpharness` package (T023)
    provides the DP-process boot surface; this ticket extends it
    with auth helpers (`MintToken`, `Reload`) and adds a `fakecp`
    package for hosting a fake control plane (to push HEALTHY).
  - `go vet` + `staticcheck` + `gosec` cover the syntactic / security
    surface (verify.sh gates 3–5).
- **Residue:**
  - Constant-time comparison latency distribution is not testable
    from userland at byte-shape granularity; T025 covers the
    statistical surface (slot-invariance under N≤4 stored hashes).
  - `UNAME` contents are not authenticated — any bytes 1–255 are
    accepted by the listener; the contract makes `UNAME` opaque to
    the auth layer (it is a stream-isolation key, not a credential).
    T024 does not constrain UNAME's contents, only its length
    (1–255) and verbatim forwarding.
  - The forward-path's actual dial to `tor:9050` is exercised via a
    synthetic upstream (`fake_socks5_tor.go` from T019a) on a
    loopback port pointed to by a new env var
    `STARGATE_TOR_SOCKS_ADDR`. The production default (`tor:9050`
    via compose DNS) is not under test here — it is gated by T019b
    (port exposure) and T032 (live sidecar contract).

## Acceptance

Named test in `tests/contract/socks5/userpass_success_test.go`,
package `socks5`:

- `TestUserpassSubnegotiationSuccess` with sub-cases:
  - (a) `AuthSuccess_ReplyIsExact_01_00`: preload one valid token
    via ReloadTokens; open a SOCKS5 connection to port 8881; do
    method negotiation (`05 01 02` → expect `05 02`); send RFC 1929
    sub-negotiation with the matching plaintext as PASSWD and a
    known UNAME; assert the reply is byte-exactly `01 00`. Then
    assert the connection is held open (no extra bytes, no close)
    — the DP must proceed to wait for the SOCKS5 request phase.
  - (b) `UNAME_LengthBoundaries`: same as (a) but with UNAME
    lengths 1, 16, and 255 bytes (the RFC 1929 range edges + a
    mid-range value). Each MUST yield `01 00` — pins the listener's
    ULEN parsing.
  - (c) `UNAME_ForwardedVerbatim`: with a fake upstream
    (`fake_socks5_tor.go` from T019a in `accept-and-relay` mode)
    pointed to by `STARGATE_TOR_SOCKS_ADDR`, AND a fake control
    plane hosting WatchEvents on `${ipcDir}/control.sock` that
    pushes a single HEALTHY event for `tor`, AND a valid token
    preloaded via ReloadTokens: open a SOCKS5 connection, do method
    negotiation, send RFC 1929 sub-negotiation with a distinctive
    UNAME (e.g. `t024-uname-marker-1234567890`), then a SOCKS5
    CONNECT to a target. Assert (1) sub-negotiation reply is `01 00`;
    (2) the fake upstream's `CircuitIDs()` snapshot contains the
    exact UNAME bytes — proving FR-007 verbatim forwarding end-to-end.
- Content-gate (per sub-test, narrowest viable gate):
  - (a)/(b) self-skip while `data-plane/internal/listener/socks5.go`
    (T042), `data-plane/internal/auth/token.go` (T044),
    `data-plane/internal/controlclient/server.go` (T045),
    `data-plane/cmd/stargate-proxy/main.go` (T050) are absent.
  - (c) additionally self-skips while
    `data-plane/internal/forward/tor.go` (T047),
    `data-plane/internal/controlclient/client.go` (T045 client side)
    are absent.
- Shared harness additions (in `tests/contract/internal/`):
  - `dpharness/auth.go` — `MintToken(t, plaintext)` (argon2id-hash
    a known plaintext under a fresh random salt; mirrors
    data-model.md §1.5 params) and `Reload(t, h, gen, tokens)` (gRPC
    ReloadTokens client wrapper). Extracted from the
    `control-grpc/dpharness_test.go` pattern; that file is
    deliberately NOT refactored (out of scope).
  - `dpharness/dpharness.go` — extend `Harness` with an
    `UpstreamAddr` option (`STARGATE_TOR_SOCKS_ADDR` env var; tests
    override the production `tor:9050` default) and a `BeforeBoot`
    callback (mirrors T021's `startDPWith`).
  - `fakecp/fakecp.go` — `Start(t, ipcDir)` hosting a programmable
    `Events` server on `${ipcDir}/control.sock` BEFORE the DP boots;
    `Send(ev)` to push `SidecarEvent`s (HEALTHY for route enable).
    Extracted from the watch_events_test.go pattern; that file is
    deliberately NOT refactored.
  - `tests/contract/go.mod` gains a replace directive for
    `github.com/zcat-app/stargate/tests/integration` so the test can
    import `fake_socks5_tor` from T019a.
- Runnable: `scripts/verify.sh` green (test self-skips on a tree
  without T042/T044/T045/T047/T050).

## Out-of-scope

- Constant-time comparison latency distributions and slot-invariance
  under the v1 N≤4 cost model — T025 (`leak_test.go`).
- `AUTH_REQUIRED` failure path (`0x01 0xFF` then close, no leak) —
  T028 (`auth_required_test.go`).
- Token-list snapshot persistence and cold-start restore — T020a
  (`cold_start_snapshot_test.go`).
- Counter side-channel (auth-pass must-increment vs auth-fail
  must-not-increment) — T025c / T025d.
- The production `tor:9050` compose-DNS resolution path — gated by
  T019b (port exposure) and T032 (live sidecar contract). T024 uses
  a synthetic upstream on loopback.
- Refactoring `tests/contract/control-grpc/dpharness_test.go` or
  `tests/contract/control-grpc/watch_events_test.go` to import from
  the new shared packages — filed as follow-up; those existing
  tests stay self-contained.

## Notes

The shared harness additions (`dpharness/auth.go`, `dpharness`
`UpstreamAddr`/`BeforeBoot`, `fakecp/fakecp.go`) are sized for
T024's needs but designed for reuse by the rest of the SOCKS5
contract family (T025, T025a, T025b, T025c, T025d, T026, T028) —
which all need some subset of (token push, fake upstream, fake CP).
Each follow-up ticket inherits the shared surface rather than
duplicating it; the residue shrinks per future ticket.

The new env var `STARGATE_TOR_SOCKS_ADDR` is the test-defined
choke point T047 / T050 must honour (mirrors the existing
`STARGATE_IPC_DIR`/`STATE_DIR`/`KEYS_DIR`/`LISTEN_ADDR` test-defined
interface authored in T020's `dpharness_test.go`). Production
default is `tor:9050` (compose DNS); tests override to a loopback
synthetic.
