---
id: T025b
title: 'Contract test for long-lived bidirectional CONNECT (Principle I byte-p'
status: done
created: 2026-07-04
last_updated: 2026-07-07
source: tasks.md#T025b
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 4   # long_lived_connect_test.go + this ticket; headroom for a review-driven harness/fake tweak
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"Edge Cases" (rows "WebSocket upgrade through CONNECT" and "HTTP/2 connections (forced fallback from QUIC)")
  - specs/001-tor-route/spec.md §"FR-005" / §"FR-006" (two inbound framings, one port; per-framing auth)
  - specs/001-tor-route/spec.md §"FR-007" (no parse/inspect/modify beyond SOCKS5 framing; username passed through unchanged)
  - specs/001-tor-route/spec.md §"FR-008" (no per-request journal surface)
  - specs/001-tor-route/contracts/socks5-auth.md §"Deadlines" (post-handshake deadline "none — long-lived")
  - specs/001-tor-route/contracts/socks5-auth.md §"HTTP CONNECT path" (request shape; 200 Connection Established then bridge)
  - specs/001-tor-route/contracts/socks5-auth.md §"Two inbound protocols, one port" (directory convention + demux)
decision_refs:
  - specs/001-tor-route/research.md §5 (contract-test harness language — Go) and §7 (synthetic SOCKS5 backend, not live Tor)
  - specs/001-tor-route/tickets/T025a-contract-test-for-socks5-success-path-lo.md (shared loginvariants allowlist is canonical; T025b is a named consumer)
  - redteam/findings/open/20260706-002-detail-rejected-echo-false-pass.md (echo-false-pass class — drives the upstream-transit assertion)
reviews: { round: 1, date: 2026-07-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T025b: Contract test for long-lived bidirectional CONNECT (Principle I byte-p

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for long-lived bidirectional CONNECT (Principle I byte-pipe invariant; spec §"Edge Cases" rows *WebSocket upgrade through CONNECT* and *HTTP/2 connections (forced fallback from QUIC)* — both mechanically subsumed: any TLS-over-CONNECT payload (H1, H2, WebSocket) is opaque bytes to the data plane after the SOCKS5/CONNECT handshake completes, so the byte-pipe transparency assertion covers all three protocol shapes without needing protocol-specific tests) — open an authenticated SOCKS5 *and* HTTP CONNECT through port 8881 to the `accept-and-relay` upstream from T019a; after handshake, exchange interleaved frames in both directions for ≥30s (mix of small / medium / large byte runs; asymmetric bandwidth; idle gaps up to 5s); assert (a) every byte round-trips unmodified — no insertion, deletion, reordering, or rewriting in either direction; (b) the data plane emits no log line for the frame traffic (the T025a shared allowlist applies); (c) the connection stays open until *either end* initiates close — the data plane MUST NOT close it due to inactivity, frame content, or size; (d) the same property holds whether the inbound framing was SOCKS5 or HTTP CONNECT — in `tests/contract/socks5/long_lived_connect_test.go`.

## Analysis

T025b is tests-first (Constitution Principle VII) for the post-handshake
byte-pipe surface of the forward path (T047 `forward/tor.go`, T043
`listener/connect.go`, T042 `listener/socks5.go`). The spec's two edge-case
rows (WebSocket upgrade, HTTP/2 fallback) are mechanically subsumed: after
the SOCKS5/CONNECT handshake completes, any TLS-over-CONNECT payload is
opaque bytes to the data plane, so one byte-transparency assertion covers
all protocol shapes.

- **Must hold:**
  - **Post-handshake byte transparency, both directions, both framings**
    (Principle I; FR-007; spec §"Edge Cases" rows cited above). Every byte
    written by the client round-trips through the DP twice (client→upstream,
    then the accept-and-relay echo upstream→client), so corruption,
    insertion, deletion, or reordering in *either* direction breaks the
    stream-equality assertion.
  - **No DP-imposed close for inactivity, frame content, or frame size**
    (contracts/socks5-auth.md §"Deadlines": post-handshake deadline is
    "none — long-lived"). The connection must survive a ≥30 s exchange
    including idle gaps up to 5 s and individual frames ≥64 KiB; only a
    client- or upstream-initiated close may end it.
  - **No journal line attributable to the frame traffic** (FR-008;
    Principle I — the DP does not narrate per-request activity). The
    journal delta captured around the exchange window is confined to the
    T025a shared allowlist (`tests/internal/loginvariants`), contains no
    destination / UNAME / payload-sentinel / token in any of the nine
    scanned renderings, and carries no sub-hour timestamp.
  - **Framing equivalence** (FR-005/FR-006; contracts/socks5-auth.md
    §"Two inbound protocols, one port" and §"HTTP CONNECT path"): the
    three properties above hold identically whether the tunnel was opened
    via authenticated SOCKS5 or via `CONNECT … HTTP/1.1` +
    `Proxy-Authorization: Bearer <token>` answered with
    `HTTP/1.1 200 Connection Established\r\n\r\n`.
  - **The traffic actually transits the fake upstream** (anti
    echo-false-pass, the 20260706-002 finding class): a DP that
    short-circuited to a local echo without forwarding would otherwise
    pass the transparency assertion. Gate: the SOCKS5-framing UNAME is
    asserted present in `upstream.CircuitIDs()` (doubles as FR-007
    username-passed-through-unchanged evidence).
  - **Tests-first self-skip** (Principle VII): the test content-gates on
    T042/T045/T050 (dpharness boot minimum) plus T044 `auth/token.go`,
    T047 `forward/tor.go`, T045 `controlclient/client.go`, and T043
    `listener/connect.go`; it SKIPs while any is absent and becomes a
    hard FAIL gate once all land.
- **Gated:**
  - `gofmt` / `go vet` / `-race` over the new file via the acceptance
    command; license header via verify.sh Gate 1.
  - The allowlist + corpus-scan core is self-tested by
    `tests/internal/loginvariants/loginvariants_test.go` (T025a).
  - First-byte demux (T023), SOCKS5 auth handshake (T024), and the
    short-lived success-path journal surface (T025a) are gated by their
    own tests; T025b layers the long-lived byte-pipe properties on top
    without restating those contracts.
- **Residue:**
  - **verify.sh Gate 2 runs only the `data-plane` module** — the
    `tests/contract` Go tests execute via this ticket's acceptance
    command (and future CI wiring), not the single green gate.
    Pre-existing gap inherited from T022–T025a; promotion (a
    contract-module `go test` gate in scripts/verify.sh) is a follow-up
    ticket, out of this ticket's scope.
  - **The echo upstream makes the two directions content-coupled**:
    upstream→client bytes are by construction the echo of client→upstream
    bytes, so "asymmetric bandwidth" is realized as burst-vs-drain
    in-flight asymmetry (writer runs ahead of the echo drain) plus
    differing volume profiles between the two framings — not as
    independently scripted directional streams. A DP bug that mangles
    only upstream-originated non-echoed bytes has no test surface until
    T019a's fake grows an independently scriptable upstream side
    (follow-up if that regression class materialises). Mitigation:
    every byte still traverses the DP once in each direction.
  - **CONNECT-framing upstream-transit proof is indirect**: the fake
    records only SOCKS5 UNAMEs, and the DP's CONNECT-path bridge
    username choice is unspecified here, so the `CircuitIDs()` gate is
    asserted for the SOCKS5 framing only. On the CONNECT path the `200`
    reply is contractually emitted only after the upstream SOCKS5
    handshake succeeds (contracts/socks5-auth.md §"HTTP CONNECT path";
    dead-sidecar → 502 ROUTE_DOWN is T065's scope), which bounds the
    false-pass to a pathological implementation, documented not promoted.
  - **The idle-gap ceiling is 5 s**: an idle-timeout regression longer
    than 5 s but finite (e.g. 60 s) escapes this test — bounded by PR-
    cadence wall-time budget. The contract value under test is "none";
    "survives ≥5 s idle" is the practical proxy.
  - **Random payload bytes are not in the journal corpus scan** — only
    the distinctive sentinel, destination, UNAME, and token plaintext
    are scanned (nine renderings each). Scanning tens of MiB of PRNG
    payload in nine encodings is quadratic cost for no added signal;
    the allowlist gate is the primary catch for an unnamed
    payload-carrying log line (mirrors T025a's bare-epoch reasoning).
  - **Redteam scope (privacy-critical, non-empty residue):** hunt for
    (a) reader/writer deadline logic that could mask a mid-run stall or
    premature close as a pass; (b) an HTTP-CONNECT response reader that
    over-reads past the header-terminating blank line and silently
    swallows tunnel bytes (breaking transparency evidence); (c) journal
    delta-window races that could hide a frame-traffic log line outside
    the before/after snapshots; (d) failure messages that could
    themselves leak payload or destination bytes into CI logs.

## Acceptance

### Named test

**NEW: `tests/contract/socks5/long_lived_connect_test.go`** — package
`socks5` (alongside T023/T024/T025/T025a; directory convention per
contracts/socks5-auth.md §"Two inbound protocols, one port").
`TestLongLivedBidirectionalCONNECT`:

1. **Fixture** (mirrors `no_per_request_logs_test.go`): content-gate on
   `auth/token.go` (T044), `forward/tor.go` (T047),
   `controlclient/client.go` (T045), and `listener/connect.go` (T043) via
   `dpharness.RequireFile`; boot `integration.NewServer(AcceptAndRelay)` +
   `dpharness.Start(WithUpstream, WithBeforeBoot(fakecp.Start))`; push
   token generation 1 (`dpharness.MintToken` of a 32-hex plaintext,
   `dpharness.Reload` must return `APPLY_STATUS_OK`); wait for the
   WatchEvents dial, push `fakecp.Healthy("tor")`; quiesce, snapshot the
   journal (`before`).
2. **Two framing legs run concurrently** (parallel subtests sharing the
   one DP + upstream), each with its own connection, deterministic PRNG
   seed, distinctive destination (`t025b-dest-<framing>….onion`),
   distinctive payload sentinel, and — SOCKS5 leg — distinctive UNAME:
   - **SOCKS5 leg**: method negotiation → RFC 1929 sub-negotiation
     (reply must be `01 00`) → CONNECT (reply must be `05 00 …`, 10
     bytes) — reusing the package's existing helpers.
   - **HTTPConnect leg**: `CONNECT <dest>:443 HTTP/1.1\r\n
     Proxy-Authorization: Bearer <token>\r\n\r\n`; read the response
     **only up to and including the header-terminating blank line**
     (no over-read); status line must be `HTTP/1.1 200 Connection
     Established`.
3. **Byte-pipe exchange, per leg** — assertions (a)+(c) of the task body:
   - Writer goroutine emits a deterministic frame schedule ≥30 s long:
     mixed sizes (small 1–64 B, medium 1–8 KiB, large 64–256 KiB),
     bursty phases interleaved with trickle phases (asymmetric
     instantaneous bandwidth), idle gaps up to and including one ≥4.5 s
     gap; first frame carries the leg's ASCII sentinel.
   - Reader goroutine regenerates the identical expected stream from the
     same seed and compares chunk-by-chunk as echoes arrive; on
     divergence it reports **offset and lengths only** (never payload
     bytes — leak-safe failure messages).
   - Any premature EOF, reset, or read/write error before the client
     initiates close is a FAIL (assertion (c): no close for inactivity,
     content, or size). After the final gap, a probe frame must still
     round-trip; then the client closes.
   - Leg completion asserts: bytes written == bytes read back, elapsed
     exchange time ≥30 s, zero stream divergence.
4. **Upstream-transit gate**: after both legs complete,
   `upstream.CircuitIDs()` contains the SOCKS5 leg's UNAME (§Analysis
   echo-false-pass must-hold).
5. **Journal invariants** — assertion (b) of the task body: quiesce,
   snapshot (`after`), compute the append-only delta, then
   `loginvariants.AssertOnlyAllowedLines(delta)`,
   `loginvariants.AssertNoSubHourTimestamp(delta)`, and
   `loginvariants.AssertNoSecrets(delta, dest_socks5, dest_connect,
   uname, sentinel_socks5, sentinel_connect, token)`.

### Runnable command

```sh
scripts/verify.sh &&
  (cd tests/contract && gofmt -l . && go vet ./socks5/... &&
   go test -race -count=1 -run TestLongLivedBidirectionalCONNECT ./socks5/...)
```

Today the test SKIPs at the dpharness boot-minimum gate (T042/T045/T050
unimplemented) — the skip self-lifts as implementation lands, matching the
T023/T024/T025/T025a precedent. `scripts/verify.sh` stays green
(gate 2 remains scoped to the data-plane module; see §Analysis residue).

## Out-of-scope

- **Protocol-specific WebSocket / HTTP/2 tests** — the task body records
  both edge-case rows as mechanically subsumed by the byte-pipe
  assertion; no protocol framing is generated or parsed.
- **HTTP CONNECT positive-path contract details** (exact 200 bridge
  behaviour, T026) and **AUTH_REQUIRED 407 template** (T027) — this test
  consumes the CONNECT success handshake, it does not pin its shape.
- **Mid-request circuit drop** (T070a) and **ROUTE_TIMEOUT / request-
  phase failures** (T067a) — separate tickets; this test never induces
  upstream failure.
- **Concurrent-load / pool-fill behaviour** (T079a) — the two legs here
  run concurrently only to bound wall-clock time, not to assert
  concurrency properties.
- **Refactoring T025 `leak_test.go` onto `loginvariants`** — follow-up
  named in T025a's residue; unchanged here.
- **Wiring a `tests/contract` go-test gate into scripts/verify.sh** —
  pre-existing gap, follow-up ticket (§Analysis residue).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
