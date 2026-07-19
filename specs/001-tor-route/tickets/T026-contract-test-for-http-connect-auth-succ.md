---
id: T026
title: 'Contract test for HTTP CONNECT auth success'
status: done
created: 2026-07-04
last_updated: 2026-07-07
source: tasks.md#T026
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
  - specs/001-tor-route/spec.md §"FR-005" (loopback 127.0.0.1:8881 listener — one port, two inbound framings)
  - specs/001-tor-route/spec.md §"FR-006" (every inbound proxy request authenticated; per-framing auth)
  - specs/001-tor-route/spec.md §"FR-007" (no parse/inspect/modify beyond SOCKS5/CONNECT framing; CONNECT parses only the request line + Proxy-Authorization)
  - specs/001-tor-route/spec.md §"FR-008" (no per-request journal surface — destination/UNAME/token-free; success path symmetric to failure)
  - specs/001-tor-route/contracts/socks5-auth.md §"HTTP CONNECT path" (the auth-success response shape `HTTP/1.1 200 Connection Established\r\n\r\n` then bridge; the contract under test)
  - specs/001-tor-route/contracts/socks5-auth.md §"Two inbound protocols, one port" (first-byte demux `C`→CONNECT; directory convention — socks5/ holds CONNECT-framed auth-success tests that do not emit the error template)
decision_refs:
  - specs/001-tor-route/research.md §5 (contract-test harness language — Go)
  - specs/001-tor-route/research.md §7 (synthetic SOCKS5 backend, not live Tor — the accept-and-relay fake)
  - specs/001-tor-route/research.md §9 (AUTH_REQUIRED response on SOCKS5 vs HTTP CONNECT framing — the two-framing split T026 success / T027 failure divides on)
  - specs/001-tor-route/tickets/T025b-contract-test-for-long-lived-bidirection.md (T025b consumes CONNECT framing as a byte-pipe vehicle and checks only the status-line prefix; its §Out-of-scope defers the exact 200 bridge behaviour to T026 — T026 is the canonical pin)
  - specs/001-tor-route/tickets/T025a-contract-test-for-socks5-success-path-lo.md (shared loginvariants allowlist is canonical; T026 is a named consumer for the CONNECT success-path journal surface)
reviews: { round: 1, date: 2026-07-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T026: Contract test for HTTP CONNECT auth success

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for HTTP CONNECT auth success — `CONNECT host:443 HTTP/1.1` + `Proxy-Authorization: Bearer <valid>` returns `HTTP/1.1 200 Connection Established\r\n\r\n` then bridges to upstream — in `tests/contract/socks5/connect_auth_success_test.go`. (Lives under `socks5/` per the directory convention: that path holds all port-8881 inbound-surface tests, including CONNECT-framed traffic that does **not** emit the privacy-safe error template. `tests/contract/error-template/` is scoped to template-emitting responses only; see `contracts/socks5-auth.md` §"Two inbound protocols, one port".)

## Analysis

T026 is tests-first (Constitution Principle VII) for the HTTP CONNECT
auth-success response shape and bridge engagement — the positive-path
contract detail T025b deliberately deferred (T025b's `openHTTPConnectTunnel`
checks only the status-line prefix as a vehicle for the byte-pipe test;
T026 pins the exact response bytes and that the bridge engages the
upstream). It is the success-path half of the two-framing split
(research.md §9); T027 owns the AUTH_REQUIRED 407 failure half.

- **Must hold:**
  - **Exact auth-success response bytes** (contracts/socks5-auth.md
    §"HTTP CONNECT path"; Principle I). On `CONNECT <host>:443
    HTTP/1.1\r\nProxy-Authorization: Bearer <valid>\r\n\r\n` the data
    plane responds byte-exactly `HTTP/1.1 200 Connection Established
    \r\n\r\n` — the status line and the header-terminating blank line,
    nothing else. No `Date`, `Proxy-Agent`, `Content-Length`, or any
    other header; no body before the bridge. A DP that adds any header
    breaches the contract and is caught by the exact-bytes assertion
    (a) (not a status-line-prefix check); a leading body byte before
    the bridge is caught by assertion (b) — it corrupts the echo
    round-trip.
  - **Bridge engages the upstream SOCKS5 connection** (FR-005/FR-006/
    FR-007; Principle I). After the 200, client bytes traverse the DP
    to the upstream and back unmodified — the tunnel is live, not a
    local short-circuit that wrote 200 then dropped the socket. Proven
    by a distinctive sentinel round-tripping through the accept-and-relay
    fake upstream (anti echo-false-pass class — a DP that 200'd without
    forwarding cannot echo).
  - **No destination or token byte in the success response**
    (contracts/socks5-auth.md §"Invariants enforced by the contract
    test" leak-scan rows, applied symmetrically to success; Principle
    III; FR-008). The 200 header block contains neither the request's
    destination host nor the offered bearer token, in any of the nine
    textual renderings an accidental logger would produce.
  - **No journal line attributable to the CONNECT success request**
    (FR-008; Principle I/III; symmetric to the SOCKS5 success path
    T025a gates — the CONNECT path is a distinct inbound code surface
    T043 `listener/connect.go`, not covered by T025a's SOCKS5-only
    burst). The journal delta around the CONNECT success is confined to
    the T025a shared allowlist (`tests/internal/loginvariants`), carries
    no destination / token / bridge-sentinel in any of the nine scanned
    renderings, and carries no sub-hour timestamp.
  - **Tests-first self-skip** (Principle VII): content-gates on T043
    (`listener/connect.go` — the inbound surface under test), T044
    (`auth/token.go` — bearer verification precondition), T047
    (`forward/tor.go` — the bridge), and T045 (`controlclient/client.go`
    — to receive the HEALTHY event that engages the route); plus the
    boot minimum inside `dpharness.Start` (T042/T045/T050). SKIPs while
    any is absent and becomes a hard FAIL gate once all land.
- **Gated:**
  - `gofmt` / `go vet` / `-race` over the new file via the acceptance
    command; license header via verify.sh Gate 1.
  - First-byte demux `C`→CONNECT routing is pinned by T023 sub-test
    (d); T026 layers on a DP that already routes `C` down the CONNECT
    path and asserts what happens AFTER the routing.
  - Auth-success mechanics (argon2id hash + `crypto/subtle`
    constant-time compare against the current generation; the
    `^[0-9a-f]{32}$` syntactic gate) are T044/T024's gated surface;
    T026 consumes auth-success as a precondition and asserts the
    response shape + bridge, not the comparison primitive.
  - The allowlist + corpus-scan + sub-hour-timestamp core is self-tested
    by `tests/internal/loginvariants/loginvariants_test.go` (T025a).
- **Residue:**
  - **verify.sh Gate 2 runs only the `data-plane` module** — the
    `tests/contract` Go tests execute via this ticket's acceptance
    command (and future CI wiring), not the single green gate.
    Pre-existing gap inherited from T022–T025b; promotion (a
    contract-module `go test` gate in scripts/verify.sh) is a follow-up
    ticket, out of this ticket's scope.
  - **The CONNECT request's host→upstream-target mapping is NOT
    observable.** The contract says the DP "bridges to the upstream
    SOCKS5 connection (which uses the host header from the request line
    as the target)," but `fake_socks5_tor.go` `readConnectRequest`
    (lines 353–386) consumes and discards the destination; there is no
    `Destinations()` accessor. This test proves the bridge engages SOME
    upstream connection (the sentinel round-trips), not WHICH target
    the DP sent to the upstream. Promoting requires extending the fake
    to record destinations — follow-up if that regression class
    materialises. Bounded by the same indirect-transit reasoning as
    T025b: the 200 is contractually emitted only after the upstream
    SOCKS5 handshake succeeds, so a no-upstream-connection DP cannot
    produce a 200 followed by an echo.
  - **The bridge round-trip is a single echo exchange**, not the
    sustained bidirectional byte-pipe transparency T025b pins (≥30 s,
    both directions, mixed frame sizes). A DP bug that mangles bytes
    only after sustained traffic or only beyond the first echo escapes
    T026 — caught by T025b. T026 and T025b are complementary: T026
    pins the handshake response + bridge-engages; T025b pins the
    sustained pipe.
  - **FR-007's "parses no header beyond the request line and
    Proxy-Authorization" is not directly exercised here** — the test
    sends the minimal valid request (request line + Proxy-Authorization
    only). A DP that incorrectly read/echoed other headers would not be
    caught by this test; that is the listener's unit-test surface
    (T043), not the positive-path contract.
  - **Random/echo payload bytes are not in the journal corpus scan** —
    only the distinctive destination, token, and bridge sentinel are
    scanned (nine renderings each). Mirrors T025a/T025b; the allowlist
    gate is the primary catch for an unnamed payload-carrying log line.
  - **Redteam scope (privacy-critical, non-empty residue):** hunt for
    (a) a response reader in the test that over-reads past the
    header-terminating `\r\n\r\n` and swallows tunnel bytes — breaking
    both the exact-response assertion AND the bridge round-trip
    evidence (the same class T025b's redteam scope (b) named); (b) any
    way the exact-bytes assertion could pass on a non-exact response
    (e.g. a prefix-only compare masquerading as exact, or a captured
    buffer trimmed to the status line); (c) a journal delta-window race
    that hides a CONNECT-success per-request log line outside the
    before/after snapshots; (d) failure messages or sub-test names that
    leak the destination or token into CI logs (the test must withhold
    both from its failure output, mirroring the loginvariants index-
    only discipline).

## Acceptance

### Named test

**NEW: `tests/contract/socks5/connect_auth_success_test.go`** — package
`socks5` (alongside T023/T024/T025/T025a/T025b; directory convention per
contracts/socks5-auth.md §"Two inbound protocols, one port" — CONNECT-
framed auth-success does not emit the error template, so it lives under
`socks5/`, not `error-template/`). `TestHTTPConnectAuthSuccess` runs as
a single consolidated body (not sub-tests) because the four must-holds
layer on one fixture (one DP boot, one token push, one HEALTHY, one
CONNECT success) — splitting would multiply the argon2id + boot cost
without adding assertion coverage (the T025a precedent).

1. **Fixture** (mirrors `long_lived_connect_test.go` / `no_per_request_logs_test.go`):
   content-gate on `auth/token.go` (T044), `forward/tor.go` (T047),
   `controlclient/client.go` (T045), and `listener/connect.go` (T043)
   via `dpharness.RequireFile`; boot `integration.NewServer(AcceptAndRelay)`
   + `dpharness.Start(WithUpstream, WithBeforeBoot(fakecp.Start))`; push
   token generation 1 (a 32-hex plaintext via `dpharness.MintToken`,
   `dpharness.Reload` must return `APPLY_STATUS_OK`); wait for the
   WatchEvents dial, push `fakecp.Healthy("tor")`; quiesce, snapshot the
   journal (`before`).
2. **Distinctive corpus**: a destination `t026-dest.example.onion`, the
   token plaintext (32-hex, distinct from T025a/T025b so a corpus hit is
   attributable to this test), and a distinctive bridge sentinel. Each
   is scanned in nine renderings where relevant.
3. **Act**: open a connection, send `CONNECT <dest>:443 HTTP/1.1\r\n
   Proxy-Authorization: Bearer <token>\r\n\r\n` (the minimal valid
   request shape per the task body — request line + Proxy-Authorization
   only). Read the response **byte-at-a-time**, capturing the full
   header block, strictly up to and including the header-terminating
   blank line (`\r\n\r\n`) — no buffered over-read into tunnel bytes
   (§Analysis redteam scope (a)).
4. **(a) ExactResponse**: the captured header block equals byte-exactly
   `"HTTP/1.1 200 Connection Established\r\n\r\n"` — status line + blank
   line, no other header, no body. A length / suffix check on the whole
   block, NOT a status-line-prefix check (§Analysis must-hold #1; the
   property T025b deferred).
5. **(b) BridgeEngages**: after the 200, write the distinctive sentinel
   and read exactly `len(sentinel)` bytes back with a bounded deadline;
   assert byte-equality. The echo proves the bridge engaged the upstream
   SOCKS5 connection and the tunnel is live (anti echo-false-pass; §Analysis
   must-hold #2). A single round-trip — the sustained pipe is T025b's scope.
6. **(c) ResponseLeaksNothing**: `loginvariants.AssertNoSecrets(resp,
   []byte(dest), []byte(token))` over the captured 200 response bytes
   (raw + eight derived renderings). The success response carries no
   destination and no token byte.
7. **(d) JournalClean**: quiesce, snapshot (`after`), compute the
   append-only delta, then `loginvariants.AssertOnlyAllowedLines(delta)`,
   `loginvariants.AssertNoSubHourTimestamp(delta)`, and
   `loginvariants.AssertNoSecrets(delta, dest, token, sentinel)` — the
   CONNECT success path emits no per-request journal line (symmetric to
   T025a's SOCKS5 success-path gate, for the distinct CONNECT inbound
   surface).

### Runnable command

```sh
scripts/verify.sh &&
  (cd tests/contract && gofmt -l . && go vet ./socks5/... &&
   go test -race -count=1 -run TestHTTPConnectAuthSuccess ./socks5/...)
```

Today the test SKIPs at the content gates (T043/T044/T045/T047/T050
unimplemented) — the skip self-lifts as implementation lands, matching
the T023/T024/T025/T025a/T025b precedent. `scripts/verify.sh` stays
green (Gate 2 remains scoped to the data-plane module; see §Analysis
residue).

## Out-of-scope

- **AUTH_REQUIRED 407 failure path** (missing / malformed / empty token)
  — T027's scope; the failure template lives under
  `tests/contract/error-template/`. T026 consumes auth-success as a
  precondition; it does not pin the failure shape.
- **Valid token + dead sidecar → 502 ROUTE_DOWN** — T065 / the
  error-template tickets; T026 always runs against a healthy upstream.
- **The sustained bidirectional byte-pipe transparency** (≥30 s, both
  directions, mixed frame sizes, idle gaps) — T025b's scope. T026's
  bridge round-trip is a single echo exchange proving the tunnel is
  live, not a pipe-transparency regression gate.
- **FR-007's "parses no header beyond the request line and
  Proxy-Authorization"** — the listener's unit-test surface (T043).
  T026 sends the minimal valid request; it does not probe header-
  ignoring behaviour.
- **Constant-time comparison / slot-invariance timing tests** — the
  contract table's timing rows are a separate surface (the auth
  primitive, T044/T024); T026 is the positive-path response-shape
  contract, not a timing gate.
- **The CONNECT request's host→upstream-target mapping** — not
  observable with the current fake (`readConnectRequest` discards the
  destination; §Analysis residue). Extending the fake to record
  destinations is a follow-up.
- **Wiring a `tests/contract` go-test gate into scripts/verify.sh** —
  pre-existing gap inherited from T022–T025b; follow-up ticket
  (§Analysis residue).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
