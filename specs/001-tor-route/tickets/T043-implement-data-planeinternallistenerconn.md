---
id: T043
title: 'Implement `data-plane/internal/listener/connect.go`'
status: in-review
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T043
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
  - "specs/001-tor-route/spec.md FR-005 (port 8881; HTTP CONNECT is the 'C' demux framing)"
  - "specs/001-tor-route/spec.md FR-006 (Proxy-Authorization: Bearer <token>; absence/mismatch → 407 + AUTH_REQUIRED template; no offered token / rejected destination in any response)"
  - "specs/001-tor-route/spec.md FR-007 (parse only what framing/auth requires; no local resolution; no inspection beyond request line + Proxy-Authorization)"
  - "specs/001-tor-route/spec.md FR-008 (count only auth-passed requests; no per-request log)"
  - "specs/001-tor-route/spec.md FR-009 (route failure on CONNECT → privacy-safe template with code per arch §10.1; the upstream dial/handshake result alone decides)"
  - "specs/001-tor-route/contracts/socks5-auth.md §\"HTTP CONNECT path\" (parse only the request line + Proxy-Authorization; ^[0-9a-f]{32}$ gate BEFORE hashing; 200 byte shape; 407 shape; then close)"
  - "specs/001-tor-route/contracts/error-template.md §\"Wire format\" (status-line table; exactly four headers in declared order; body = Template literal with the three substitutions; forbidden set)"
  - "THREAT-MODEL.md §3.1 Local profile (same-host unprivileged processes must not proxy without the token)"
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T043: Implement `data-plane/internal/listener/connect.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/listener/connect.go` — parse only the request line and the `Proxy-Authorization` header from `CONNECT host:port HTTP/1.1`; no other header is read; on success, write `HTTP/1.1 200 Connection Established\r\n\r\n` and hand off to the forward path. Verified by T026.

## Analysis

Property map (grounding-verified 2026-09-03; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (body-vs-reality items):**

1. **The CONNECT status line must be written only AFTER the upstream
   dial/handshake result is known.** FR-009 ("the upstream
   dial/handshake result alone decides success or the route error"),
   error-template contract row 3 ("Valid token + dead sidecar → 502 +
   ROUTE_DOWN template" — T065's future gate), and T026 §Analysis
   residue ("the 200 is contractually emitted only after the upstream
   SOCKS5 handshake succeeds") all pin this ordering. T042's fused
   `Forwarder.Forward(client, uname, target)` seam cannot express it
   for this path: dialing before the status line would let upstream
   bytes precede it, and dialing after would make a dead sidecar yield
   200-then-EOF instead of the 502 template. This file therefore
   defines its own consumer-side seam, `Tunneler` (`Dial(target)` +
   `Pipe(client, upstream)`), implemented by T047's forward/tor.go over
   the same internals as `Forwarder` — the seam splits, the
   implementation need not. `socks5.go` is untouched by this ticket.
2. **Seams are consumer-defined here** (T042 precedent): T044
   (`auth/token.go`), T047 (`forward/tor.go`), T048
   (`errortpl/render.go`) do not exist yet and must not be imported.
   `ConnectDeps{Auth, Tunnel, Audit, Renderer}` is this file's wiring
   point; T050 closure-wires `HandleConnect` into the existing
   `Deps.Connect func(net.Conn)`. `Auth`/`Audit` reuse T042's
   `Verifier`/`Audit` interfaces (same package). All fields required
   non-nil at call time — no defensive nil guards inside the trust
   boundary (CONTRIBUTING doctrine).
3. **The `^[0-9a-f]{32}$` syntactic gate lives HERE** (contract step 2:
   "Token MUST match ^[0-9a-f]{32}$ syntactically before hashing";
   T042 §Analysis finding 3 already scoped it CONNECT-path-only).
   Gate-fail and VerifyPassword-fail fold into the same
   `AUTH_REQUIRED` response — byte-identical modulo the renderer's
   per-response `LOCAL_REFERENCE_ID` (T027 gates the
   no-distinguishing-substring property). The gate also keeps
   wrong-format candidates from ever reaching the hash (T044's
   constant-time loop is not keyed on their bytes either way).
4. **The failure template is a seam, not an import.** T048 owns
   `errortpl/render.go` (v1: `AUTH_REQUIRED`; T071 extends the
   remaining codes). This file defines `ErrorRenderer.WriteFailure(
   w, code)` over the fixed four-code vocabulary and routes BOTH the
   auth-failure branch (`AUTH_REQUIRED`) and the route-failure branch
   (`ROUTE_DOWN`/`ROUTE_REFUSED`/`ROUTE_TIMEOUT`, mapped from T042's
   `RouteError` REP codes 0x03/0x04/0x06; unclassified dial error →
   `ROUTE_DOWN` — an unclassified dial failure means the sidecar path
   is broken, which is what DOWN says) through it, so T071 extends the
   renderer without touching this file. A renderer write error is
   best-effort: the caller closes either way; nothing is logged.
5. **Byte-at-a-time header read; the byte pipe starts at the blank
   line.** A buffered reader would over-read past the header
   terminator and swallow the client's first tunnel bytes (TLS
   ClientHello sent un-pipelined is real); the parser reads one byte
   at a time up to and including the `\r\n\r\n` and never touches the
   conn again except to write the status line. The total header-block
   budget is a named constant (8 KiB, nginx-class default): overflow →
   silent close. This is edge-input validation (CONTRIBUTING allows it
   at system edges), bounding memory per connection on the loopback
   surface; the inherited 30 s handshake deadline bounds duration.
6. **No UNAME on this path.** CONNECT carries no username; `Dial`
   takes only the target. US2's per-first-party stream isolation is
   SOCKS5-framed (the extension); a CONNECT client gets the upstream's
   default isolation. T047's grounding owns the upstream-uname
   consequence.

- **Must hold:**
  - Request line parsed as exactly `CONNECT <authority> HTTP/1.1`
    (the leading `C` was consumed by the demux): method uppercase
    literal, authority `host:port` with non-empty host and 1–5-digit
    port after the last colon, version literal `HTTP/1.1`. Any other
    shape — and any framing overrun or header-block overflow — is a
    silent close with ZERO response bytes: the contract defines no
    400-class response, and the SOCKS5 path's post-auth framing row is
    the precedent. Auth seam never consulted on a framing close.
  - Parse only the request line + the `Proxy-Authorization` header
    (FR-007; contract step 1): header-name match is ASCII
    case-insensitive (HTTP header names are case-insensitive) but the
    match is on THIS name only; lookalikes (`X-Proxy-Authorization`,
    suffix/prefix names) must not authenticate. Other header lines are
    consumed byte-wise to find the blank line and never branched on.
  - Value shape: optional whitespace, then the literal scheme `Bearer `
    (contract's canonical form; anything else is a format-gate fail),
    then the token which MUST match `^[0-9a-f]{32}$` (lowercase hex,
    exactly 32) before hashing (contract step 2).
  - Every auth failure — header absent, scheme not `Bearer `, token
    fails the format gate, `VerifyPassword` false — produces the same
    `AUTH_REQUIRED` renderer call, then close; the offered token and
    the destination appear in no response byte (FR-006; error-template
    forbidden set).
  - Auth pass fires `Audit.AuthPassedRequest()` exactly once, BEFORE
    the status line (FR-008 asymmetry: route failures still count —
    T067b — auth failures never do; T027's fixture asserts the 407
    leaves counters untouched).
  - Success: after `Dial` succeeds, write EXACTLY
    `HTTP/1.1 200 Connection Established\r\n\r\n` (status line +
    blank line, no other header, no body — T026's exact-bytes gate),
    clear the deadline (`SetDeadline` zero — no post-handshake idle
    deadline; T025b), then `Pipe`. Pipe's error is close-only: no
    bytes may be injected into an established tunnel.
  - No resolution, no canonicalisation of the host: the authority is
    forwarded to `Dial` verbatim (FR-007; Principle III — SOCKS5h).
  - No per-request log anywhere in this file (FR-008; nothing on
    stderr for framing, auth, route, or success).
  - Principle I byte budget: this file parses ONLY the request line
    and the one auth header — no other header interpreted, no payload
    inspection, no timestamps, no destination-derived bytes in any
    output.
- **Gated** (verify.sh catches fail-closed):
  - `go vet` + `go test` over the data-plane module via
    `scripts/go-workspace-gate.py` — the repo's only wired Go gate:
    the syntactic surface and a class of correctness bugs (no
    scanner-class gate is wired; see §Residue).
  - `go test ./internal/listener/` — the in-package unit test this
    ticket ADDS (`connect_test.go`, net.Pipe + stub seams, reusing
    socks5_test.go's helpers) pins every row above NOW: 200 exact
    bytes + verbatim target + deadline-zero, anti-over-read early
    tunnel bytes, missing/malformed/mismatch → identical
    AUTH_REQUIRED with zero auth-seam and audit traffic, lookalike
    header rejection, framing-garbage silent closes, oversize bound,
    route-error → code mapping, unclassified → ROUTE_DOWN. (Residue
    promotion — T026/T027 stay SKIP until T044/T045/T047/T048/T050
    land, so the CONNECT byte contract would otherwise be ungated at
    this ticket's review.)
  - License-header check gates the SPDX header.
  - Contract suites T026 (success) / T027 (407) / T065 (502) gate the
    same shapes end-to-end once T044/T045/T047/T048/T050 land; their
    `dpharness.RequireFile` gate on this very file self-lifts then.
- **Residue:**
  - staticcheck and gosec gate NOTHING on the data plane — no wired
    invocation exists in scripts/, CI, or Makefiles (round-1 review
    finding). The data plane is the privacy TCB and currently runs
    with `go vet` + `go test` only. Wiring a scanner-class gate (or
    recording its absence as accepted tooling residue in docs) is a
    tooling follow-up ticket, out of this ticket's scope.
  - The 8 KiB header-block bound and the strict `HTTP/1.1` /
    uppercase-`CONNECT` / exact-`Bearer ` requirements are
    contract-silent choices (the contract pins only the canonical
    request). Promoted to gated by this ticket's unit test rows; a
    future client that legitimately needs looser parsing re-opens with
    a spec-level rationale.
  - `Tunneler.Dial`'s 30 s upstream deadline and its `RouteError`
    classification do not exist until T047 lands; until then the
    route-error rows are exercised only against stubs. Accepted —
    T065/T066/T067 are the end-to-end gates for exactly these rows.
  - The CONNECT auth-FAILURE journal-delta allowlist gate is unclaimed
    by any contract test (T027 §Analysis residue, same gap);
    connection-level silence (no log call in this file) is the
    interim guarantee, verifiable by reading. Follow-up note for a
    journal-delta ticket, not a new ticket here.
  - Redteam scope (privacy-critical, non-empty residue): (a) any read
    path that could over-read past the blank line into tunnel bytes;
    (b) any byte of the destination or offered token surviving into
    the 200, the 407, or an error message; (c) a distinguishing
    response byte between the missing-header and malformed-token
    cases (renderer input must not vary with WHY auth failed); (d)
    header-name matching that over-matches (prefix/suffix/substring)
    and lets a lookalike header authenticate; (e) allocation
    amplification via the header-block budget (a slow-loris on 8881).

## Acceptance

### Named tests

**NEW: `data-plane/internal/listener/connect_test.go`** — package
`listener` (alongside `socks5_test.go`; reuses its helper/stub idiom —
no redeclaration), net.Pipe client ↔ `HandleConn` with
`Deps.Connect` wired to `HandleConnect` over stub
`Verifier`/`Tunneler`/`Audit`/`ErrorRenderer` seams. Every response
byte this file writes is either the exact 200 literal or stub-renderer
output, so byte assertions are exact.

- `Connect_Success_Exact200_VerbatimTarget` — valid request line +
  `Proxy-Authorization: Bearer <32-hex>` + two OTHER headers
  (`User-Agent`, `X-Stargate-Probe`) → stub renderer NOT called;
  client reads exactly `HTTP/1.1 200 Connection Established\r\n\r\n`;
  `Dial` got `t043.example.onion:443` verbatim; a zero-deadline call
  recorded before `Pipe` (contract §"Deadlines"); audit fired exactly
  once, auth seam saw the raw token bytes.
- `Connect_EarlyTunnelBytesNotSwallowed` — header block + sentinel
  written in ONE client write; after the 200 the sentinel round-trips
  through the stub `Pipe` (anti-over-read: the parser stopped at the
  blank line).
- `Connect_HeaderNameCaseInsensitive` — `proxy-AUTHORIZATION:` lower/
  mixed-case → still authenticates (HTTP names are case-insensitive).
- `Connect_AuthMissing_407_NoAuthNoCounter` — no
  `Proxy-Authorization` → renderer called with `AUTH_REQUIRED` exactly
  once; auth seam and audit untouched; EOF after the renderer bytes.
- `Connect_AuthMalformed_407_Indistinguishable` — `Bearer notatoken`,
  31-hex, 33-hex, uppercase hex, `bearer <valid>` (scheme is
  case-sensitive), `Basic <valid>` → each: renderer
  `AUTH_REQUIRED` (identical stub response), auth seam never called
  (format gate precedes hashing).
- `Connect_AuthVerifyFail_407_NoCounter` — valid-format token,
  `VerifyPassword` false → `AUTH_REQUIRED`; audit 0 (FR-008 side
  channel).
- `Connect_LookalikeHeader_407` — `X-Proxy-Authorization: Bearer
  <valid>` and `Proxy-Authorization-Extra: Bearer <valid>` → 407
  (exact-name match only).
- `Connect_FramingGarbage_SilentClose` — wrong method (`GET / HTTP/1.1`
  — first byte 'G' is demux'd, so here: `ONLY CRLF` junk after a
  forced-'C' entry), wrong version (`HTTP/1.0`), missing authority,
  `host:none` (non-digit port) → each: zero response bytes, EOF,
  auth/dial/renderer untouched.
- `Connect_OversizedHeaders_SilentClose` — >8 KiB header block →
  silent close, renderer untouched.
- `Connect_RouteError_Template` — `Dial` returns `routeErr{0x03}` /
  `{0x04}` / `{0x06}` → renderer called with `ROUTE_DOWN` /
  `ROUTE_REFUSED` / `ROUTE_TIMEOUT` respectively; plain `errors.New`
  → `ROUTE_DOWN`; audit fired exactly once each (route failures count,
  FR-008); NO 200 bytes on the wire before the template.
- `Connect_PipeError_NoInjectedBytes` — after a good 200, `Pipe`
  returns an error → EOF with zero additional bytes (a tunnel is never
  injected into).

### Runnable command

```sh
scripts/verify.sh && (cd data-plane && go test -race -count=1 ./internal/listener/)
```

`scripts/verify.sh` stays green: the new file compiles under the
existing data-plane Go gate; contract suites T026/T027 remain in their
documented self-SKIP until T044/T045/T047/T048/T050 land and then gate
this file end-to-end without further changes here.

## Out-of-scope

- `errortpl/render.go` (T048 v1 AUTH_REQUIRED renderer; T071 route
  codes): this file defines the `ErrorRenderer` seam only.
- `forward/tor.go` (T047): upstream dial, SOCKS5h handshake, byte-pipe
  pump, the 30 s upstream constant, `RouteError` classification. This
  file defines the `Tunneler` seam only.
- `auth/token.go` (T044): HMAC verifier list, constant-time
  compare-every-slot. This file formats-gates the candidate and calls
  the reused `Verifier` seam.
- T050's wiring (`HandleConnect` closure into `Deps.Connect`), the
  audit counters (T049), the control client (T045).
- Contract suites under `tests/contract/` (T026/T027/T065) — they
  exist tests-first and self-skip until the boot trio (T044/T045/T050)
  plus T047/T048 land.
- The SOCKS5 path (`socks5.go`) — untouched by this ticket.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
