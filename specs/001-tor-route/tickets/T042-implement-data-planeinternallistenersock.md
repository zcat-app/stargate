---
id: T042
title: 'Implement `data-plane/internal/listener/socks5.go`'
status: in-review
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T042
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
  - "specs/001-tor-route/contracts/socks5-auth.md §\"Two inbound protocols, one port\" (demux table: 0x05 / 'C' / anything-else-silent-close)"
  - "specs/001-tor-route/contracts/socks5-auth.md §\"Auth method negotiation\" (0x02 wins anywhere in the list; NO_AUTH-only → 0x05 0xFF + close)"
  - "specs/001-tor-route/contracts/socks5-auth.md §\"Username/password sub-negotiation\" + §\"Auth failure response\" (01 00 on pass; 01 0xFF + close on every failure, no distinguishing bytes)"
  - "specs/001-tor-route/spec.md FR-005 (port 8881 listener), FR-006 (auth, 01 0xFF surface, no token/dest in any response or log), FR-007 (UNAME verbatim, SOCKS5h, no local resolution), FR-008 (count only auth-passed requests)"
  - "specs/001-tor-route/data-model.md §1.5 (HMAC-SHA-256 verifier, compare-every-slot) + §1.7 (pepper file — read by T044, not this ticket)"
  - "THREAT-MODEL.md §3.1 Local profile (same-host unprivileged processes must not proxy without the token)"
  - "specs/001-tor-route/research.md §9 (SOCKS5 failure is the 2-byte reply only — never the HTML template)"
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T042: Implement `data-plane/internal/listener/socks5.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/listener/socks5.go` — first-byte demultiplex (`0x05` vs `'C'`), RFC 1928 method negotiation (require `0x02` USERNAME/PASSWORD; reject NO_AUTH-only with `0x05 0xFF`), RFC 1929 sub-negotiation framing. Verified by T023, T024, T025.

## Analysis

Property map (grounding-verified 2026-09-03; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (body-vs-reality items):**

1. **The file owns the whole inbound SOCKS5 framing, not just three
   named phases.** The task body headlines demux + method negotiation +
   RFC 1929 framing, but ground truth (plan.md project tree —
   "listener/socks5.go # port 8881 listener"; the verifying tests) shows
   the request-phase read (RFC 1928 §4: VER/CMD/RSV/ATYP/target/port)
   has no other owning ticket: T047 owns only the *upstream* dial+pipe,
   T050 owns only the accept loop + wiring. The inbound request-phase
   parse therefore lands in this file, immediately after the `01 00`
   success reply, handing `(client conn, UNAME bytes, target string)` to
   the forward seam. Without it, T024(c) UNAME_ForwardedVerbatim and
   T067a have no implementation to gate.
2. **Seams are consumer-defined interfaces in this file** (Go
   consumer-side idiom): T044 (`auth/token.go`), T047 (`forward/tor.go`),
   T049 (`audit/counters.go`) do not exist yet and must not be imported.
   `Deps{Auth, Forward, Audit, Connect}` is the single wiring point T050
   fills; `Connect func(net.Conn)` is T043's handler (closure-wired by
   T050), because referencing `connect.go` symbols from this ticket would
   expand scope into T043's file. All fields are required non-nil at
   HandleConn time (T050 wires them together with the packages they
   delegate to) — no nil guards inside the trust boundary (CONTRIBUTING
   doctrine).
3. **No syntactic token-format gate on the SOCKS5 path.** research.md §9
   and tests/contract/socks5/auth_required_test.go pin byte-identity
   across the whole AUTH_REQUIRED family: every PASSWD (1–255 bytes,
   well-formed or not) funnels through the auth seam's hash+compare to
   the same `01 0xFF`. The `^[0-9a-f]{32}$` gate is CONNECT-path-only
   (T043). The `VerifyPassword([]byte) bool` seam takes raw bytes and
   this file never inspects them (FR-006; Principle I).
4. **Single-owner connection lifecycle.** The listener owns the client
   conn for its whole life (one `defer Close` in HandleConn); the
   `Forwarder` seam owns the upstream conn and the byte pipe but MUST
   NOT close the client (contract documented on the interface). This
   removes every double-close/leak branch at the T042/T047 boundary.
5. **Bounded handshake reads, deadline-free byte pipe.** Inbound framing
   reads run under one generous deadline (named constant, 30 s — the
   contract's handshake-phase ceiling); it is cleared (`SetDeadline`
   zero) immediately before the forward handoff because the post-BND
   phase has NO idle deadline (contracts/socks5-auth.md §"Deadlines";
   T025b byte-pipe invariant; Principle I).

- **Must hold:**
  - First-byte demux: `0x05` → SOCKS5 path; `0x43` ('C') → the CONNECT
    seam with the conn positioned after the consumed first byte (held
    open — never a SOCKS5 reply, never a close); anything else → close
    with ZERO response bytes (FR-005; contract demux table; T023 d/e).
  - Method negotiation: `0x02` offered anywhere in the methods list →
    reply EXACTLY `0x05 0x02` and wait for sub-negotiation (no trailing
    bytes, no close); list without `0x02` (incl. NO_AUTH-only, incl.
    NMETHODS=0) → reply EXACTLY `0x05 0xFF` then close (THREAT-MODEL
    §3.1 — same-host processes never get free proxy access; T023 a/b/c,
    T025(e)).
  - RFC 1929 framing: read `VER ULEN UNAME PLEN PASSWD` exactly
    (ULEN/PLEN 1–255; ULEN=0/PLEN=0/VER≠0x01 are framing failures);
    auth pass → reply EXACTLY `0x01 0x00` then proceed to the request
    phase; any failure → reply EXACTLY `0x01 0xFF`, then close, no
    further bytes, byte-identical across the whole failure family
    (FR-006; research.md §9; T024 a/b, T025(a), T028).
  - UNAME is opaque: passed VERBATIM (byte-for-byte) to the forward
    seam; never inspected, parsed, normalised, logged, or echoed
    (FR-007; T024(c)).
  - PASSWD handed to the auth seam raw; this file performs no format
    gate, no hashing, no comparison, and never logs any candidate byte
    (finding 3; Principle I; FR-006 forbidden behaviours).
  - No per-request log line anywhere in this file — nothing on stderr
    for framing, auth failure, or success (FR-008; T025(d) journal-delta
    scan; the log allowlist is T025a's).
  - Counters: the audit seam fires exactly once per auth-passed request,
    BEFORE the request phase (FR-008: auth failures leave counters
    untouched; route failures still count — T025c/T025d/T067b).
  - Request-phase failures after auth pass: 10-byte reply
    `05 <REP> 00 01 00×6` with BND.ADDR/BND.PORT always zeroed — never
    destination, upstream, or port-derived bytes; then close, no further
    bytes (FR-009; contract §"SOCKS5 request-phase failures"; T067a's
    future gate). REP comes from the route error; unpinned fallback is
    `0x01` (RFC general failure); CMD≠CONNECT → `0x07`; unknown ATYP →
    `0x08` (RFC 1928 §6; none of these three pinned by a test yet —
    see Residue).
  - Target rendered without any name resolution (ATYP=0x03 domain
    forwarded verbatim as string; ATYP=0x01/0x06 formatted as IP
    literals) — no DNS anywhere in this file (FR-007; Principle III).
  - Principle I byte budget: this file parses ONLY the framing fields
    named above — no header/payload inspection, no TLS, no per-request
    timestamps.
- **Gated** (verify.sh catches fail-closed):
  - `go build` / `go vet` / staticcheck / gosec gate the syntactic
    surface and a class of correctness bugs (data-plane Go gate).
  - `go test ./internal/listener/` — the in-package unit test this
    ticket ADDS (`socks5_test.go`, net.Pipe + stub seams) pins every
    byte shape above NOW, without waiting for T044/T045/T050: demux
    rows, method negotiation a/b/c, sub-negotiation success/failure,
    UNAME verbatim pass-through, auth-fail counter silence, 10-byte
    zeroed failure reply, silent close. (Residue promotion — the
    contract suites cannot leave SKIP until T044/T045/T050 land, so the
    byte contract would otherwise be ungated at this ticket's review.)
  - License-header check gates the SPDX header.
  - Contract suites T023/T024/T025/T028 (process-level, via dpharness)
    gate the same shapes end-to-end once T044/T045/T050 land — their
    `dpharness.Start` content-gate self-lifts then; T042's contribution
    is exercised by them from that moment on.
- **Residue:**
  - CMD≠CONNECT → `0x07`, unknown ATYP → `0x08`, and post-auth framing
    garbage → silent close are RFC-correct choices NOT pinned by any
    contract test (T067a pins only ROUTE_DOWN/REFUSED/TIMEOUT). Promoted
    partially: the in-package unit test pins the `0x07` and
    ATYP=0x09→`0x08` rows only. The post-auth framing-garbage
    silent-close row has no automated pin — production behaviour was
    verified by reading (readRequestTarget returns the silent-close
    branch) and awaits T067a's contract-level pin (or an 8-line
    in-package silent-close case there if T067a lands late). Follow-up
    note for that ticket, not a new ticket.
  - "The reply is flushed before close on every failure path" is
    kernel-buffered (write-then-close delivers data+FIN) and is covered
    by the unit test's EOF-after-reply assertions on net.Pipe; a TCP-
    level regression would only surface in the dpharness suites post-
    T050. Accepted (loopback profile, standard Go net semantics).
  - The inbound 30 s framing deadline is a DoS bound, not a privacy
    property; no test can pin "no goroutine leak under stalled clients"
    cheaply. Accepted for v1 (local profile; bound is generous); the
    constant is named for one-edit re-tuning.

## Acceptance

1. **`data-plane/internal/listener/socks5.go` exists** and compiles:
   `cd data-plane && go build ./... && go vet ./...` — PASS.
2. **`data-plane/internal/listener/socks5_test.go` (added by this
   ticket) passes**: `cd data-plane && go test ./internal/listener/` —
   PASS. Named cases (net.Pipe client ↔ HandleConn server, stub
   Verifier/Forwarder/Audit/Connect):
   - `Demux_SilentClose_UnknownFirstByte` — 'G' → EOF, zero bytes.
   - `Demux_ConnectRouted` — 'C' reaches the Connect seam; conn held.
   - `Method_UserPassOnly_0502`, `Method_Mixed_0502`,
     `Method_NoAuthOnly_05FF_Close`, `Method_EmptyMethods_05FF_Close` —
     exact 2-byte replies; held-open vs close as contracted.
   - `Subneg_Success_0100_ThenRequestPhase` — `01 00` exactly, audit
     seam fired exactly once, request-phase target rendered
     (`example.onion:443`, ATYP=0x03) and UNAME bytes forwarded
     verbatim, deadline cleared before handoff.
   - `Subneg_Failure_01FF_Close_NoCounter` — auth seam false → `01 0xFF`
     + EOF; audit and forward seams never fired.
   - `Subneg_MalformedFraming_01FF` — VER≠0x01, ULEN=0, PLEN=0 → `01
     0xFF` + close, byte-identical.
   - `RequestPhase_RouteError_ZeroedBND` — route error → exact
     `05 03 00 01 00×6` + EOF (and `0x01` fallback for a plain error).
   - `RequestPhase_UnsupportedCmd_0507` / `RequestPhase_UnknownATYP_0508`.
3. **Existing suites stay green**: `bash scripts/verify.sh` — PASS
   (socks5 contract suites T023/T024/T025/T028 remain in their
   documented self-SKIP until T044/T045/T050 land; the data-plane Go
   gate now covers `internal/listener`).
4. **Byte-for-byte failure-surface check (hand-verifiable)**: the only
   bytes this file ever writes are `05 02`, `05 FF`, `01 00`, `01 FF`,
   and the 10-byte `05 <REP> 00 01 00×6` — grep the file for `Write`
   calls to confirm; no other responder exists.

## Out-of-scope

- `connect.go` (HTTP CONNECT framing — T043): this ticket only routes
  'C' to the `Deps.Connect` seam; the CONNECT parser, 407/200 paths,
  and the `^[0-9a-f]{32}$` format gate live there.
- `auth/token.go` (T044): HMAC verification, pepper loading, the
  compare-every-slot loop. This file defines the `Verifier` seam only.
- `forward/tor.go` (T047): upstream dial, UNAME pass-through to Tor,
  the byte-pipe pump, route-error classification (`ROUTE_DOWN`/
  `REFUSED`/`TIMEOUT`, the 30 s upstream constant). This file defines
  the `Forwarder`/`RouteError` seams only.
- `audit/counters.go` (T049) and all T050 wiring; `dp.sock` /
  `ReloadTokens` (T045); the error template (T048).
- Contract suites under `tests/contract/socks5/` — they exist
  (tests-first, T023/T024/T025/T028) and self-skip until the
  boot-minimum trio (T042+T045+T050) lands; they are this ticket's
  end-to-end gates from that moment.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
