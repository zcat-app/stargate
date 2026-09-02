---
id: T068a
title: 'Contract test for the **response-header invariants** of the privacy-sa'
status: pending
created: 2026-07-04
last_updated: 2026-09-02
source: tasks.md#T068a
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: [T009]   # T096/M6: removed inverted T048 dep — the test must NOT wait on its impl (Constitution VII)
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-009" (HTTP CONNECT path emits the privacy-safe template with the exactly-four headers; the upstream dial/handshake result alone decides the route error — a SidecarEvent is advisory only)
  - specs/001-tor-route/spec.md §"User Story 3 acceptance-scenario 2" (headers contain exactly Content-Type, Content-Length, Cache-Control: no-store, and X-Stargate-Error — and no other headers; no Server, no Via, no X-Forwarded-*, no sidecar version strings)
  - specs/001-tor-route/contracts/error-template.md §"Wire format · Response headers" ("Exactly these four headers, in this order, no others" + the Forbidden list)
  - specs/001-tor-route/contracts/error-template.md §"Contract tests" row `header_set_test.go` (four headers in declared order; forbidden set plus net/http defaults; Content-Length matches the body on the wire; leak scan over every header byte)
  - specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant" (corpus definition scanned over every header byte)
  - specs/001-tor-route/contracts/socks5-auth.md §"Deadlines" (the 30 s dial-and-handshake deadline maps to ROUTE_TIMEOUT; the fake's slow-mode delay is strictly greater so the DP times out deterministically)
decision_refs:
  - specs/001-tor-route/research.md §7 (synthetic SOCKS5 backend instead of the live Tor network for contract tests)
  - specs/001-tor-route/tickets/T027-contract-test-for-authrequired-on-connec.md (the AUTH_REQUIRED per-code setup mirrored here; same Go package, so its dial/capture/split helpers are reused directly)
  - specs/001-tor-route/tickets/T065-contract-test-testscontracterror-templat.md, T066, T067 (the per-code route-failure setups the task body cites; all three are pending, so T068a mirrors them inline to stay parallel-safe)
  - specs/001-tor-route/tickets/T026-contract-test-for-http-connect-auth-succ.md (WithUpstream + fake-upstream wiring; admission/dial NOT gated on a SidecarEvent — no HEALTHY pushed, T090 / sol-review B3)
  - specs/001-tor-route/tickets/T048-implement-data-planeinternalerrortplrend.md, T071, T072 (the gated renderer and route-mapping surfaces; T071/T072 EXTEND files that already exist once T048/T047 land, so those skips gate on content markers, not file existence)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T068a: Contract test for the **response-header invariants** of the privacy-sa

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for the **response-header invariants** of the privacy-safe template — `tests/contract/error-template/header_set_test.go`. Gates FR-009 + spec US3 acceptance-scenario 2 ("they contain exactly `Content-Type`, `Content-Length`, `Cache-Control: no-store`, and `X-Stargate-Error: <CODE>` — and no other headers") + error-template.md §"Response headers" ("Exactly these four headers, in this order, no others"). For one CONNECT-path failure of each of the four codes (`AUTH_REQUIRED`, `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`) — using the per-code setups from T065–T067 + T027 — capture the response header block (every byte from the status line up to and including the blank line that terminates headers). Assert: (a) **header count is exactly four**; (b) **order matches the contract** — `Content-Type`, `Content-Length`, `Cache-Control`, `X-Stargate-Error` (case-sensitive, as serialised on the wire); (c) `Content-Type: text/html; charset=utf-8` byte-for-byte; (d) `Content-Length` parses to a non-negative integer that matches the actual body length emitted in the same response; (e) `Cache-Control: no-store` byte-for-byte; (f) `X-Stargate-Error: <CODE>` where `<CODE>` matches the failure code under test; (g) **no occurrence of any forbidden header name** in the captured block — the closed set asserted absent is `{Server, Via, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-Port, Proxy-Agent, Date, Connection, Keep-Alive, Transfer-Encoding}` (the spec's enumerated forbidden list plus the headers Go's `net/http` server adds by default if not suppressed, so a regression to `http.Server` defaults trips this test); (h) leak-corpus scan over every captured header byte (corpus per error-template.md §"Leak-corpus invariant") returns zero hits. Pairs with T048/T071 (the renderer is what enforces the header set on the wire). T068a MUST be authored and failing before T048 lands (Principle VII — header handling is a privacy-critical category per the constitution discipline table).

## Analysis

T068a is tests-first (Constitution Principle VII — header handling is a
privacy-critical category per the constitution discipline table) and is
authored BEFORE T048 lands. The contract under test is
`contracts/error-template.md` §"Response headers" ("Exactly these four
headers, in this order, no others") applied on the HTTP CONNECT path to
one failure of EACH of the four codes. Grounding found the setups this
test mirrors: T027's AUTH_REQUIRED fixture is DONE (bare
`dpharness.Start`, token generation 1, CONNECT without
`Proxy-Authorization`) and lives in the same Go package
(`tests/contract/error-template`, package `errortemplate`), so its
capture/split helpers are reused directly; T065–T067 (the three
route-failure setups) are all PENDING, so their setups are mirrored
inline to keep this ticket parallel-safe (`blocked_by: [T009]` only):
ROUTE_DOWN = `WithUpstream` pointing at a bind-then-released loopback
port (TCP RST — the dial result alone decides, FR-009/T090/sol-review
B3); ROUTE_REFUSED = a package-local synthetic upstream that completes
the SOCKS5 handshake then replies REP=0x04 (the wire shape the real
sidecar produces for a non-resolvable `.onion`; T019a's shared fake has
NO refusing mode, and a file-local backend keeps this ticket to its
single named artifact — promotion into the shared fake is T066's call);
ROUTE_TIMEOUT = the shared fake in `Slow` mode with a first-write delay
STRICTLY GREATER than the DP's 30 s dial-and-handshake deadline
(`contracts/socks5-auth.md` §"Deadlines") so the DP deterministically
fires first. No `HEALTHY` is pushed anywhere (T026/T090 precedent:
admission and dialing are not CP-gated), and per-code sub-tests make a
DP that misroutes one code to another's response FAIL via assertion (f).

- **Must hold:**
  - **Header count is exactly four** (task-body (a); error-template.md
    §"Response headers"; Principle I/III). The captured block (status
    line through the blank line) carries exactly four header lines —
    any fifth header (or a folded continuation line) fails.
  - **Order matches the contract, case-sensitive on the wire** (task-body
    (b)): `Content-Type`, `Content-Length`, `Cache-Control`,
    `X-Stargate-Error` in that byte-exact name order.
  - **Byte-exact `Content-Type: text/html; charset=utf-8`** (c) and
    **`Cache-Control: no-store`** (e) — no charset variation, no
    whitespace variation, no quoting.
  - **`Content-Length` framing integrity** (d): the value parses (ASCII
    digits only — no sign, no space) to a non-negative integer equal to
    the body bytes actually emitted in the SAME response (first
    `\r\n\r\n` terminates headers; body is LF-ended per §"Response
    body"). A DP that lies about the length, or emits
    `Transfer-Encoding` instead, fails here / at (g).
  - **`X-Stargate-Error: <CODE>`** (f) where `<CODE>` is the failure
    code under test — pins per-code code-marking and catches a DP that
    misroutes one failure kind to another code's response.
  - **No forbidden header name anywhere in the captured block** (g): the
    closed case-insensitive set `{Server, Via, X-Forwarded-For,
    X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-Port, Proxy-Agent,
    Date, Connection, Keep-Alive, Transfer-Encoding}` — the spec's
    enumerated list plus the headers Go's `net/http` server adds by
    default, so a regression to `http.Server` defaults trips. Case-
    insensitive so a folded-case regression cannot slip the literal
    scan; the four required headers contain none of these substrings,
    so there is no false-positive surface. Belt-and-braces with (a)+(b):
    a byte-exact four-line block already excludes extras, but (g) gives
    the precise diagnostic when the DRIFT is the extra header itself.
  - **Zero-hit leak-corpus scan over every captured header byte** (h):
    corpus = this test's destination + its bearer token (distinct from
    T025a/T025b/T026/T027's so a hit is attributable) + the fixed
    version-string and backtrace fragments of error-template.md
    §"Leak-corpus invariant", in all nine textual renderings
    (loginvariants). Diagnostics are index/encoding-only — the block
    bytes themselves are never echoed (a buggy DP may have smuggled the
    destination into a header value; echoing the block re-leaks it).
  - **Tests-first self-skip** (Principle VII): content-gates on the
    boot minimum inside `dpharness.Start` (T042/T045/T050),
    `listener/connect.go` (T043), `auth/token.go` (T044),
    `errortpl/render.go` (T048), `forward/tor.go` (T047). T071
    (route-code rendering) and T072 (failure mapping + the 30 s
    constant) EXTEND `render.go` and `tor.go` — files that already
    exist once T048/T047 land — so the route sub-tests additionally
    gate on content markers (the route-code identifiers those tickets
    must introduce) instead of file existence; without this, the skip
    would lift early and turn the route sub-tests red in the window
    between T048 and T071/T072. All skips self-lift as the surfaces
    land, then a header-set regression is FAIL, not SKIP.
- **Gated:**
  - `gofmt` / `go vet` / `-race` over the new file via the acceptance
    command; license header via verify.sh Gate 1.
  - Status-line shape and per-code template bodies + full-response leak
    scans are T065–T067's gated surface; T068a consumes only the
    captured header block plus the body LENGTH for (d).
  - Body byte-match (T068), ref-ID uniqueness/unlinked (T069), and the
    structural no-distinguishing-substring property (T027) gate the
    body and ref-ID dimensions this test deliberately does not restate.
  - The leak scanner's nine renderings are self-tested by
    `tests/internal/loginvariants/loginvariants_test.go` (T025a/T101).
- **Residue:**
  - **verify.sh Gate 2 runs only the `data-plane` module** — the
    `tests/contract` Go tests execute via this ticket's acceptance
    command (and future CI wiring), not the single green gate.
    Pre-existing gap inherited from T022–T027; promotion is a
    follow-up ticket, out of scope here.
  - **The SOCKS5 path has no header block** — post-auth route failures
    there are 10-byte RFC 1928 replies (T067a) and auth failure is the
    2-byte `01 FF` (T024/T025); this test's invariants are CONNECT-path
    only by contract.
  - **Status-line shape is unchecked here** — the captured block
    includes the status line (it is capture metadata), but its
    per-code byte shape is T065–T067's assertion; T068a would only
    observe a malformed status line indirectly, via the header-line
    split.
  - **DISABLED-mask cross-cut** (route never marked HEALTHY vs marked)
    is not exercised — no event is pushed at all (T090/B3 precedent);
    the mask-state cross-cut is T073's surface.
  - **Redteam scope (privacy-critical, non-empty residue):** hunt for
    (a) a block-capture boundary bug — splitting on a LATER `\r\n\r\n`
    or mis-sizing the terminator would mis-split count vs order
    assertions; the FIRST `\r\n\r\n` in the response is the header
    terminator by construction; (b) any diagnostic that echoes header
    VALUES, the body, or the destination/token into CI output on
    failure — assertions report index/length/rule only (the
    loginvariants discipline); (c) a forbidden-name scan that is
    case-sensitive or anchored to line starts only — a folded-case or
    obs-fold-smuggled forbidden header must trip (g) even when (a)+(b)
    somehow pass; (d) a Content-Length comparison that normalises
    (`+5`, leading spaces, `0x` forms must FAIL to parse, not parse
    leniently); (e) the ROUTE_TIMEOUT setup racing the DP's 30 s
    deadline — the fake's delay must be strictly greater so the DP
    deterministically fires first, and the read deadline must bound a
    DP that NEVER times out (fails at the deadline rather than hanging
    the run); (f) a DP that keeps the connection open after the error
    response — the read-until-EOF strategy must fail bounded (deadline)
    rather than hang, mirroring T027's wedged-DP handling.

## Acceptance

### Named test

**NEW: `tests/contract/error-template/header_set_test.go`** — package
`errortemplate` (the existing T027 package; header_set reuses its
capture/split helpers in-package). `TestHeaderSet` with four sub-tests,
one per code, each on its OWN harness (the four setups need different
upstream wiring):

1. **`TestHeaderSet/AUTH_REQUIRED`** — T027's setup verbatim: bare
   `dpharness.Start` (no upstream — auth fails before the forward path
   is consulted), token generation 1 pushed and `APPLY_STATUS_OK`,
   `CONNECT <dest>:443 HTTP/1.1` with NO `Proxy-Authorization`.
   Gates: connect.go (T043), token.go (T044), render.go (T048).
2. **`TestHeaderSet/ROUTE_DOWN`** — `dpharness.WithUpstream` pointed at
   a bind-then-released loopback port (`dpharness.FreeLoopbackAddr`):
   nothing listens, the dial gets TCP RST → `ROUTE_DOWN` (FR-009: the
   dial result alone decides; no `HEALTHY` pushed). Valid bearer auth
   on the CONNECT. Gates: + forward/tor.go (T047) and the T071/T072
   content markers.
3. **`TestHeaderSet/ROUTE_REFUSED`** — `WithUpstream` pointed at the
   package-local synthetic upstream that completes the SOCKS5
   handshake (mirroring the shared fake's method-selection +
   RFC 1929 sub-negotiation surface) then replies REP=0x04 →
   `ROUTE_REFUSED`. Valid bearer auth. Same gates as ROUTE_DOWN.
4. **`TestHeaderSet/ROUTE_TIMEOUT`** — `WithUpstream` pointed at the
   shared `tests/integration` fake in `Slow` mode with
   `WithLatency(45s)` — strictly greater than the DP's 30 s
   dial-and-handshake deadline (`contracts/socks5-auth.md`
   §"Deadlines"), so the DP deterministically fires `ROUTE_TIMEOUT`
   first; the sub-test's read deadline (90 s) bounds a DP that never
   times out. Valid bearer auth. Same gates as ROUTE_DOWN.

Each sub-test captures the full response (read until EOF on a bounded
deadline; the DP closes after the error response), splits at the FIRST
`\r\n\r\n` into header block (status line through terminator) and body,
and asserts the eight task-body invariants:

- **(a)** the block carries exactly four header lines;
- **(b)** names in wire order `Content-Type`, `Content-Length`,
  `Cache-Control`, `X-Stargate-Error`, case-sensitive;
- **(c)** `Content-Type: text/html; charset=utf-8` byte-for-byte;
- **(d)** `Content-Length` value is ASCII digits only, parses to a
  non-negative integer equal to `len(body)` from the same capture;
- **(e)** `Cache-Control: no-store` byte-for-byte;
- **(f)** `X-Stargate-Error: <CODE>` with `<CODE>` = the code under test;
- **(g)** none of the eleven forbidden names appears as a substring of
  the block (case-insensitive): `Server`, `Via`, `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`,
  `Proxy-Agent`, `Date`, `Connection`, `Keep-Alive`,
  `Transfer-Encoding`;
- **(h)** `loginvariants.AssertNoSecrets` over the block bytes with
  this test's destination + token + the fixed §"Leak-corpus invariant"
  fragments (`Server: tor/`, `Tor`, `Tor Browser`, `Mandrel`,
  `Quarkus`, `Hibernate`, `SQLite`, `panic:`, `goroutine`,
  `stack trace`, `at line`).

Failure diagnostics report index/length/rule only — header VALUES,
body bytes, dest, and token are never echoed (§Analysis redteam
scope (b)).

### Runnable command

```sh
scripts/verify.sh &&
  (cd tests/contract && gofmt -l . && go vet ./error-template/... &&
   go test -race -count=1 -run TestHeaderSet ./error-template/...)
```

Today the test SKIPs at the content gates (T042/T043/T044/T045/T047/
T048/T050 unimplemented; T071/T072 markers absent) — each skip
self-lifts as implementation lands, matching the T023–T027 precedent.
`scripts/verify.sh` stays green (Gate 2 remains scoped to the
data-plane module; see §Analysis residue).

## Out-of-scope

- **Per-code status lines, per-code template bodies, and full-response
  leak scans** — T065/T066/T067's scope. T068a consumes only the
  header block plus the body length for (d), and its ROUTE_DOWN/
  REFUSED/TIMEOUT setups mirror (not preempt) those tickets' fixtures;
  when T065–T067 land in the same package they may consolidate the
  shared setup helpers.
- **Body byte-match against the template** — T068 (`body_byte_match_test.go`).
- **Ref-ID uniqueness / unlinkedness** — T069.
- **The structural no-distinguishing-substring property (missing vs
  malformed)** — T027, already landed.
- **SOCKS5-path failure bytes** (REP mapping `0x03/0x04/0x06`, sub-
  negotiation `01 FF`) — T067a/T067b; there is no header block on that
  path.
- **Renderer implementation (T048/T071) and failure-mapping + 30 s
  constant (T047 base / T072)** — this ticket only gates on their
  artifacts.
- **Counter-increment asymmetry** — T067b.
- **Adding a Refuse mode to the shared `tests/integration` fake** —
  T068a ships a package-local REP=0x04 backend to stay within its
  single named artifact; promoting a `Refuse` mode into
  `fake_socks5_tor.go` is T066's call (same package can reuse the
  local backend until then).
- **DISABLED-vs-HEALTHY mask-state cross-cut** — T073.
- **Wiring a `tests/contract` go-test gate into scripts/verify.sh** —
  pre-existing gap inherited from T022–T027; follow-up ticket
  (§Analysis residue).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
