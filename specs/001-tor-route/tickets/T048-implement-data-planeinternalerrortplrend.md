---
id: T048
title: 'Implement `data-plane/internal/errortpl/render.go`'
status: pending
created: 2026-07-04
last_updated: 2026-09-04
source: tasks.md#T048
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T027, T068a]   # T068a/T027 are the Principle-VII test-first gates (T096)
parallel: false
files_budget: 8
privacy_critical: true
tests_first: [T068a, T027]   # T096/M6: T068a MUST be done before this impl (Constitution VII)
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/error-template.md (§"Wire format" status/headers/body, §"Leak-corpus invariant", §"Contract tests" rows 1+7)
  - specs/000-architecture/spec.md §10 (10.1 codes, 10.2 body template, 10.3 test pattern)
  - specs/001-tor-route/spec.md FR-006, FR-009
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T048: Implement `data-plane/internal/errortpl/render.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/errortpl/render.go` — render the template literal from T019 for the `AUTH_REQUIRED` case on the CONNECT path; emit exactly four headers in declared order; generate `LOCAL_REFERENCE_ID` via `crypto/rand.Read(8)` + hex (16 chars). Verified by T027. Extended in T071 for the remaining error codes.

## Analysis

Required (`privacy_critical: true`) — full property map. Grounded 2026-09-04
against the contract, the landed listener seam, and the two done tests-first
suites that gate this file (T027 `auth_required_test.go`, T068a
`header_set_test.go` — both content-gate on `errortpl/render.go` existing).

**Scope split (binding):** T048 renders `AUTH_REQUIRED` ONLY — the task body
names that single case. `ROUTE_DOWN`/`ROUTE_REFUSED`/`ROUTE_TIMEOUT` are
T071's extension (`requireImplMarker` in T068a gates the route sub-tests on
the `ROUTE_DOWN` marker landing in render.go, so an early full table would
lift them prematurely and gut T071). T047 §Out-of-scope records the same
split ("ROUTE_REFUSED errortpl wiring: T071/T072").

**Seam obligation (verified on disk):** `listener.ErrorRenderer`
(`connect.go:92`) — `WriteFailure(w io.Writer, code ErrorCode) error`;
`ConnectDeps.Renderer` must be non-nil whenever `HandleConnect` runs
(T050 composition root). The implementation therefore lives in package
`errortpl` importing `listener` for the `ErrorCode` type (no cycle:
`listener` never imports `errortpl`). The renderer writes bytes only;
closing the connection stays with `HandleConn`'s defer (the contract's
"DP closes after the error response" is already owned by the listener).

- **Must hold (property map)**
  - Byte-exact response assembly, never `net/http` (forbidden-header
    tripwire: T068a (g) scans for `Server`/`Date`/`Connection`/
    `Keep-Alive`/`Transfer-Encoding` — Go's defaults if `http.Server`
    touches the response): status line `HTTP/1.1 407 Proxy
    Authentication Required\r\n` (contract §"Status line" AUTH_REQUIRED
    row; pinned byte-for-byte by T027's `wantStatusLine`), then exactly
    four headers in declared order — `Content-Type: text/html;
    charset=utf-8`, `Content-Length: <ASCII decimal of body length>`,
    `Cache-Control: no-store`, `X-Stargate-Error: AUTH_REQUIRED` —
    CRLF-terminated, block terminated by `\r\n\r\n` (T027
    `assertStatusShape`; T068a `assertHeaderBlock` (a)–(f)).
  - Body = `errortpl.Template` (T019's byte-pinned literal) with exactly
    the three permitted substitutions — `{ROUTE_LABEL}`→`Tor`,
    `{CODE}`→`AUTH_REQUIRED`, `{LOCAL_REFERENCE_ID}`→16 lowercase hex —
    LF endings, no trailing newline, no other byte varied (T027
    `assertBodyTemplate`, anchored full-literal match; contract
    §"Response body" "byte-for-byte ... with the three permitted fields
    substituted").
  - `LOCAL_REFERENCE_ID` is fresh per response from `crypto/rand.Read(8)`
    hex-encoded lowercase (16 chars) and derived from NOTHING
    request-derived — never the token, destination, timestamp, or source
    port (contract §"Response body" bullet 3). Fresh-per-response is what
    T027's structural-equality check relies on (the ONLY allowed
    differing bytes are the 16-byte ref-ID slot).
  - The response carries no request-derived data at all: destination,
    offered/rejected token, its hash, or any proxy identity
    (FR-006/FR-009; T027 (d) corpus scan; T068a (h) header-byte scan).
    By construction here: the only variable bytes in the response are
    the ref-ID and the Content-Length digits.
  - Non-`AUTH_REQUIRED` codes write ZERO bytes and return an error:
    their wire shape is T071's; inventing it here would (a) redefine a
    wire shape outside the contract-review loop and (b) prematurely lift
    T068a's `requireImplMarker` route gates. `HandleConnect` ignores the
    renderer's error (best-effort reply semantics, pinned at
    `connect.go:131`), so the failure mode is a silent close — the same
    no-framing precedent as the SOCKS5 framing-garbage row. → Residue,
    below.
- **Gated (verify.sh catches fail-closed once this file lands)**
  - Every byte-shape property above: T027 + T068a self-lift from SKIP to
    FAIL-forcing (process-level, through the real DP binary via
    dpharness).
  - Compile-time seam conformance: `var _ listener.ErrorRenderer =
    (*Renderer)(nil)` shape-asserted in render.go.
  - gofmt / go vet / staticcheck / gosec / race under the data-plane
    container gate.
- **Residue (no gate catches; scoped for review/redteam)**
  - The T048→T071 window: a CONNECT route failure (upstream dial fails)
    gets a silent close instead of the contract's 502/504 template,
    because the route-code table is T071's. Availability degradation
    only — zero response bytes cannot leak (Principle III holds
    trivially). Closes when T071 lands; recorded so the window is
    visible, not silent.
  - Ref-ID distinctness/uniformity at volume and ref-ID-unlinkedness —
    T069's `reference_id_*` tests (pending); the unit test below pins
    only shape (16 lowercase hex) and freshness (differs across
    draws).
  - Live-stack corpus items (egress IP, exit IP, .onion corpus) in the
    §"Leak-corpus invariant" — exercised by the T065–T067 suites and the
    milestone T078 sweep, not by the harness-isolated T027/T068a runs.

## Acceptance

Tests-first (Constitution Principle VII): T068a + T027 are done and
self-skip on this file's absence — landing render.go lifts their
`AUTH_REQUIRED` sub-tests to FAIL-forcing. Additionally the in-package
unit suite below is authored and failing BEFORE render.go lands.

In-package suite `data-plane/internal/errortpl/render_test.go`, each test
driving `Renderer.WriteFailure` into a `bytes.Buffer`:

- `TestWriteFailureAuthRequiredShape` — output is exactly:
  status line `HTTP/1.1 407 Proxy Authentication Required\r\n` +
  `Content-Type: text/html; charset=utf-8\r\n` + `Content-Length: N\r\n`
  (N = actual body length, ASCII digits) + `Cache-Control: no-store\r\n`
  + `X-Stargate-Error: AUTH_REQUIRED\r\n` + `\r\n` + body, where body ==
  `Template` with the three substitutions and LF endings (compare
  against `strings.ReplaceAll` on the literal — the same construction
  the renderer must use, so drift fails).
- `TestWriteFailureRefIDIsFreshLowercaseHex` — across repeated renders:
  the 16-char slot parses as lowercase hex, and the slot values differ
  between two renders of the same request shape (freshness;
  distribution/uniqueness-at-volume stays with T069).
- `TestWriteFailureNoRequestDataInOutut` — rendering with a code value
  only: the output bytes contain no caller-suppliable field (the API
  shape itself is the gate — there is no parameter that could carry the
  destination or token), and the ref-ID slot is the only
  render-to-render variable.
- `TestWriteFailureRouteCodesWriteNothing` — `ROUTE_DOWN`,
  `ROUTE_REFUSED`, `ROUTE_TIMEOUT`: zero bytes written, non-nil error
  (T071's lift point pinned as deliberate, not forgotten).
- `scripts/verify.sh` green from repo root; the process-level lift is
  `go test ./tests/contract/error-template/ -run
  'TestAUTHRequiredConnectPath|TestHeaderSet/AUTH_REQUIRED'` (from
  `tests/contract`, the self-lifted T027 + T068a sub-tests) PASS.

## Out-of-scope

- Route-code rendering (`ROUTE_DOWN`/`ROUTE_REFUSED`/`ROUTE_TIMEOUT`
  status rows) — T071 extends this file; T048 writes zero bytes for
  those codes (§Analysis residue).
- Upstream-failure classification refinement — T072 (`forward/tor.go`).
- Boot wiring of the renderer into `ConnectDeps.Renderer` — T050.
- `SOCKS5`-path failure replies — binary RFC 1928/1929 shapes owned by
  the landed listener/forward surfaces; no HTML body on that path
  (contract §"Scope").
- The template literal itself — T019's `template.go`, byte-pinned;
  this ticket only substitutes into it.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
