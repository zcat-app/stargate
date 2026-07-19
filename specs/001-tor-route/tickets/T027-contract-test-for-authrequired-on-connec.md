---
id: T027
title: 'Contract test for `AUTH_REQUIRED` on CONNECT path in `tests/contract/e'
status: done
created: 2026-07-04
last_updated: 2026-07-07
source: tasks.md#T027
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
  - specs/001-tor-route/spec.md §"FR-005" (loopback 127.0.0.1:8881 listener; HTTP CONNECT is one of the two inbound framings on this port)
  - specs/001-tor-route/spec.md §"FR-006" (every inbound proxy request authenticated; HTTP CONNECT path on token absence/mismatch → HTTP 407 + AUTH_REQUIRED template; the offered token and the rejected destination MUST NOT appear in any response)
  - specs/001-tor-route/spec.md §"FR-009" (privacy-safe failure response shape per inbound protocol; both paths MUST NOT carry destination/upstream/token/sidecar-derived bytes in any response field)
  - specs/001-tor-route/contracts/error-template.md §"Contract tests" row 1 (auth_required_test.go: missing vs malformed → 407 + AUTH_REQUIRED, byte-for-byte identical except the LOCAL_REFERENCE_ID substitution slot)
  - specs/001-tor-route/contracts/error-template.md §"Response body" ({LOCAL_REFERENCE_ID} = 16-char lowercase-hex of crypto/rand.Read(8); NOT derived from request data; freshly generated per response)
  - specs/001-tor-route/contracts/error-template.md §"Response headers" (exactly four headers in declared order; the forbidden set including Proxy-Agent / Server / Via / X-Forwarded-*)
  - specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant" (scan every byte of status line + every header + body + X-Stargate-Error value for any corpus substring)
  - specs/001-tor-route/contracts/socks5-auth.md §"HTTP CONNECT path" (the auth-failure flow: parse request line + Proxy-Authorization only; token MUST match ^[0-9a-f]{32}$ before hashing; on absence/mismatch emit 407 + AUTH_REQUIRED template, then close)
  - specs/001-tor-route/contracts/socks5-auth.md §"HTTP CONNECT path · Invariants enforced by the contract test" (Missing Proxy-Authorization → 407 + AUTH_REQUIRED; Malformed token → 407 + AUTH_REQUIRED with no distinction from the missing case at the byte level; Response NEVER includes destination host/port or offered token)
decision_refs:
  - specs/001-tor-route/research.md §5 (contract-test harness language — Go)
  - specs/001-tor-route/research.md §9 (the two-framing split — T026 success / T027 failure divides on this; both are CONNECT-framed but T027 emits the privacy-safe template, so it lives under tests/contract/error-template/ per the directory convention in socks5-auth.md §"Two inbound protocols, one port")
  - specs/001-tor-route/tickets/T025-contract-test-for-socks5-leak-invariants.md (T025's AuthFailure_NoTokenBytesInCapture is the SOCKS5 analogue of T027; it established the bare-dpharness.Start + token-push + auth-failure-response-capture pattern with NO upstream and NO HEALTHY — the route-independent auth-failure setup T027 mirrors for the CONNECT path)
  - specs/001-tor-route/tickets/T026-contract-test-for-http-connect-auth-succ.md (T026 is the success-path twin; T027 is the failure-path half. T026 set the CONNECT-path content-gate + read-until-blank-line pattern T027 adapts for the close-after-AUTH_REQUIRED shape)
  - T069 (reference_id_unique_test.go + reference_id_unlinked_test.go own the distinct-ref-ID property — 1000-fixture uniqueness, uniformity, and same-request-two-distinct-ref-IDs; T027's structural-equality check deliberately does NOT assert ref-IDs are distinct across the two responses, only that no distinguishing substring exists outside the ref-ID slot. The two properties are orthogonal.)
reviews: { round: 1, date: 2026-07-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T027: Contract test for `AUTH_REQUIRED` on CONNECT path in `tests/contract/e

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for `AUTH_REQUIRED` on CONNECT path in `tests/contract/error-template/auth_required_test.go` — per `contracts/error-template.md` §"Contract tests" row 1 and `contracts/socks5-auth.md` §"HTTP CONNECT path · Invariants". Cases: (a) missing `Proxy-Authorization` → 407 + template; (b) malformed token → 407 + template with **no distinguishing substring** from the missing-header case (i.e. byte-for-byte identical *except for the `LOCAL_REFERENCE_ID` substitution slot*, which is freshly generated per response per error-template.md §"Response body" and is asserted distinct by T069). The test either mocks `crypto/rand` so both responses get a deterministic `LOCAL_REFERENCE_ID` and asserts literal byte equality, or compares the two responses structurally with the 16 hex-byte ref-ID slot excluded — whichever T048's render path more cleanly accommodates; (c) leak-corpus scan over response bytes for each of (a) and (b).

## Analysis

T027 is tests-first (Constitution Principle VII) for the HTTP CONNECT
`AUTH_REQUIRED` response shape and its no-distinguishing-substring
property — the failure-path half of the two-framing split
(research.md §9); T026 owns the success-path half. The contract under
test is `contracts/error-template.md` §"Contract tests" row 1 +
`contracts/socks5-auth.md` §"HTTP CONNECT path · Invariants" rows 1–2.
T025's `AuthFailure_NoTokenBytesInCapture` is the SOCKS5-analogue
precedent: T027 mirrors its route-independent setup (bare
`dpharness.Start`, one token push, NO upstream, NO HEALTHY — auth
fails before the forward path is consulted) and adds the
no-distinguishing-substring property unique to the CONNECT template
path (the SOCKS5 failure is a fixed 2-byte `01 FF`; the CONNECT
failure carries a renderable template body, so "identical modulo the
random ref-ID slot" is a non-trivial property the SOCKS5 path does
not need).

- **Must hold:**
  - **Exact `AUTH_REQUIRED` response shape** (contracts/error-template.md
    §"Wire format"; Principle I/III). On both `CONNECT <dest>:443
    HTTP/1.1\r\n\r\n` (no `Proxy-Authorization`) and `CONNECT <dest>:443
    HTTP/1.1\r\nProxy-Authorization: Bearer notatoken\r\n\r\n` the data
    plane responds with status line `HTTP/1.1 407 Proxy Authentication
    Required\r\n`, the header block, and a body byte-for-byte equal to
    `errortpl.Template` (T019) with `{ROUTE_LABEL}`="Tor",
    `{CODE}`="AUTH_REQUIRED", and `{LOCAL_REFERENCE_ID}`=a 16-char
    lowercase-hex run. A DP that emits the wrong status, the wrong
    code marker, or a body diverging from the Template (extra
    whitespace, missing element, wrong ROUTE_LABEL) is caught by the
    status-line + body-template assertions.
  - **No distinguishing substring between missing and malformed**
    (contracts/socks5-auth.md §"HTTP CONNECT path · Invariants" row 2;
    contracts/error-template.md §"Contract tests" row 1; Principle
    III). The two responses are byte-for-byte identical **except for
    the 16-char `LOCAL_REFERENCE_ID` slot**, which is freshly generated
    per response. A third-party observer cannot learn from the
    response bytes whether the client sent a missing header or a
    malformed token. Proven by masking the 16 ref-ID bytes in both
    captures and asserting byte equality on the remainder.
  - **No destination, malformed-token, or sidecar-derived byte in the
    response** (contracts/socks5-auth.md §"Invariants" rows 4–5;
    contracts/error-template.md §"Leak-corpus invariant"; Principle
    III; FR-006/FR-009). The 407 response carries neither the
    request's destination host nor the offered malformed token, in any
    of the nine textual renderings an accidental logger would produce.
  - **Tests-first self-skip** (Principle VII): content-gates on T043
    (`listener/connect.go` — the inbound CONNECT surface under test),
    T044 (`auth/token.go` — the bearer-verify failure path that
    produces `AUTH_REQUIRED`), and T048 (`errortpl/render.go` — the
    renderer that substitutes `{ROUTE_LABEL}`/`{CODE}`/
    `{LOCAL_REFERENCE_ID}` into the Template and emits the four
    headers), plus the boot minimum inside `dpharness.Start`
    (T042/T045/T050). SKIPs while any is absent and becomes a hard
    FAIL gate once all land.
- **Gated:**
  - `gofmt` / `go vet` / `-race` over the new file via the acceptance
    command; license header via verify.sh Gate 1.
  - First-byte demux `C`→CONNECT routing is pinned by T023 sub-test
    (d); T027 layers on a DP that already routes `C` down the CONNECT
    path and asserts what happens on the auth-FAILURE branch.
  - Auth-failure mechanics (argon2id hash + `crypto/subtle`
    constant-time compare returning no-match; the `^[0-9a-f]{32}$`
    syntactic gate rejecting `notatoken` before hashing) are T044/
    T024's gated surface; T027 consumes auth-failure as the event
    under test, not the comparison primitive.
  - The Template literal is byte-pinned by `errortpl/template_test.go`
    (T019); T027 consumes it via the on-the-wire response body.
  - The allowlist + corpus-scan core is self-tested by
    `tests/internal/loginvariants/loginvariants_test.go` (T025a).
- **Residue:**
  - **verify.sh Gate 2 runs only the `data-plane` module** — the
    `tests/contract` Go tests execute via this ticket's acceptance
    command (and future CI wiring), not the single green gate.
    Pre-existing gap inherited from T022–T026; promotion (a
    contract-module `go test` gate in scripts/verify.sh) is a
    follow-up ticket, out of this ticket's scope.
  - **The exhaustive header-set invariants** (exactly four headers in
    declared order; no forbidden header including `Server`, `Via`,
    `Date`, `Connection`, `Keep-Alive`, `Transfer-Encoding`,
    `Proxy-Agent`, `X-Forwarded-*`) **are T068a's scope**
    (`header_set_test.go`) for all four codes. T027 asserts only the
    minimum header shape needed to make its structural-equality claim
    non-trivial (status line + `X-Stargate-Error: AUTH_REQUIRED` +
    body-Template shape). A DP that emits an extra header on
    `AUTH_REQUIRED` identically across the missing/malformed cases is
    caught by T068a, not T027 — UNLESS the extra header differs
    between the two cases (then T027's structural-equality check
    catches it as a distinguishing substring).
  - **The distinct-ref-ID property** (1000-fixture uniqueness +
    uniformity; same-request-two-distinct-ref-IDs) **is T069's
    scope**. T027 does NOT assert the two captured ref-IDs differ; a
    buggy renderer that emits a constant ref-ID across responses
    passes T027's structural-equality check trivially and is caught
    by T069. The two properties are orthogonal: T027 = no
    distinguishing bytes OUTSIDE the ref-ID slot; T069 = ref-IDs
    VARY across responses. T027's structural check is meaningful
    standalone because it would still fail on any non-ref-ID
    distinguishing byte even if the two ref-IDs happened to collide.
  - **The malformed-token syntactic-rejection matrix** (wrong length
    vs non-hex vs exactly-32-hex-but-unknown) **is T044's unit-test
    surface**. T027 uses ONE canonical malformed value (`Bearer
    notatoken` per the cited test method — fails both the length and
    the charset gate) and asserts the response shape; it does not
    enumerate the matrix.
  - **The CONNECT auth-FAILURE journal allowlist is not gated by any
    existing test.** The contract row "No per-request log on auth
    failure" (socks5-auth.md §"Invariants") calls for a journal tail
    during auth-failure tests, but the task body for T027 specifies
    "(c) leak-corpus scan over response bytes" only, and T025's
    SOCKS5 auth-failure precedent likewise omits the journal scan.
    Promotion (a journal-delta sub-test on the CONNECT auth-failure
    path, symmetric to T025a/T026's success-path gates) is a
    follow-up ticket — out of scope here per the surgical-changes
    doctrine. Noted because the auth-failure journal surface is
    particularly sensitive: an attacker probing auth gets their
    attempted token logged if the DP misbehaves.
  - **The DP's response shape when the route is DISABLED**
    (`routeEnableMask[TOR]=false`, no `HEALTHY` pushed) **vs ENABLED
    is not exercised** — T027 does not push `HEALTHY` (auth-fail is
    route-independent). A DP that routes the auth-fail differently
    based on mask state is not caught by T027; that cross-cut is
    T073's surface.
  - **Redteam scope (privacy-critical, non-empty residue):** hunt for
    (a) a response reader that over-reads past the `AUTH_REQUIRED`
    response into a subsequent response or partial bytes — corrupting
    both the body-template and the structural-equality evidence
    (mirrors T026's redteam scope (a)); (b) any way the structural-
    equality check could pass on a non-identical response — a
    comparison that normalises whitespace, folds headers, or masks a
    slot wider than the 16 ref-ID hex chars before comparing would
    let real distinguishing bytes through; (c) failure messages or
    sub-test names that leak the destination or the malformed token
    into CI logs (the test must withhold both from its failure
    output, mirroring the loginvariants index-only discipline and
    T026's response-bytes-withheld policy); (d) any byte in the
    response that depends on the offered-token BYTES (not just
    "header absent" vs "header present") — e.g. a debug header that
    hashes the malformed token, or a body field that echoes it; (e)
    a body-template check that matches a prefix or suffix only
    rather than the full Template literal, letting an extra body
    element slip through; (f) a read-until-EOF strategy that hangs
    on a DP which writes the response but never closes — bounded by
    a read deadline so a wedged DP fails rather than hangs the test.

## Acceptance

### Named test

**NEW: `tests/contract/error-template/auth_required_test.go`** —
package `errortemplate` (NEW directory; convention per
contracts/socks5-auth.md §"Two inbound protocols, one port" —
template-emitting responses live under `error-template/`, not
`socks5/`). `TestAUTHRequired` runs as a single consolidated body
(not sub-tests) for the act+shape+structural assertions because they
layer on one fixture (one DP boot, one token push, two sequential
CONNECT auth-fail requests on independent connections); only the two
response-bytes leak scans split into sub-tests so a corpus hit in
either case is independently attributable (the T025 leak-test
precedent).

1. **Fixture** (mirrors T025's `AuthFailure_NoTokenBytesInCapture`
   — the route-independent auth-failure setup, NOT T026's success-
   path setup): content-gate on `listener/connect.go` (T043),
   `auth/token.go` (T044), and `errortpl/render.go` (T048) via
   `dpharness.RequireFile`; boot `dpharness.Start(t)` with **no
   options** — no `WithUpstream` (auth-fail happens before the
   forward path is consulted; the upstream is never dialed), no
   `WithBeforeBoot(fakecp.Start)` (no `HEALTHY` to push — `AUTH_REQUIRED`
   is route-independent; the DP's background WatchEvents dial fails
   harmlessly, matching T025's pattern); push token generation 1 (a
   32-hex plaintext via `dpharness.MintToken`, distinct from
   T025a/T025b/T026's tokens so a corpus hit is attributable to this
   test), `dpharness.Reload` must return `APPLY_STATUS_OK`. The valid
   token establishes a non-empty generation — the realistic case
   where a missing/malformed offer is rejected against a populated
   generation (not the degenerate empty-generation case).
2. **Distinctive corpus**: a destination `t027-dest.example.onion`
   and a malformed token `notatoken` (9 chars, contains non-hex
   letters — fails BOTH the length and the `^[0-9a-f]{32}$` charset
   gate per `contracts/socks5-auth.md` §"HTTP CONNECT path" step 2,
   matching the cited test method verbatim). Each is scanned in nine
   renderings.
3. **Act (a) Missing**: open a connection (`dialProxy`-equivalent
   local helper — `dialProxy` lives in package `socks5` and is not
   importable across packages), send `CONNECT <dest>:443
   HTTP/1.1\r\n\r\n` (no `Proxy-Authorization` header — the
   request-line-only shape per the cited test method). Read the full
   response with a bounded read deadline until EOF (the DP closes
   after `AUTH_REQUIRED` per `contracts/error-template.md` §"HTTP
   CONNECT path"; a wedged DP that writes the response but never
   closes fails the test rather than hangs it — §Analysis redteam
   scope (f)). Capture `respMissing`.
4. **Act (b) Malformed**: open a NEW connection (the DP closed the
   first after `AUTH_REQUIRED`), send `CONNECT <dest>:443
   HTTP/1.1\r\nProxy-Authorization: Bearer notatoken\r\n\r\n`. Read
   until EOF. Capture `respMalformed`.
5. **(a) StatusShape**: both responses begin byte-exactly with
   `HTTP/1.1 407 Proxy Authentication Required\r\n` AND contain
   `X-Stargate-Error: AUTH_REQUIRED\r\n` — gates that the response
   IS the `AUTH_REQUIRED` template, not (e.g.) a 200, a 502, or a
   different code. A DP that returns the wrong status or wrong code
   marker fails here, before the structural-equality check gives a
   misleading byte-comparison failure. Response bytes are WITHHELD
   from the failure message (mirror T026's leak-safe policy).
6. **(b) BodyTemplate**: both response bodies match `errortpl.Template`
   byte-for-byte after substituting `{ROUTE_LABEL}`="Tor",
   `{CODE}`="AUTH_REQUIRED", and `{LOCAL_REFERENCE_ID}`=a run of 16
   lowercase-hex chars. Locate the body via the LF-terminated literal
   prefix from `contracts/error-template.md` §"Response body" (the
   body follows the header-terminating blank line; LF line endings,
   not CRLF). A DP that emits a different body (extra whitespace,
   missing element, wrong `ROUTE_LABEL`, trailing newline) fails this
   assertion. The match is full-Template-literal, not prefix/suffix
   (§Analysis redteam scope (e)).
7. **(c) NoDistinguishingSubstring**: locate the 16-char ref-ID slot
   in each response by finding the literal body prefix
   `Code: AUTH_REQUIRED · Reference: ` and reading the next 16 chars.
   Mask those 16 bytes (zero them) in both `respMissing` and
   `respMalformed`; assert the two masked responses are byte-for-byte
   equal. A DP that emits ANY distinguishing byte outside the ref-ID
   slot — a header value, a body field, an extra CRLF, a different
   `Content-Length` — fails this assertion (§Analysis must-hold #2;
   the property the task body names). The masking is exactly 16 bytes
   wide (not 14, not 18) so a wider-or-narrower mask cannot hide real
   distinguishing bytes (§Analysis redteam scope (b)).
8. **(d) ResponseLeaksNothing** — two sub-tests, one per case so a
   hit is attributable independently:
   - `Response_NoCorpusItem_Missing`:
     `loginvariants.AssertNoSecrets(respMissing, []byte(dest),
     []byte("notatoken"))` (raw + eight derived renderings).
   - `Response_NoCorpusItem_Malformed`:
     `loginvariants.AssertNoSecrets(respMalformed, []byte(dest),
     []byte("notatoken"))`.
   The 407 response carries no destination and no malformed-token
   byte (§Analysis must-hold #3; the cited leak-corpus invariant).

### Runnable command

```sh
scripts/verify.sh &&
  (cd tests/contract && gofmt -l . && go vet ./error-template/... &&
   go test -race -count=1 -run TestAUTHRequired ./error-template/...)
```

Today the test SKIPs at the content gates (T043/T044/T048 unimplemented)
— the skip self-lifts as implementation lands, matching the
T023/T024/T025/T025a/T025b/T026 precedent. `scripts/verify.sh` stays
green (Gate 2 remains scoped to the data-plane module; see §Analysis
residue).

## Out-of-scope

- **Distinct-ref-ID property** (1000-fixture uniqueness, uniformity,
  same-request-two-distinct-ref-IDs) — T069's scope
  (`reference_id_unique_test.go` + `reference_id_unlinked_test.go`).
  T027's structural-equality check does NOT assert the two captured
  ref-IDs differ; the two properties are orthogonal (T027 = no
  distinguishing bytes OUTSIDE the slot; T069 = ref-IDs VARY).
- **Exhaustive header-set invariants** (exactly four headers in
  declared order; no forbidden header including `Server`, `Via`,
  `Date`, `Connection`, `Keep-Alive`, `Transfer-Encoding`,
  `Proxy-Agent`, `X-Forwarded-*`) — T068a's scope
  (`header_set_test.go`) for all four codes. T027 asserts only the
  minimum header shape needed to make its structural-equality claim
  non-trivial.
- **The malformed-token syntactic-rejection matrix** (wrong length /
  non-hex / exactly-32-hex-but-unknown) — T044's unit-test surface.
  T027 uses ONE canonical malformed value (`Bearer notatoken`) per
  the cited test method.
- **Constant-time comparison / slot-invariance timing tests** —
  T044/T024's surface (the auth primitive). T027 consumes auth-
  failure as the event under test.
- **Valid token + dead sidecar → 502 `ROUTE_DOWN`** and the other
  three codes' templates — T065/T066/T067/T071's scope. T027 pins
  `AUTH_REQUIRED` only.
- **`AUTH_REQUIRED` on the SOCKS5 path** (`0x01 0xFF` then close) —
  `contracts/socks5-auth.md` §"Auth failure response"; lives under
  `tests/contract/socks5/` (T024/T025 already gate this byte
  sequence).
- **CONNECT auth-FAILURE journal allowlist** — the contract row "No
  per-request log on auth failure" calls for a journal tail, but the
  task body scopes T027's leak scan to RESPONSE bytes only and T025's
  SOCKS5 auth-failure precedent likewise omits the journal scan.
  Promotion (a journal-delta sub-test symmetric to T025a/T026's
  success-path gates) is a follow-up ticket (§Analysis residue).
- **The DP's response shape when the route is DISABLED vs ENABLED** —
  T027 does not push `HEALTHY` (auth-fail is route-independent). The
  mask-state cross-cut is T073's surface.
- **Wiring a `tests/contract` go-test gate into scripts/verify.sh** —
  pre-existing gap inherited from T022–T026; follow-up ticket
  (§Analysis residue).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
