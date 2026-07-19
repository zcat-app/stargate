---
id: T028
title: 'Contract test for `AUTH_REQUIRED` on SOCKS5 path'
status: done
created: 2026-07-04
last_updated: 2026-07-08
source: tasks.md#T028
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
  - specs/001-tor-route/contracts/socks5-auth.md §"Auth failure response"
  - specs/001-tor-route/contracts/socks5-auth.md §"Username/password sub-negotiation"
decision_refs:
  - research.md §9 (AUTH_REQUIRED response on SOCKS5 vs HTTP CONNECT framing — the symmetric-failure decision)
reviews: { round: 1, date: 2026-07-08, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T028: Contract test for `AUTH_REQUIRED` on SOCKS5 path

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for `AUTH_REQUIRED` on SOCKS5 path — exact 2-byte response `0x01 0xFF` then close, no additional bytes — in `tests/contract/socks5/auth_required_test.go` — per research.md §9 and `contracts/socks5-auth.md` §"Auth failure response".

## Analysis

T028 is tests-first (Constitution Principle VII) for T042
(listener RFC 1929 framing) and T044 (argon2id token verification)
on the AUTH_REQUIRED failure path. It is the SOCKS5-path analogue
of T027 (which owns the HTTP CONNECT AUTH_REQUIRED template shape);
research.md §9 fixes the two-framing split — SOCKS5 failure is a
fixed 2-byte `0x01 0xFF` binary response, NOT the HTML template.

T025 (a) already gates the byte-exact `0x01 0xFF` + close + no-
trailing-bytes shape for the **valid-format-but-wrong** (near-miss
password against a populated generation) case, plus its leak scan.
T028 does NOT re-assert that case. T028's distinct contribution is
the **AUTH_REQUIRED family** the contract groups separately from
the near-miss case, plus the **cross-case byte-identity** invariant
no other test asserts:

- **empty generation** — no tokens loaded at all (T025 always loads
  a valid token first; the empty-generation case is the canonical
  AUTH_REQUIRED scenario — the name literally means auth is required
  because no token was provisioned). contracts/socks5-auth.md
  §"Auth failure response": "OR the generation is empty".
- **syntactically malformed PASSWD** — wrong length and/or non-hex
  contents. SOCKS5 has NO syntactic gate on PASSWD (unlike the
  CONNECT path's `^[0-9a-f]{32}$`); a malformed candidate is hashed
  and compared like any other, and fails the comparison (research.md
  §9; contracts/socks5-auth.md §"Username/password sub-negotiation"
  step 3). A buggy implementation could special-case malformed input
  with a distinct response (a framing reject, a diagnostic byte) —
  T028 pins that it does not.

- **Must hold:**
  - Empty generation + RFC 1929 sub-negotiation with any PASSWD →
    reply EXACTLY `0x01 0xFF` (contracts/socks5-auth.md §"Auth
    failure response").
  - Populated generation + syntactically malformed PASSWD (wrong
    length, non-hex) → reply EXACTLY `0x01 0xFF`. SOCKS5 funnels
    malformed input through hash+compare-fail, NOT a syntactic
    short-circuit (research.md §9).
  - The reply is exactly 2 bytes; the connection closes immediately
    after; NO further bytes are written. "the 2-byte sub-negotiation
    reply plus close is the entire SOCKS5-path failure surface — no
    body, no template" (contracts/socks5-auth.md §"Auth failure
    response").
  - No distinguishing substring across the AUTH_REQUIRED cases
    (empty-gen vs malformed-length vs malformed-charset): the full
    response captures are byte-for-byte identical to each other AND
    equal to `[0x01, 0xFF]` exactly (contracts/socks5-auth.md
    §"Auth failure response": "no distinguishing substring across
    missing/malformed/empty cases"; Principle III / FR-006 / FR-009).
  - No HTML-template bytes appear on the SOCKS5 failure path — the
    template is CONNECT-only (research.md §9).
- **Gated:**
  - `tests/contract/socks5/auth_required_test.go` (this ticket) is
    itself the fail-closed gate for the byte shapes and cross-case
    identity above; once T042/T044 land the test flips SKIP → RED,
    driving the implementation.
  - `go vet` + `staticcheck` + `gosec` cover the syntactic / security
    surface (verify.sh gates 3–5); the license-header check gates
    SPDX.
  - T025 (a) gates the byte-exact `0x01 0xFF` + close + no-trailing-
    bytes shape and the leak scan for the valid-format-but-wrong
    near-miss case; T028 does not re-assert that case.
  - T023 gates the method-negotiation layer (`0x05 0x02` selection)
    that precedes RFC 1929 sub-negotiation; T028 reaches that layer
    via the shared `doMethodNegotiation` helper and fails fast there
    on regression (mirrors T024/T025).
- **Residue:**
  - **Timing-distinguishability** of AUTH_REQUIRED cases is NOT
    asserted here. Byte-identity is gated above; a buggy
    implementation that fails empty-gen on a fast-path (no argon2id
    work) while spending full argon2id on malformed candidates would
    be timing-distinguishable to an observer, leaking generation
    state. T025 (b)/(c) gate the constant-time / slot-invariance
    surface for the populated-generation case; the empty-generation
    timing path is not gated by any current test. Promoting it would
    need a statistical test mirroring T025 (b) — deferred. Risk
    characterization: the leak is a one-bit coarse signal about
    whether the operator has provisioned ANY token (flips once per
    proxy lifetime), NOT per-request destination/token metadata
    (the contract's actual concern); forcing dummy argon2id work on
    empty-gen to close it would be a prescriptive design decision
    that belongs in the contract, not the test. Deferral owner: a
    follow-up `T025e` (extend T025's constant-time machinery to the
    empty-gen fast-path) OR an explicit risk acceptance logged in
    SECURITY-DECISIONS.md. Either resolution is out of T028's charter.
  - **Journal-content for AUTH_REQUIRED-specific shapes** (empty-gen,
    non-hex, wrong-length) is gated only shape-agnostically by T025
    (d)'s offered-bytes scan: any DP that logs the offered PASSWD
    *bytes* for all failure shapes would log T025 (d)'s distinctive
    `distinctPass` and fail; but a category-label logger
    ("auth failed: empty generation" / "malformed length=8") reveals
    no credential and is not gated by any current test. LOW — a
    failure-class label is already implied by the adversary's own
    connection attempt and reveals no destination/token/UNAME.
    Extending T025 (d)'s corpus to category-label regexes via
    `loginvariants` is the natural home; out of T028's charter.
  - RFC 1929 framing edge `PLEN=0` (zero-length PASSWD) is a
    protocol violation below the layer the contract specifies
    (PASSWD is 1–255 bytes). T028 does not probe `PLEN=0`; a future
    implementation that rejects it at framing with a non-`01 FF`
    response would not be caught here. That is a listener-framing
    concern in T042's scope, gated by T023's demux family — out of
    T028's charter.

## Acceptance

Named test in `tests/contract/socks5/auth_required_test.go`, package
`socks5` (same package as T023/T024/T025 — reuses the shared helpers
`dialProxy`, `readN`, `doMethodNegotiation`, `doSubnegotiation`,
`expectEOF` already defined in sibling `_test.go` files; no new
harness code):

- `TestAUTHRequiredSOCKS5Path` with sub-cases:
  - (a) `EmptyGeneration_ReplyIsExact_01FF_ThenClose`: boot the DP
    via `dpharness.Start` and do NOT call `ReloadTokens` (the DP's
    token generation is empty — the canonical AUTH_REQUIRED state).
    Open a SOCKS5 connection; do method negotiation (`05 01 02` →
    expect `05 02`); send RFC 1929 sub-negotiation with a well-
    formed 32-hex PASSWD and a known UNAME. Assert the reply is
    byte-exactly `01 FF`. Then assert the connection closes with no
    further bytes (`expectEOF`).
  - (b) `MalformedPasswd_ReplyIsExact_01FF_ThenClose`: load one
    valid token via `ReloadTokens` (establishing a populated
    generation — the realistic case where a malformed offer is
    rejected against real state, mirroring T027's setup); then for
    each malformed PASSWD in a table, open a fresh SOCKS5
    connection, do method negotiation, send sub-negotiation, and
    assert reply `01 FF` + close. The table covers the two
    syntactic-malformation modes:
    - `WrongLength_Short` — `"tooshort"` (8 chars, ≠ 32).
    - `WrongLength_Long` — 33-char hex run (1 over the 32-char
      token width).
    - `NonHex_32chars` — 32 chars containing non-hex letters
      (e.g. `"zzzz..."`), so length matches but charset does not.
    One value per malformation mode; SOCKS5 has no syntactic gate
    so all three funnel through hash+compare-fail (research.md §9).
  - (c) `NoDistinguishingSubstring_acrossAUTH_REQUIRED_Cases`:
    capture the FULL response (the 2-byte reply PLUS every trailing
    byte through EOF) for each AUTH_REQUIRED case — empty generation
    (no Reload) and each malformed-PASSWD variant from (b). Assert
    every capture is byte-for-byte identical to the others AND equal
    to `[0x01, 0xFF]` exactly (zero trailing bytes on every path).
    This is the cross-case invariant research.md §9 and
    contracts/socks5-auth.md §"Auth failure response" name ("no
    distinguishing substring across missing/malformed/empty cases");
    T025 gates the single-case shape, T028 gates the cross-case
    identity. A buggy implementation that emits a diagnostic byte
    on one path but not another fails here.
- Content-gate (per sub-test, narrowest viable gate): every sub-test
  self-skips while `data-plane/internal/listener/socks5.go` (T042)
  or `data-plane/internal/auth/token.go` (T044) is absent — the
  boot minimum (T042/T045/T050) is already gated inside
  `dpharness.Start`. The skip self-lifts when T042/T044 land; until
  then the test is SKIP, not FAIL.
- Setup shape mirrors the route-independent auth-failure precedent
  (T025 (a), T027): bare `dpharness.Start` — NO `WithUpstream`
  (auth-fail happens before the forward path is consulted) and NO
  `WithBeforeBoot(fakecp.Start)` (no HEALTHY to push — AUTH_REQUIRED
  is route-independent; the DP's background WatchEvents dial fails
  harmlessly).
- Runnable: `scripts/verify.sh` green (test self-skips on a tree
  without T042/T044/T045/T050).

## Out-of-scope

- The valid-format-but-wrong (near-miss) invalid-password case —
  byte shape, no-trailing-bytes, and leak-corpus scan are T025 (a)
  (`leak_test.go`). T028 does not re-assert that case.
- Constant-time comparison latency distributions and slot-invariance
  under the v1 N≤4 cost model — T025 (b)/(c). T028 gates
  byte-identity only; timing-identity across AUTH_REQUIRED cases is
  §Analysis residue (deferred).
- The HTTP CONNECT AUTH_REQUIRED template shape (407 + template,
  missing-vs-malformed byte-identity modulo the ref-ID slot) — T027
  (`error-template/auth_required_test.go`).
- RFC 1929 framing edges (`PLEN=0`, `ULEN=0`, oversize length fields)
  — these are listener-framing concerns in T042's scope, gated by
  T023's demux family. T028 probes only well-framed sub-negotiations
  with AUTH_REQUIRED failure semantics.
- Counter side-channel (auth-fail must-not-increment) — T025c /
  T025d.
- Token-list snapshot persistence and cold-start restore — T020a.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
