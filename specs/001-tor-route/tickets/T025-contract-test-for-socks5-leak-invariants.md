---
id: T025
title: 'Contract test for SOCKS5 leak invariants in `tests/contract/socks5/lea'
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T025
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T024]   # T009 proto stubs; T024 ships the shared dpharness auth + fakecp surface this test reuses
parallel: true
files_budget: 4   # leak_test.go (+1); harness/README touches if any
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/socks5-auth.md §"Invariants enforced by the contract test"
  - specs/001-tor-route/contracts/socks5-auth.md §"Forbidden behaviours (both paths)"
  - specs/001-tor-route/data-model.md §1.5
  - specs/001-tor-route/spec.md §"FR-006"
  - specs/001-tor-route/spec.md §"FR-008"
decision_refs:
  - research.md §5 (Contract-test harness language — Go)
reviews: { round: 1, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: [{ round: 1, date: 2026-07-06, severity: "2 Major + 4 Minor", verdict: "remediated-in-round-1" }]
clarity_check: {}
---

# T025: Contract test for SOCKS5 leak invariants in `tests/contract/socks5/lea

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 leak invariants in `tests/contract/socks5/leak_test.go` — per `contracts/socks5-auth.md` §"Invariants enforced by the contract test". Covers: (a) no token bytes in any response capture; (b) constant-time comparison latency distribution — two distinct invalid passwords of the same length yield close-to-equal latency distributions (best-effort, per contract); (c) **slot-invariance under the v1 N≤4 cost model** (data-model.md §1.5: "authentication against N stored tokens requires N argon2id operations to keep the comparison constant-time; short-circuiting on the first match would leak which slot matched") — load a generation of N=4 distinct token hashes, then drive authentication latency measurements with the matching token placed at slot index 0, 1, 2, 3 respectively, plus the all-fail case, and assert the five latency distributions are statistically indistinguishable at the test's significance threshold (an implementation that early-exits on the first hash match would produce monotonically increasing latency by slot index and fail this assertion); (d) no per-request journal entry on auth failure; (e) rejection of same-host NO_AUTH-only clients.

## Analysis

T025 is tests-first (Constitution Principle VII) for the auth-path leak
surface — T024 already gates auth-SUCCESS byte shape and argon2id
parameter agreement (its residue names T025 as the owner of the
constant-time + slot-invariance surface). This ticket pins the
properties T024 explicitly deferred.

- **Must hold:**
  - **No token bytes in any auth-failure response capture**
    (FR-006; contracts/socks5-auth.md row "Auth failure does not leak
    token bytes"). Every byte the DP writes from sub-negotiation-reply
    through close — including the 2-byte `0x01 0xFF` and any trailing
    bytes (none expected) — MUST NOT contain the offered PASSWD
    plaintext, any substring of it, or the stored argon2id hash bytes.
  - **Slot-invariance under the v1 N≤4 cost model**
    (data-model.md §1.5: per-token salts → auth against N stored hashes
    requires N argon2id ops; "short-circuiting on the first match
    would leak which slot matched"). With N=4 distinct hashes loaded,
    auth-SUCCESS latency when the matching hash is at slot index
    0/1/2/3 — plus auth-FAILURE latency for a fifth non-matching
    plaintext — MUST be statistically indistinguishable across the
    five cases. An early-exit-on-first-match loop produces ~1 op at
    slot 0 vs ~4 ops at slot 3 (a ~4× latency ratio at ~50 ms/op),
    which fails this assertion with wide margin.
  - **Constant-time latency on two distinct invalid passwords of equal
    length** (contracts/socks5-auth.md row "Constant-time comparison" —
    best-effort per contract because true constant-time verification
    is hard from userland). The implementation MUST use
    `crypto/subtle.ConstantTimeCompare`; a `bytes.Equal`/`==` on the
    hash produces a length- or prefix-dependent timing leak that this
    assertion surfaces when the two candidates differ in every byte.
  - **No per-request journal entry on auth failure** (FR-008; Principle
    I — no per-request logs at finer than ≥1-hour aggregate resolution;
    contracts/socks5-auth.md row "No per-request log on auth failure").
    The DP's journal capture MUST NOT contain the offered PASSWD, the
    offered UNAME, the stored argon2id hash bytes, or — when present —
    the destination host. Auth-failed requests MUST NOT increment any
    counter (FR-008 / data-model.md §3 — counting them is a token-
    guessing side channel); counter invariants proper are T025c/T025d's
    scope, but the journal scan here covers the textual leak surface.
  - **Same-host NO_AUTH-only SOCKS5 clients are rejected** (THREAT-MODEL
    §3.1 local profile; contracts/socks5-auth.md §"Auth method
    negotiation" — `0x05 0x01 0x00` → `0x05 0xFF` + close). Canonical
    byte-shape gate is T023 (`demux_test.go`/MethodNegotiation_NoAuth-
    Only); T025 re-asserts it because the contract document's
    "Invariants enforced by the contract test" table groups the
    invariant under this suite. Belt-and-braces, not the canonical
    gate.
  - **Auth-failure response is exactly `0x01 0xFF` followed by close,
    no further bytes** (FR-006 / FR-009; contracts/socks5-auth.md §"Auth
    failure response"). The 2-byte reply plus close is the entire
    SOCKS5-path failure surface — no body, no template, no
    distinguishing substring across missing/malformed/empty cases.
  - **Self-skip while implementation is absent.** Every sub-test MUST
    self-skip (never FAIL) while T042 (listener), T044 (auth/token.go),
    T045 (controlclient client+server), T046 (server-side ReloadTokens
    hosting), T050 (main wiring) are unimplemented; the skip lifts when
    those land and the assertions flip to RED-driving (Principle VII
    tests-first; precedent T023/T024).
- **Gated:**
  - `dpharness.Start` content-gates on the T042/T045/T050 boot-minimum
    files; auth-touching sub-tests additionally `dpharness.RequireFile`
    on `data-plane/internal/auth/token.go` (T044). The skip self-lifts
    on implementation landing — this is the test-first mechanism.
  - `go vet` + `staticcheck` + `gosec` (via `scripts/verify.sh`) cover
    the new test file's syntax and the implementation-under-test's
    `crypto/subtle.ConstantTimeCompare` usage (a `bytes.Equal`/`==` on
    hashes trips `gosec G601/G402-adjacent checks for insecure
    comparison).
  - License-header check gates the SPDX header on the new file.
  - T024 (`userpass_success_test.go`) already gates the auth-SUCCESS
    byte shape AND the argon2id parameter agreement between
    `dpharness.MintToken` and `data-plane/internal/auth/params.go` —
    a parameter drift surfaces there before T025. T025 inherits that
    gating and focuses on the failure/leak/slot-invariance surface.
  - T023 (`demux_test.go`) already gates invariant (e) (NO_AUTH-only
    rejection). T025's re-assertion is for contract-document
    completeness; the canonical gate stays T023.
- **Residue:**
  - **True constant-time verification is hard from userland** (contract
    calls the statistical assertions "best-effort"). CI noise can mask
    a small timing leak; a sub-microsecond early-exit on the comparison
    loop would be invisible. Mitigation: tune the sample count (≥8
    per case) and the threshold (medians within 25% of the overall
    median) to surface the SPECIFIC leak the contract names —
    early-exit-on-first-MATCH producing ~4× latency between slot 0 and
    slot 3, well above CI noise. Cannot promote to gated without a
    deterministic argon2id timing oracle, which does not exist in
    userland.
  - **The journal scan is corpus + HH:MM:SS-timestamp + delta-scoped**,
    which covers the realistic v1 text-journal shape. Two gaps remain:
    (1) Unix-epoch timestamps (bare 10-digit numbers) are not matched
    — too broad a pattern would false-positive on byte counts and port
    numbers; (2) a future binary journal sink would evade both the
    corpus substring scan and the timestamp regex. T025a's
    `tests/internal/loginvariants/` allowlist is the proper home for
    exhaustive journal-format-aware leak detection; T025's regex
    backstops the obvious text-form case until T025a lands.
  - **Sub-test (c) trusts ReloadTokens to preserve token-list order.**
    The test places hashA at slot 0/1/2/3 and measures auth latency;
    if a future implementation re-orders or dedups the list internally
    (e.g. sorts by hash for binary search), the four slot cases
    collapse into one internal state and the test cannot distinguish
    them. T044 (auth/token.go) is expected to preserve insertion
    order; a regression here would need a side-channel check T025
    does not own.
  - **The argon2id ~50 ms/op cost makes the slot-invariance test
    slow.** 5 cases × 8 samples × ~200 ms ≈ 8 s of argon2id work per
    test run on top of boot. Acceptable for a contract test gating a
    Constitution-level property; not promotable to a faster gate.

## Acceptance

Named test in `tests/contract/socks5/leak_test.go`, package `socks5`
(reuses the `dialProxy`/`readN`/`expectEOF` helpers and
`doMethodNegotiation`/`doSubnegotiation` from T023/T024 in the same
package — no new shared harness code required):

- `TestSOCKS5LeakInvariants` with sub-cases:
  - (a) **`AuthFailure_NoTokenBytesInCapture`**: preload one valid
    token via `dpharness.Reload` (asserting `APPLY_STATUS_OK`);
    open SOCKS5, do method negotiation, send RFC 1929 sub-
    negotiation with the matching plaintext EXCEPT its final byte
    flipped (so auth fails). `io.ReadAll` every byte the DP writes
    from sub-negotiation-reply through EOF. Assert: (1) reply is
    byte-exactly `0x01 0xFF`; (2) **strict zero-trailing-bytes check**
    — any bytes after the 2-byte reply are a contract breach
    (catches encoded leaks that would evade the corpus scan);
    (3) connection closes with EOF (no timeout); (4) the offered
    PASSWD plaintext, the stored argon2id hash, AND the stored salt
    do not appear in the capture in raw, hex, or base64 form.
    Content-gate on `data-plane/internal/auth/token.go` (T044).
  - (b) **`AuthFailure_ConstantTimeLatency_TwoInvalidPasswords`**:
    preload one valid token; for each of two distinct 32-char-hex
    invalid passwords (generated to differ in every byte — not just
    a long shared prefix — so a prefix-based short-circuit would be
    visible if it existed), time `N=8` auth-failure attempts (open
    conn, do method negotiation, do sub-negotiation, measure wall-
    clock from sub-negotiation-write to reply-read). Assert the two
    distributions' medians are within 25% of each other. Best-effort
    per contract; documented as such in the test.
    Content-gate on `data-plane/internal/auth/token.go` (T044).
  - (c) **`SlotInvariance_N4_ConstantTimeAcrossList`**: pre-mint 4
    distinct token hashes via `dpharness.MintToken` (distinct
    plaintexts). For each slot index s ∈ {0,1,2,3}: push a fresh
    monotonic generation with the real token's hash at index s and
    the other three slots filled with the other real hashes; time
    `K=8` auth-SUCCESS attempts for the matching plaintext. For the
    all-fail case: push a generation with all 4 real hashes; time
    `K=8` auth-FAILURE attempts for a 5th plaintext not in the set.
    Assert all 5 distributions' medians are within 25% of the overall
    median. A short-circuit-on-first-match implementation produces
    slot-0 ≈ 50 ms vs slot-3 ≈ 200 ms (≈4× ratio) — fails with wide
    margin. Content-gate on `data-plane/internal/auth/token.go` (T044).
  - (d) **`AuthFailure_NoPerRequestJournalEntry`**: snapshot
    `h.Journal.String()` before; preload one token (asserting
    `APPLY_STATUS_OK`); open SOCKS5, do method negotiation, send
    RFC 1929 sub-negotiation with a distinctive PASSWD and a
    distinctive UNAME; wait for `0x01 0xFF` + close. Snapshot
    `h.Journal.String()` after. Assert the post-snapshot delta
    contains none of: the offered PASSWD, the offered UNAME, the
    stored hash bytes, OR the stored salt — scanned in raw, hex,
    and base64 form. Additionally scan the delta for any
    `HH:MM:SS`-shaped timestamp substring (FR-008 prohibits
    per-request timestamps finer than ≥1-hour resolution). The
    delta-scoping avoids false-positives from boot-log timestamps.
    Unix-epoch and binary-format timestamps still evade — see
    §Analysis residue (T025a's allowlist closes that gap).
    Content-gate on `data-plane/internal/auth/token.go` (T044).
  - (e) **`SameHost_NoAuthOnly_Rejected`**: open SOCKS5, send
    `0x05 0x01 0x00`; assert reply is byte-exactly `0x05 0xFF`; assert
    connection closes with no further bytes. Canonical gate is
    T023's `demux_test.go`/`MethodNegotiation_NoAuthOnly`; this
    re-assertion covers the contract-document enumeration. No
    auth-gate needed (NO_AUTH rejection happens before sub-negotiation
    so does not depend on T044).
- **Behavioral assertion**: every auth-touching sub-test calls
  `dpharness.RequireFile(t, <path>, <reason>)` so the suite self-skips
  (never FAILs) until T042/T044/T045/T046/T050 land. The
  boot-minimum gate inside `dpharness.Start` covers T042/T045/T050;
  the auth gate inside each sub-test covers T044.
- **Runnable**: `scripts/verify.sh` green. On the current tree (no
  T042/T044/T045/T046/T050 yet) the new test compiles, lints clean,
  and self-skips under the content gates.

## Out-of-scope

- Counter side-channel (auth-pass must-increment `aggregate_counters`
  vs auth-fail must-not-increment) — T025c / T025d. T025's journal
  scan covers the textual leak surface only, not the counter row.
- Auth-SUCCESS byte shape (`0x01 0x00`), RFC 1929 framing correctness,
  UNAME verbatim forwarding — T024 (`userpass_success_test.go`).
- `AUTH_REQUIRED` template invariants (HTTP CONNECT path) — T028
  (`error-template/auth_required_test.go`).
- Request-phase failures (post-auth, ROUTE_DOWN/REFUSED/TIMEOUT 10-
  byte SOCKS5 reply) — T067a (`request_phase_failures_test.go`).
- Multi-protocol counter side-channel under mixed SOCKS5 + CONNECT
  load — T025c/T025d/T067b.
- The argon2id parameter values themselves — pinned in
  `data-plane/internal/auth/params.go` + its `_test.go` (T044) and
  mirrored in `dpharness/auth.go` (T024). T025 inherits the agreement
  gate from T024's auth-SUCCESS test; it does not re-pin the params.
- Refactoring `tests/contract/control-grpc/dpharness_test.go` or
  `tests/contract/control-grpc/watch_events_test.go` to import from
  the shared `dpharness`/`fakecp` packages — already filed as a
  follow-up under T024; not this ticket's work.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
