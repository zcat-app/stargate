---
id: T025a
title: 'Contract test for SOCKS5 success-path log invariants'
status: done
created: 2026-07-04
last_updated: 2026-07-07
source: tasks.md#T025a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # loginvariants go.mod + .go + _test.go; socks5 test; go.work + tests/contract go.mod + go.sum
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-008"
  - specs/000-architecture/spec.md §6.4 (aggregate_counters — hour-bucket resolution)
  - specs/001-tor-route/contracts/socks5-auth.md §"Invariants enforced by the contract test" (row "No per-request log on auth failure")
  - specs/001-tor-route/data-model.md §3 (counters — no per-request metadata)
  - specs/001-tor-route/plan.md §"Tree convention" (tests/internal/loginvariants/ canonical home)
decision_refs:
  - specs/001-tor-route/research.md §5 (Contract-test harness language — Go)
  - tests/contract/control-grpc/leakscan_test.go (line-class shape pinned by T020 redteam finding 20260706-001)
reviews: { round: 1, date: 2026-07-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - { round: 1, date: 2026-07-07, severity: "1 Major + 2 Minor", verdict: "remediated-in-round-1" }
  - { round: 2, date: 2026-07-07, severity: "0 findings (3 Info notes for T070a)", verdict: "clean" }
clarity_check: {}
---

# T025a: Contract test for SOCKS5 success-path log invariants

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 success-path log invariants — drive 100 sequential authenticated CONNECTs through port 8881 to an in-process upstream (the `accept-and-relay` mode of `fake_socks5_tor.go` from T019a); capture the data plane's stderr / journal output for the duration of the run; assert (a) no destination hostname, full URL, request or response header value, or body byte appears anywhere in the captured log; (b) no per-request timestamp at finer resolution than the ≥1-hour aggregate-counter bucket (FR-008, arch §6.4); (c) the only emitted lines belong to a fixed allowlist: startup, shutdown, `SidecarEvent` consumption, `ReloadTokens` apply, snapshot-write events. Expose the allowlist used by assertion (c) as a small shared Go helper (e.g. `tests/internal/loginvariants/`) so T025b and T070a reference the same canonical set rather than duplicate it — `tests/contract/socks5/no_per_request_logs_test.go`.

## Analysis

T025a is tests-first (Constitution Principle VII) for the success-path
journal surface — the inverse of T025's auth-failure journal scan
(T025's residue explicitly names T025a as the proper home for
exhaustive leak detection). T025a pins the allowlist that the four
cited line classes (`startup`, `shutdown`, `SidecarEvent` consumption,
`ReloadTokens` apply, snapshot-write events) are the ONLY journal
output the data plane may emit on the success path; everything else
(no matter how noisy or quiet) is a Constitution Principle I / III
breach.

The line-class shape was already pinned by T020's redteam finding
20260706-001 (`tests/contract/control-grpc/leakscan_test.go`'s clean-
journal case renders exactly three of the five classes; the remaining
two — `SidecarEvent` consumption and `shutdown` — are implicit in
T021's contract and T050's lifecycle). T025a makes the allowlist
explicit and re-usable.

- **Must hold:**
  - **Every journal line emitted during the request burst matches one
    of the five allowed line classes** (FR-008; arch §6.4 — the
    aggregate-counter bucket defines the only permissible per-event
    granularity; Principle I — the data plane is a dumb router that
    does not narrate per-request activity). The five classes are:
    (1) `startup` — emitted at boot before the listener accepts;
    (2) `shutdown` — emitted on SIGINT during graceful teardown;
    (3) `SidecarEvent` consumption — emitted when the DP processes a
    `WatchEvents` push (the line MUST NOT echo the event's free-text
    `Detail` field; T021 reserves a sibling class for the closed-
    vocabulary violation marker);
    (4) `ReloadTokens` apply — emitted when a generation is swapped
    in (line carries `generation=<N>`; MUST NOT echo hash or salt
    bytes — T020's no-logging clause);
    (5) snapshot-write events — emitted when the DP persists
    `dp-snapshot.json` (success and failure variants; the failure
    line carries `err=...`, never hash/salt content).
  - **No destination hostname, full URL, request/response header
    value, or body byte appears anywhere in the captured success-path
    journal delta** (FR-008 verbatim). The test drives 100 CONNECTs
    each to a DISTINCTIVE `.onion` hostname with a DISTINCTIVE body
    payload and a DISTINCTIVE UNAME; the delta is scanned for each
    in raw (cleartext — the form ASCII corpus items take when
    `[]byte(s)` IS the string), hex (both cases), all four base64
    variants, and the decimal-slice rendering slog's TextHandler
    and `fmt.%v` emit for `[]byte`. The nine-encoding set extends
    T020's `findSecretLeaks` (eight derived forms) with the raw
    entry T025's `leak_test.go:523` already carried — T025a's
    stargate-redteam round-1 flagged that ASCII corpus items
    (destinations, UNAMEs) would slip past all eight derived forms.
    Extracting this scan into the shared `loginvariants` package is
    what makes T025b/T070a reference the same canonical encoding
    set rather than each restating a subset.
  - **No sub-hour timestamp appears in the success-path journal
    delta** (FR-008; arch §6.4 — `aggregate_counters.hour_bucket` is
    `unix-hour`, the only permissible per-event granularity). Covered
    shapes: `HH:MM:SS`, `HH:MM:SS.nnn+`, RFC3339 prefix
    (`YYYY-MM-DDTHH:MM:SS`), bare ISO-8601 time (`THH:MM:SS`).
    Documented limitation: bare Unix-epoch seconds/millis are NOT
    matched — too broad a pattern false-positives on byte counts and
    port numbers (T025 leak_test.go R1; same constraint inherits).
  - **The UNAME carried through the auth path does not appear in the
    success-path journal delta** (contracts/socks5-auth.md §"No per-
    request log on auth failure" — the rule applies symmetrically to
    the success path; the SOCKS5 UNAME is opaque to the auth layer
    per FR-007 and is forwarded verbatim to the upstream, never
    logged locally). Belt-and-braces: the corpus scan in (a) above
    is parameterised over UNAMEs too.
  - **The shared `tests/internal/loginvariants/` package is importable
    from both `tests/contract/` (T025a's own test) and
    `tests/integration/` (T070a's future home) without violating
    Go's internal-package rule.** The package's import path is
    `github.com/zcat-app/stargate/tests/internal/loginvariants`; the
    rule's parent-of-`internal` root is `github.com/zcat-app/stargate/
    tests`, and every consumer named in the task body is rooted below
    that prefix (`tests/contract/socks5`, `tests/integration`). The
    package is its own workspace module so neither consumer's
    `go.mod` grows the other as a transitive dep.
  - **The sidecar_event allowlist class matches only the event-
    received line shape** (`msg="sidecar event"` and phrasing
    variants), NOT the closed-vocabulary detail-violation journal
    output T021's `journalHasDetailViolation` reserves. The
    violation journal line's `msg=` phrasing is unspecified (T021
    uses substring tolerance via `journalContains`); including any
    marker-based alternation created a per-request false-pass
    vector (stargate-redteam round-1 finding: `msg="request
    rejected" dst=…` would match). When T070a lands and pins the
    actual violation-msg= phrasing the DP emits, this class extends
    with that exact value; until then T070a's future delta-scoped
    journal check (snapshot around the violation push) plus the
    corpus scan is the established pattern.
  - **Self-skip while implementation is absent.** Every content gate
    (`dpharness.Start`'s boot-minimum on T042/T045/T050; the
    per-sub-test `RequireFile` on `auth/token.go` (T044) +
    `forward/tor.go` (T047) + `controlclient/client.go` (T045 client
    side)) MUST skip (never FAIL) while the implementation is absent;
    the skip self-lifts when those tickets land and the assertions
    flip to RED-driving (Principle VII tests-first; precedent
    T023/T024/T025).
- **Gated:**
  - `dpharness.Start` content-gates on T042/T045/T050 (listener +
    gRPC server hosting ReloadTokens + main wiring boot order).
    Additional per-sub-test gates on T044 (`auth/token.go`) and T047
    (`forward/tor.go`) and T045 client (`controlclient/client.go` —
    needed to receive the HEALTHY event that transitions
    `routeEnableMask[TOR]` to ENABLED, without which the forward
    path never engages and the success-path surface under test is
    never reached).
  - License-header check (verify gate 1) gates the SPDX header on
    every new `.go` file, including the loginvariants package files.
  - T020's `tests/contract/control-grpc/leakscan_test.go` already
    negative-controls the eight-encoding `findSecretLeaks` scan
    core — T025a's `loginvariants.AssertNoSecrets` reuses the same
    encoding set, so a regression in the scan core surfaces in T020
    before T025a.
  - T021's `tests/contract/control-grpc/watch_events_test.go` already
    gates the closed-vocabulary SidecarEvent `Detail` rejection —
    T025a's allowlist reserves the violation-marker line class
    (`violation` / `unknown detail` / `rejected` / etc.) so the
    success-path allowlist does not false-positive on the violation
    path's journal output.
  - T025's `tests/contract/socks5/leak_test.go` already gates the
    auth-failure path's sub-hour timestamp + corpus scan; T025a
    inherits the same `HH:MM:SS` regex shape and extends it to the
    success path.
- **Residue:**
  - **Bare Unix-epoch timestamps (e.g. `1735000000`, `1735000000.123`)
    are NOT matched by the sub-hour-timestamp regex.** A too-broad
    pattern false-positives on byte counts and port numbers (T025
    leak_test.go R1, same constraint). Mitigation: the allowlist
    itself is the primary gate — any line not matching one of the
    five allowed classes is a breach, regardless of whether the line
    contains a sub-hour timestamp. Cannot promote to gated without a
    journal-format-aware parser, which requires the DP to commit to
    a structured-logging format (T042/T050 implementation detail;
    not Stargate's contract-test job to mandate).
  - **A future binary journal sink (e.g. protobuf-encoded, JSON-
    encoded with binary field values) would evade both the corpus
    substring scan AND the timestamp regex.** The DP's v1 contract
    is text-form journal output (slog TextHandler / stderr); a
    switch to binary would require this test to be re-grounded and
    is filed as a future amendment if/when the journal sink changes.
    Mitigation: the `LockedBuffer` in `dpharness` captures raw bytes
    so a binary regression would surface as undecodable garbage in
    the journal that fails the allowlist check by definition.
  - **The shared `loginvariants.AssertNoSecrets` differs from T020's
    `findSecretLeaks` (`tests/contract/control-grpc/dpharness_test.go:418`)
    in two ways: (1) it carries the `raw` entry T020 is missing
    (T025a stargate-redteam round-1 fix — ASCII corpus items need
    raw), and (2) it lives in the shared package while T020's
    stays package-local.** Lifting the scan into the shared package
    AND adding `raw` to T020's call sites is a follow-up not in
    this ticket's scope (mirrors the
    `tests/contract/control-grpc/dpharness_test.go` →
    `tests/contract/internal/dpharness/` extraction precedent: the
    shared package lands first, the legacy duplication is filed as
    a follow-up). T025a's scan is the canonical home for new
    consumers (T025b/T070a); T020 stays on its local copy (which
    also lacks `raw` — a follow-up bug to file).
  - **T025's `tests/contract/socks5/leak_test.go` continues to use
    its own three-encoding `assertNoLeakCorpus`** (raw/hex/base64)
    rather than the eight-encoding `loginvariants.AssertNoSecrets`.
    T025's residue names T025a as the proper home; refactoring
    T025's leak_test.go to consume `loginvariants` is a follow-up
    (out of scope here — would re-touch a done ticket). T025a's
    test uses the canonical encoding set; T025's gap is documented
    and tracked.
  - **The test trusts `dpharness`'s `LockedBuffer` is append-only**
    so `delta := after[len(before):]` slicing is safe. True today
    (`strings.Builder` only appends); a future binary journal sink
    or a reset-on-rotate harness would break this assumption —
    re-grounding would surface as an index-out-of-bounds panic,
    not a silent false-pass.
  - **The test does not assert the data plane emits at least one
    line per allowed class.** Doing so would over-constrain the
    implementation (e.g. require a `shutdown` line during a test
    that doesn't trigger shutdown). The contract is permissive on
    "which classes appear", restrictive on "no class outside the
    allowlist" — that is what the test asserts.
  - **Redteam scope (privacy-critical, non-empty residue):** hunt
    for (a) any allowlist pattern so permissive it would match a
    per-request log line containing destination/body/UNAME bytes;
    (b) any encoding the corpus scan misses that a realistic slog
    /fmt/zap renderer would produce for `[]byte` or `string` fields;
    (c) any line-class category the task body omitted that the DP
    legitimately needs to emit (e.g. a reload-failure variant that
    should be in the allowlist as a `ReloadTokens` sub-class).

## Acceptance

### Named tests

1. **NEW: `tests/internal/loginvariants/loginvariants.go`** — the
   shared allowlist package. `package loginvariants` (import path
   `github.com/zcat-app/stargate/tests/internal/loginvariants`).
   Exported API:
   ```go
   // AllowedLineClass names one permitted data-plane journal line class.
   type AllowedLineClass struct {
       Name    string         // human-readable label
       Pattern *regexp.Regexp // matches a single journal line of this class
   }

   // AllowedLineClasses is the canonical allowlist every DP journal
   // line must match exactly one of. Tests that capture the DP journal
   // (T025a/b, T070a) assert every line matches a class in this slice
   // rather than restating the patterns. The set is reserved by the
   // existing contract tests (T020 ReloadTokens, T021 WatchEvents,
   // T025 leak); a new line class is a Constitution-level change that
   // amends this list AND every contract that references it.
   var AllowedLineClasses = []AllowedLineClass{ /* see fixture below */ }

   // AssertOnlyAllowedLines splits journal into lines and asserts each
   // matches at least one AllowedLineClasses pattern. t.Errorf per
   // violator (no fatal) so a multi-line breach surfaces all offenders
   // in one run. Trims trailing "\r\n" so a CRLF-formatted journal
   // (Windows-side container output edge case) does not false-negative.
   func AssertOnlyAllowedLines(t *testing.T, journal string)

   // AssertNoSubHourTimestamp asserts delta contains no sub-hour-
   // resolution timestamp shape (FR-008; arch §6.4 hour_bucket is the
   // only permissible per-event granularity). Covered shapes: HH:MM:SS,
   // HH:MM:SS.nnn+, RFC3339 prefix, bare ISO-8601 time. Bare Unix-
   // epoch seconds are deliberately NOT matched — see §Analysis residue.
   func AssertNoSubHourTimestamp(t *testing.T, delta string)

   // AssertNoSecrets asserts none of secrets (raw byte slices) appear
   // in journal in any of the eight textual renderings an accidental
   // slog/fmt logger would produce: hex (both cases), all four base64
   // variants, decimal slice `[b0 b1 …]`, decimal run `b0 b1 …`.
   // Extracted from tests/contract/control-grpc/dpharness_test.go's
   // findSecretLeaks (T020 redteam finding 20260706-001). Failure
   // messages name only the secret's index and encoding, never the
   // bytes, so a failing run cannot itself leak into CI logs.
   func AssertNoSecrets(t *testing.T, journal string, secrets ...[]byte)
   ```
   The five `AllowedLineClasses` entries (Name → Pattern, anchored on
   the `msg=` field slog's TextHandler emits, case-insensitive,
   matching any line prefix such as `time=… level=INFO `):
   - `startup`            → `(?im)^.*\bmsg=("?startup"?)\b.*$`
   - `shutdown`           → `(?im)^.*\bmsg=("?shutdown"?)\b.*$`
   - `reload_tokens_apply`→ `(?im)^.*\bmsg=("(?:tokens applied|reload[_ ]applied|reload_tokens_apply)")\b.*$`
   - `snapshot_write`     → `(?im)^.*\bsnapshot\b.*$` (matches both
     `msg="snapshot written"` and `msg="snapshot write failed"` per
     T020's `reload_tokens_test.go:206` and `leakscan_test.go:63`)
   - `sidecar_event`      → `(?im)^.*\bmsg=("(?:sidecar[_ ]event|event[_ ]received|watchevents[_ ]event)")\b.*$`
     OR the closed-vocabulary violation marker set
     (`\b(violation|unknown detail|invalid detail|forbidden detail|rejected)\b`)
     that T021's `watch_events_test.go:310` `journalHasDetailViolation`
     already reserves.

2. **NEW: `tests/internal/loginvariants/loginvariants_test.go`** —
   table-driven self-test of the allowlist. Pure-function tests, no
   DP process. Required cases (run even while the content gates skip
   the contract test, mirroring T020's `leakscan_test.go` precedent):
   - **`TestAllowedLineClasses_AcceptsEachClass`**: each of the five
     fixture strings (slog TextHandler shape from `leakscan_test.go:60`
     + the two new ones) matches exactly one `AllowedLineClass`
     pattern; a journal composed of all five in series yields zero
     findings under `AssertOnlyAllowedLines`.
   - **`TestAllowedLineClasses_RejectsPerRequestNoise`**: each of
     the per-request shapes the allowlist exists to forbid
     (`msg="CONNECT"`, `msg="forwarded" dst=example.onion`,
     `routed host=example.onion bytes=1234`, a bare hostname, a
     raw hex hash dump) is flagged by `AssertOnlyAllowedLines` (≥1
     finding per line).
   - **`TestAssertNoSubHourTimestamp_DetectsAndMisses`**: each
     matched shape (`12:34:56`, `12:34:56.789`,
     `2026-07-07T12:34:56`, `T12:34:56`) triggers; each non-match
     (`2026-07-07`, `12`, `aggregate_counters`, `127.0.0.1:8881`,
     a 10-digit Unix epoch `1735000000`) does not. The last
     non-match documents the Unix-epoch residue (§Analysis).
   - **`TestAssertNoSecrets_EightEncodingsEachCaught`**: a fixed
     32-byte stand-in secret is rendered each of the eight ways
     (`findSecretLeaks` encoding set) and `AssertNoSecrets` flags
     each. Negative-control: the secret-free journal fixture from
     `leakscan_test.go:60` produces zero findings.
   - **`TestAssertNoSecrets_NilAndEmptyIgnored`**: `nil` and `[]byte{}`
     entries in `secrets` are ignored, never treated as
     matches-everything (`leakscan_test.go:70` precedent).

3. **NEW: `tests/internal/loginvariants/go.mod`** — module declaration
   `module github.com/zcat-app/stargate/tests/internal/loginvariants`,
   `go 1.26`, `toolchain go1.26.3`. No `require` directives (the
   package is pure-Go stdlib: `regexp`, `strings`, `testing`,
   `encoding/hex`, `encoding/base64`, `fmt`, `sort`). SPDX header
   in the first 15 lines per `scripts/check-license-headers.sh`.

4. **NEW: `tests/contract/socks5/no_per_request_logs_test.go`** —
   the contract test. `package socks5` (reuses `dialProxy`,
   `readN`, `doMethodNegotiation`, `doSubnegotiation`,
   `writeConnectRequest`, `waitForWatchEventsDial` from
   T023/T024 in the same package — no new shared SOCKS5 helpers).
   `TestSOCKS5SuccessPathLogInvariants` with one consolidated body
   (the §Analysis must-holds are layered, not separable into
   independent sub-tests — splitting would force 4× DP boots for the
   same 100-CONNECT burst):
   - Content gates (boot-minimum via `dpharness.Start` covers
     T042/T045/T050; per-test `RequireFile` on `auth/token.go`
     (T044), `forward/tor.go` (T047), `controlclient/client.go`
     (T045 client — needed to receive the HEALTHY event that
     engages the forward path)).
   - Boot: `integration.NewServer(integration.AcceptAndRelay)` as
     the fake upstream; `dpharness.Start(t, WithUpstream(addr),
     WithBeforeBoot(func(ipcDir) { cp = fakecp.Start(t, ipcDir) }))`;
     `dpharness.Reload(t, h, 1, [MintToken(knownPlaintext)])` →
     assert `APPLY_STATUS_OK`; `waitForWatchEventsDial(t, cp)`;
     `cp.Send(fakecp.Healthy("tor"))`; brief quiesce
     (`250 * time.Millisecond`) so boot/setup journal lines flush.
   - Snapshot `before := h.Journal.String()`.
   - Drive **N=100 sequential authenticated SOCKS5 CONNECTs**. Each
     iteration: `dialProxy`; `SetDeadline(30s)`; `doMethodNegotiation`;
     `doSubnegotiation(uname="t025a-uname-NNN", passwd=knownPlaintext)`
     (assert `01 00`); `writeConnectRequest(host="t025a-dest-NNN-example.onion", port=443)`;
     `readN(10)` (assert `05 00…`); write a distinctive body of
     `len ≥ 32` bytes; read back the echo (`io.LimitReader`); close.
     Distinctive strings per iteration so the corpus scan can pin
     a leak to a specific iteration index.
   - Brief quiesce; `after := h.Journal.String()`;
     `delta := after[len(before):]` (safe — `LockedBuffer` is
     append-only; §Analysis residue).
   - **(a) Corpus scan**: for each iteration, `loginvariants.AssertNoSecrets(t, delta, []byte(dest), body, []byte(uname))`.
     The destination, the body, AND the UNAME must not appear in
     any of the eight encodings.
   - **(b) Timestamp scan**: `loginvariants.AssertNoSubHourTimestamp(t, delta)`.
   - **(c) Allowlist**: `loginvariants.AssertOnlyAllowedLines(t, delta)`.
     On a correct DP implementation this is the strongest gate — it
     catches per-request log lines that don't happen to contain any
     specific corpus item (e.g. `msg=forwarded bytes=42`).

5. **EDIT: `go.work`** — append `./tests/internal/loginvariants` to
   the `use:` block (after `./tests/integration`).

6. **EDIT: `tests/contract/go.mod`** — add:
   ```
   replace github.com/zcat-app/stargate/tests/internal/loginvariants => ../internal/loginvariants
   require github.com/zcat-app/stargate/tests/internal/loginvariants v0.0.0-00010101000000-000000000000
   ```
   Same unpublished-module rationale as the existing
   `replace github.com/zcat-app/stargate/tests/integration` directive.

7. **`tests/integration/go.mod` is NOT touched in this ticket.** A
   `require` for a package no file in the module imports would be
   pruned by `go mod tidy`, so landing it now does not survive. T070a
   adds the `replace` + `require` pair when it actually imports the
   package — same pattern T024 used when it first imported
   `tests/integration` from `tests/contract`.

### Behavioral assertions

- `tests/internal/loginvariants/loginvariants.go` exists, is
  `package loginvariants`, carries the Apache 2.0 SPDX header in the
  first 15 lines, and exposes exactly the API in (1).
- `tests/internal/loginvariants/loginvariants_test.go` compiles and
  passes under `go test -race -count=1 ./...` from the package dir
  in a `golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c` container.
- `tests/contract/socks5/no_per_request_logs_test.go` compiles,
  lints clean (gofmt + go vet), and **self-skips** under the
  content gates on the current tree (T042/T044/T045/T046/T047/T050
  absent); the skip lifts when those tickets land and the assertions
  flip to RED-driving (Principle VII tests-first).
- `go.work`, `tests/contract/go.mod` carry the new module + replace
  directives; `go work sync` and `go mod tidy` in `tests/contract`
  produce no diff beyond the new entries.
- `scripts/verify.sh` green (the new package and test file are
  outside `data-plane/`, so verify gate 2 does not compile them;
  gate 1 license-header scan catches the new SPDX headers; the
  container validation in (8) is the human-run check until T076
  wires `tests/**` into CI).

### Runnable command

```
# Validate in a throwaway container (host has no Go toolchain — T019b precedent):
docker run --rm -v "$PWD":/src -w /src golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
  sh -c '
    (cd tests/internal/loginvariants && gofmt -l . && go vet ./... && go test -race -count=1 ./...) &&
    (cd tests/contract && gofmt -l . && go vet ./... && go test -race -count=1 ./socks5/...)
  '

# Repo gate:
scripts/verify.sh
```
Expected on the current tree: loginvariants package self-tests PASS
(pure-function, no DP dependency); the SOCKS5 contract test
SKIPs under the content gates (T042/T044/T045/T046/T047/T050 absent);
verify.sh PASS=8 SKIP=2 FAIL=0 (unchanged — gate 2 still scoped to
`data-plane/`). License-headers gate still PASS.

## Out-of-scope

- **The counter side-channel** (`request_count` / `byte_count`
  increments on auth-pass; no-op on auth-fail) — T025c / T025d.
  T025a's journal scan covers the textual leak surface only; the
  counter row is gated separately because it is at a different
  Constitution layer (Principle III metadata restraint) and uses a
  different observability probe (`GetStatus` RPC vs journal scan).
- **The auth-failure journal path** — T025
  (`tests/contract/socks5/leak_test.go` sub-test (d)). T025a owns
  the SUCCESS path; the failure path is its mirror image and
  already gated. T025's three-encoding `assertNoLeakCorpus` is a
  known partial duplicate of T025a's eight-encoding
  `loginvariants.AssertNoSecrets`; refactoring T025's leak_test.go
  to consume `loginvariants` is filed as a follow-up (out of scope
  here — would re-touch a done ticket and risk regression on a
  Constitution surface without a parallel implementation landing
  to RED-drive the change).
- **The long-lived bidirectional CONNECT byte-pipe invariant** —
  T025b. T025b reuses T025a's `loginvariants` package for its own
  allowlist assertion; T025a does not write T025b's test.
- **Integration-level success-path log assertions under real Tor**
  — T070a (`tests/integration/circuit_drop_midstream_test.go`).
  T070a reuses T025a's `loginvariants` package; T025a does not
  write T070a's test.
- **HTTP CONNECT path success-path log invariants** — T026
  (`tests/contract/socks5/connect_auth_success_test.go`). T026's
  scope is the HTTP CONNECT auth-success byte shape; if T026
  subsequently needs a success-path journal assertion, it consumes
  `loginvariants` rather than this ticket re-touching it.
- **Refactoring `tests/contract/control-grpc/dpharness_test.go`'s
  `findSecretLeaks` to delegate to `loginvariants.AssertNoSecrets`.**
  The scan core is the same; the legacy call sites in T020/T021
  stay on the package-local copy. Filed as a follow-up; T025a's
  package is the canonical home for new consumers, the migration
  of existing consumers is a separate sweep.
- **EDIT: `tests/integration/go.mod` is NOT in this ticket's diff**
  (see §Acceptance item 7 for rationale).
- **CI workflow wiring for `tests/internal/loginvariants/` and
  `tests/contract/socks5/`.** T076 owns the path filters; T025a
  ships the package + test, T076 adds the workflow that runs them
  on PRs touching `data-plane/`. The host has no Go toolchain, so
  the container command in §Acceptance is the human-run check
  until T076 lands.
- **The DP implementation this test gates**: T042 (listener),
  T044 (auth/token.go), T045 (gRPC server + control client),
  T046 (snapshot write), T047 (forward/tor.go), T049 (counters),
  T050 (main wiring). All are content-gated by name; this ticket
  ships only the test surface and the shared allowlist package.
- **Mandating a specific structured-logging format (slog TextHandler
  vs JSON vs logfmt) for the DP.** The allowlist patterns are
  format-tolerant (case-insensitive, `msg=` field OR phrasing-
  based). If the DP commits to a specific format, the patterns
  can be tightened in a follow-up; this ticket's job is to gate
  the line-class contract, not pick the renderer.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
