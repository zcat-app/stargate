---
id: T035a
title: 'Unit test for `TokenLoader.java` (T035) diff logic and validation'
status: pending
created: 2026-07-04
last_updated: 2026-09-02
source: tasks.md#T035a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093]
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §FR-017 (tokens.yaml is the operator-facing CP config surface; plaintext token = 32-char lowercase hex; verifier = HMAC-SHA-256(pepper, token) at read time; format violations rejected with label-only, never token bytes)"
  - "specs/001-tor-route/spec.md §FR-018 (read once at startup; enrolled/revoked/config_error audit per the diff against the previous load; T092 failure semantics — missing/unreadable/invalid/unparseable → config_error (or exempt first-boot warning) and NO ReloadTokens call; explicit `tokens: []` is the sole revoke-all path; missing-file exemption writes no audit row)"
  - "specs/001-tor-route/data-model.md §1.1 (tokens.yaml validation table + narrowed memory-erasure claim: the mutable byte[] HMAC input buffer is zeroed; SnakeYAML Strings are NOT claimed erased)"
  - "specs/001-tor-route/data-model.md §1.5 (verifier = HMAC-SHA-256 under the 32-byte install-time pepper; no salt)"
  - "specs/001-tor-route/data-model.md §1.6 (entity invariants: plaintext never persists outside tokens.yaml; failure semantics — no ReloadTokens on missing/unreadable/invalid/unparseable)"
  - "specs/001-tor-route/data-model.md §1.8 (token_generation singleton; propose last + 1)"
  - "specs/001-tor-route/data-model.md §1.9 (configured_tokens is the manual-YAML record home; enrolled_devices reserved for dashboard enrollment)"
  - "specs/001-tor-route/data-model.md §4 (audit row vocabulary: enrolled/revoked/config_error; actor=tokens.yaml for token actions; detail_json kinds parse|validation|io; missing-file writes no row)"
  - "specs/001-tor-route/contracts/control-grpc.md §ReloadTokens (ReloadTokensRequest{generation, tokens[]}; TokenVerifier carries a 32-byte verifier, no salt)"
decision_refs:
  - "specs/001-tor-route/tickets/T092-amend-token-verifier-lifecycle.md (the contract amendment; acceptance #7 names T035a for refinement; its §Analysis is the must-hold source)"
  - "specs/001-tor-route/tickets/T093-test-token-verifier-lifecycle.md (the landed oracle suite this ticket extends; its Javadoc explicitly defers 'the detailed unit tests against the real loader with repository/audit fakes' to T035a)"
  - "SECURITY-DECISIONS.md §Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)"
  - "specs/001-tor-route/tickets/T068a-contract-test-for-the-response-header-in.md (round-1 APPROVE precedent this ticket follows: a tests-first ticket lands GREEN via self-skips that gate on the impl's surface and lift when it exists)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T035a: Unit test for `TokenLoader.java` (T035) diff logic and validation

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `TokenLoader.java` (T035) diff logic and validation — `control-plane/core/src/test/java/.../TokenLoaderTest.java`. Pure JVM unit test: in-memory fake of the `EnrolledDeviceRepository` (Panache repository for `enrolled_devices`), capturing fake of `AuditLogService` that records every `write(action, target, detailJson)` call, and a test-double `Argon2idHasher` that records the `byte[]` references it receives and exposes a post-call all-zero assertion (so the plaintext-zeroing rule from data-model.md §1.1 — "the `byte[]` cleared to zero before the next file entry is processed" — is testable without a real argon2id run; no `@QuarkusTest`, no SQLite, no DI runtime). Cases (each a separate `@Test`): (a) first-load with empty `enrolled_devices` and N valid tokens → N `enrolled` audit rows (one per label, `actor='tokens.yaml'`), no `revoked`, no `config_error`; `enrolled_devices` populated to match the new label set; (b) unchanged load (same labels as previous generation) → zero new audit rows; `enrolled_devices` unchanged; (c) one label removed from `tokens.yaml` → exactly one `revoked` row for that label; the corresponding `enrolled_devices` row is deleted; (d) one new label added → exactly one `enrolled` row; one new `enrolled_devices` row inserted; (e) mixed add+remove → both rows emitted in the same transaction (test asserts the call sequence to the fake repo is `BEGIN, delete(removed), insert(added), audit.write*, COMMIT` — no interleaved partial state visible to a concurrent reader); (f) malformed token entry (wrong length, non-hex chars) → `config_error` row with `detail_json.kind = "validation"` and `detail_json.label` set; no token bytes anywhere in `detail_json` or in the captured logs; the record is skipped, valid records continue to load (data-model.md §1.1 partial-failure tolerance); (g) unparseable YAML → `config_error` row with `detail_json.kind = "parse"` and a line number; (h) plaintext-zeroing: after (a) completes, the test asserts every `byte[]` ever handed to the test-double hasher is now all-zero (data-model.md §1.1's "`byte[]` cleared to zero" rule, which is the operationalisation of data-model.md §1.6's "plaintext tokens never persist outside `tokens.yaml`" entity invariant); (i) **file missing** (`FileNotFoundException` / `NoSuchFileException` thrown by the YAML reader) → loader returns an empty token list, emits **one** warning log line that mentions the path but contains no token-bytes context (there are none — the file did not open), writes **no** `config_error` audit row (the missing-file case is distinct from a parse/validation failure; per FR-018 the CP "logs a warning and proceeds with an empty token list" — no operator-actionable audit entry is created because the legitimate first-boot state is also "file does not exist yet"), and pushes an empty `ReloadTokensRequest` to the data plane via the injected fake `ReloadTokensClient` so callers observe the same RPC shape as a successful load; (j) **file unreadable** (`AccessDeniedException` thrown on open, e.g. the operator-mounted file has wrong group/mode) → same outcome shape as (i) for token-list and RPC, but emits a single **`config_error`** audit row with `detail_json.kind = "io"` and `detail_json.line = null` (matching the §4 schema; `io` is the kind that distinguishes a permissions misconfiguration from a missing file — `line` is null because there is no parser context) so the operator sees a distinct signal from "file just isn't there yet" — the audit log is the operator's path to noticing a permissions misconfiguration. In both (i) and (j), the loader MUST NOT throw (the CP would crash-loop on a missing/unreadable file otherwise, defeating Principle II's "data plane keeps serving with last-known token list" property; instead the CP comes up healthy with an empty generation and the DP returns `AUTH_REQUIRED` on all requests per FR-018). Pairs with T035 (impl); T035a MUST be authored and failing before T035 lands. Principle VII applies because `tokens.yaml` is the operator-facing public CP config surface and the diff-derived audit log is operator-visible — together they fall under "Public API surfaces (REST, gRPC contracts)" in the principle's discipline table (treating the operator-facing config file + audit log as a public-surface pair).

## Analysis

Property map (grounding-verified 2026-09-02; required — `privacy_critical:
true` per `docs/process/analysis.md`). The ticket body above is the
PRE-amendment tasks.md text; per the tasks.md header note and T092
acceptance #7, the **T092 amendment (in §Notes below) is authoritative**
where the two conflict. The §Acceptance derives from the amended contract.

**Grounding findings resolved into this design (five body-vs-amendment
contradictions):**

1. Body's `EnrolledDeviceRepository` → `configured_tokens` store
   (§1.9: `enrolled_devices` is reserved for dashboard enrollment; manual
   YAML records live in `configured_tokens`). The fake persists nothing —
   it records ordered calls against a shared journal.
2. Body's `Argon2idHasher` test-double → a `VerifierMinter` seam
   (§1.5: `verifier = HMAC-SHA-256(pepper, token)`, no salt). Same
   test-double mechanics as the body asked: records every `byte[]`
   reference it receives, exposed for a post-load all-zero assertion.
3. Body's case (i) "pushes an empty `ReloadTokensRequest`" → RETIRED.
   Amended §1.6/FR-018: a missing file does NOT call `ReloadTokens`
   (the DP keeps its last-known list, Principle II) and writes NO audit
   row (first-boot exemption, §4). Only a successfully-parsed explicit
   `tokens: []` pushes (an empty generation) — the revoke-all path.
4. Body's case (j) `config_error kind=io line=null` and case (g)
   `kind=parse` → unchanged by the amendment; both additionally get
   **no `ReloadTokens` call** and **no store mutations**.
5. Body's "push via the injected fake `ReloadTokensClient`" → the loader
   owns the push (T035's amendment note (c): on a stale reply the loader
   retries with `current + 1`), so the seam is a `ReloadChannel`
   injected into the loader; T038's gRPC client implements the channel
   and T041 only calls `load()`. (T041's step list "load (T035) → push
   (T038)" predates T092; the amendment note is later and authoritative.)

**How a unit test for a not-yet-existing class lands green** (the
load-bearing constraint): `verify.sh` Gate 3 runs `./mvnw -q verify` on
this host (JDK 25 present — verified), so the T012a compile-red pattern
(a test referencing an absent class) is a hard FAIL here, not a SKIP.
The T068a round-1-APPROVE precedent governs instead: a tests-first
ticket lands **green via self-skips that gate on the impl's surface and
lift when it lands**. Java analog, three layers:

- **`TokenLoaderContract.java`** (main sources, seam-only, zero
  behavior): the injectable ports the body's fakes REQUIRE —
  `ConfiguredTokenStore`, `GenerationStore`, `AuditSink` (the
  `write(action, target, detailJson)` shape tasks.md T036 fixes),
  `ReloadChannel`, `VerifierMinter` — plus the two value records. This
  is what makes fakes for an absent class compilable, and it is the
  testability surface T035 must conform to (T035 is `blocked_by` T035a:
  the test-first ticket pins the seams; the impl fills them).
- **Oracle layer (green now):** the §4 audit-row vocabulary and the
  enrolled/revoked diff algebra pinned as executable reference
  expectations — extending (not duplicating) T093, which pinned mint,
  erasure-narrowing, and the failure decision table but NOT the
  diff/audit semantics.
- **Loader-driving layer (self-skips until T035 lands):** a reflective
  probe locates `app.zcat.stargate.auth.TokenLoader`. Absent → every
  behavioral `@Test` skips with a loud Principle-VII marker (JUnit
  assumption = skip; surefire stays green). Present but **not**
  exposing the pinned surface → hard FAIL naming expected vs actual
  (this is the conformance gate that gives the binding teeth — a
  signature drift by T035 fails loudly instead of silently re-skipping).
  Present and conforming → the tests drive the REAL loader through the
  fakes; every assertion below bites from that moment on (i.e., inside
  T035's own verify run).

Pinned surface (the ONLY surface assumption; everything else is
observable through the fakes): one constructor whose parameter type list
is exactly `{Path tokensYaml, byte[] pepper, ConfiguredTokenStore,
GenerationStore, AuditSink, ReloadChannel, VerifierMinter}` (matched
order-insensitively; package-private allowed) and one no-arg method
named `load` (return type and modifier unpinned). Path + pepper are
constructor-injected so the loader stays path/pepper-agnostic; T041's
wiring reads the FR-017 fixed path and the §1.7 pepper file.

- **Must hold:**
  - **Diff → audit rows (§4, FR-018):** `enrolled` row per label new
    this load, `revoked` per label present in the previous store set but
    absent now, `actor='tokens.yaml'` (actor mapping asserted at T036's
    layer — the sink derives it; residue below), `detail_json` =
    `{"source":"tokens.yaml","generation":<gen>}`.
  - **First load (body (a), amended):** empty store + N valid tokens →
    N `enrolled` rows, zero `revoked`/`config_error`, store receives
    the N upserts, generation store proposes `0 + 1`, ONE push carrying
    verifiers == `HMAC-SHA-256(pepper, tokenUtf8)` per token (§1.5
    verifier construction under the pepper — amendment note (a)).
  - **Unchanged load (body (b)):** same label set → zero diff rows, no
    upsert/delete, generation still bumps, one push (§1.8: every
    successful parse writes verifiers + bumps + pushes).
  - **Remove (c) / add (d) / mixed (e):** exactly one `revoked` row +
    one delete; exactly one `enrolled` row + one upsert; mixed → the
    shared journal shows `begin` before every mutation and diff-audit
    write, `commit` after them (atomicity — no interleaved partial
    state), push last (after commit and the generation write).
  - **Validation partial failure (body (f), §1.1):** wrong-length and
    non-hex entries → one `config_error` row each, `kind="validation"`,
    `label` set, line unpinned; the offending record is skipped and the
    valid records still enroll/upsert/push.
  - **Unparseable YAML (body (g)):** one `config_error`, `kind="parse"`,
    `line` present and ≥ 1 (parser context); no store mutations, no
    generation write, NO push, loader does not throw.
  - **Plaintext zeroing (body (h), narrowed per §1.1/T092):** the fake
    minter records every `byte[]` reference handed to it (pure mint, NO
    internal clear — the T093 mint-then-clear step is the LOADER's role
    in the real system, so a loader that omits `Arrays.fill` leaves
    recorded buffers non-zero and FAILS: non-tautological, unlike a
    minter-side clear); after load, every recorded reference is
    all-zero. No assertion about SnakeYAML `String`s (the narrowed
    claim — amendment note (b)).
  - **Missing file (body (i), amended):** no audit row at all, NO push,
    no store/generation writes, loader does not throw (first-boot
    exemption, §4/§1.6).
  - **Unreadable file (body (j)):** exactly one `config_error`,
    `kind="io"`, `line` null-or-absent; NO push; no mutations; no
    throw. Distinct from missing precisely so an operator sees a
    permissions misconfiguration. POSIX chmod in `@TempDir`, guarded by
    an assumption that skips when running privileged (root bypasses
    permission checks — the skip is environmental, not contractual).
  - **Explicit empty list = revoke-all (amendment note (c), §1.6):**
    parsed `tokens: []` → one `revoked` row per previously-stored
    label, store deletes them all, generation bumps, ONE push with an
    EMPTY verifier list. The only failure-shaped input that pushes.
  - **Generation proposal (§1.8, amendment/T035 note (b)):** store
    preloaded with 7 → next successful load proposes and pushes 8, and
    records 8 (restart-safety through the real loader; T093 pinned the
    oracle rule, this pins the loader calling it).
  - **No plaintext escapes (§1.6):** across every capturing case, the
    union of captured audit `detail_json` strings + pushed payloads
    contains NO 32-hex plaintext and no pepper bytes (pushes carry
    verifiers only — labels are not in the ReloadTokens contract by
    design).
- **Gated:** `scripts/verify.sh` Gate 3 (mvnw) compiles + runs the
  suite; oracle-layer tests PASS pre-T035; loader-driving tests SKIP
  (never FAIL) until `TokenLoader` lands, then gate T035's verify.
  `scripts/lint-ticket.py` clean at ground.
- **Residue** (documented, not silently dropped):
  - **Log-line observability.** The body's "one warning log line
    mentioning the path" (missing-file) and "warnings without token
    bytes" properties are log-surface claims; a no-container pure-JVM
    unit test cannot portably capture the Quarkus/JBoss log pipeline
    without over-pinning the loader's logging (a log seam would be
    design intrusion). The unit suite asserts no-plaintext on every
    fake-observable surface (audit, RPC, store); log-line shape is
    gated at the wiring/contract layer (T041) and by the operator-
    visible audit rows. Accepted as layering, not omission.
  - **Actor mapping** (`actor='tokens.yaml'`) lives in the audit sink
    (T036 fixes `write(action, target, detailJson)`); asserted by
    T036/V001 tests, not here.
  - **Stale-retry handshake** (T035 note (c)) is wire+state behavior
    spanning CP and DP; T093 pinned the proposal rule and T020 row 6
    pins the DP side. The unit suite's fake returns a non-stale reply
    only; retry orchestration is out of scope (below).
  - **A loader that bypasses its injected `VerifierMinter`** and mints
    internally is unobservable through seams (its verifiers would still
    equal expected HMACs). The pinned constructor makes the seam the
    only injection point; a bypass is a design review finding, not a
    test failure — flagged here so it is a conscious acceptance.
  - **Per-entry clear windows** are post-hoc observable only at load
    boundaries; a reuse-buffer loader that clears per mint passes (its
    security property is equivalent), a never-clear loader fails.
  - **Label-validation sub-rules** (empty, >64 chars, NUL, duplicate
    label; §1.1 label row) are not in the body's case list; only
    token-format violations are tested. Store-side stamps (`created_at`,
    `revoked_at`) are the production store's concern (§1.9).

## Acceptance

Named test: `control-plane/core/src/test/java/app/zcat/stargate/auth/
TokenLoaderTest.java` (pure JUnit 5 + SnakeYAML already on the core
classpath; NO `@QuarkusTest`, no SQLite, no DI runtime). Named
production artifact: `control-plane/core/src/main/java/app/zcat/
stargate/auth/TokenLoaderContract.java` (seam interfaces + value
records, zero behavior). Runnable command: `scripts/verify.sh` green
from repo root (Gate 3 = `cd control-plane && ./mvnw -B -q verify`);
fast inner loop: `cd control-plane && ./mvnw -B -q -pl core test`.

1. `TokenLoaderContract.java` exists in main sources declaring exactly
   the five seam interfaces + two records of §Analysis, with Javadoc
   citing the governing data-model.md § for each — zero behavior, so
   the impl ticket T035 owns all loader logic.
2. Oracle layer passes TODAY (no skip): `auditRowVocabularyIsPinned`
   (§4 fixed vocabulary: actions `enrolled`/`revoked`/`config_error`;
   config_error `detail_json` kinds `parse`/`validation`/`io`; token
   diff rows carry `{"source":"tokens.yaml","generation":N}` — asserted
   as parsed maps against literal golden JSON) and
   `diffOracleComputesEnrolledAndRevokedSets` (symmetric-difference
   algebra: added/removed/unchanged/mixed fixtures).
3. Loader-driving cases — each a separate `@Test`, self-skipping until
   `TokenLoader` exists, hard-FAILING on a nonconforming surface
   (§Analysis), then driving the real loader through the fakes:
   `firstLoadEnrollsEveryLabelAndPushesGeneration1` (a);
   `firstLoadLeavesEveryMinterBufferZeroed` (h);
   `unchangedReloadEmitsNoDiffRowsButBumpsGenerationAndPushes` (b);
   `removedLabelRevokesExactlyThatLabel` (c);
   `addedLabelEnrollsExactlyThatLabel` (d);
   `mixedAddRemoveEmitsBothRowsInsideOneStoreTransaction` (e);
   `malformedEntryIsRejectedWithValidationRowAndValidRecordsContinue`
   (f, wrong-length + non-hex rows);
   `unparseableYamlEmitsParseErrorRowAndDoesNotPush` (g);
   `missingFileIsFirstBootNoAuditNoPushNoThrow` (i);
   `unreadableFileEmitsIoRowWithoutLineAndDoesNotPush` (j);
   `explicitEmptyListIsRevokeAll` (amendment (c));
   `restartProposesLastGenerationPlusOne` (§1.8).
4. Every loader-driving case that captures audit/RPC/store traffic runs
   the no-plaintext sweep (§1.6) over the captures — zero 32-hex
   plaintext occurrences, zero pepper bytes.
5. Pre-T035 state is GREEN, not red: `mvnw verify` passes with the
   loader-driving tests reported skipped (Principle VII tests-first
   state per the T068a precedent); no production class named
   `TokenLoader` is introduced by THIS ticket (that file is T035's
   named artifact).
6. Both new files carry the Apache-2.0 header (`scripts/
   check-license-headers.sh` stays green); test fixtures reuse the
   repo's documented example tokens (T093's gitleaks practice).

## Out-of-scope

- **`TokenLoader.java` itself** — T035's named artifact. THIS ticket
  must not create it; the loader-driving layer self-skips until T035
  lands it.
- **T035 must NOT edit `TokenLoaderTest.java` or
  `TokenLoaderContract.java`.** If the pinned surface genuinely cannot
  host T035's design, that is a **refine** escalation against this
  ticket (rewrite §Analysis's pinned-surface paragraph), not a test
  edit — "fix the code, never the test" applies, and this paragraph is
  the explicit authorization boundary.
- **Stale-generation retry orchestration** (T035 note (c)), CP DB-wipe
  DP-reconciliation (§1.8 runtime wiring, T041/T038), and the
  `WatchEvents`/`GetStatus` surfaces — wire/state behavior pinned at
  T093 + T020 + T038's layer.
- **Audit sink persistence semantics** (append-only triggers,
  `actor` derivation, `configured_tokens` DDL) — T036's tickets and
  the landed `V001MigrationTest`/`AuditLogAppendOnlyTest` gate those.
- **Log-line shape** (§Analysis residue): gated at T041's wiring layer.
- **Label-validation sub-rules** beyond token format (empty/long/NUL/
  duplicate labels): follow-up ticket territory if review demands them;
  not in the body's case list.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.** The unit
test must cover: (a) HMAC-SHA-256 verifier construction under the pepper
(not Argon2id); (b) the **narrowed memory-erasure claim** — assert the
mutable `byte[]` HMAC input buffer is zeroed, and do NOT assert that
SnakeYAML-materialized `String` values were erased (the parser hands back
immutable `String`s the loader cannot reach; `data-model.md` §1.1 "Memory-
erasure claim is deliberately narrow"); (c) the failure semantics —
missing/unreadable/invalid/unparseable `tokens.yaml` triggers
`config_error` and NO `ReloadTokens` call, while a successfully-parsed
`tokens: []` is the revoke-all path (`data-model.md` §1.6); (d) manual
token persistence to `configured_tokens`. T093 (blocked_by T092) is the
cross-plane/Go side of the test-first discipline.
