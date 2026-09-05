---
id: T035
title: 'Implement `control-plane/core/src/main/java/.../TokenLoader.java`'
status: in-progress
created: 2026-07-04
last_updated: 2026-09-05
source: tasks.md#T035
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093, T035a]
parallel: false
files_budget: 8
privacy_critical: true
tests_first: [T035a, T093]   # T096/M6: the self-skipping suites that gate this impl (Constitution VII)
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §FR-017 (fixed-path /etc/stargate/tokens.yaml; plaintext = 32-char lowercase hex; verifier = HMAC-SHA-256(pepper, token) at read time; format violations rejected label-only, never token bytes)"
  - "specs/001-tor-route/spec.md §FR-018 (read once at startup; enrolled/revoked/config_error audit per the diff; T092 failure semantics — missing/unreadable/invalid/unparseable → NO ReloadTokens call; explicit `tokens: []` is the sole revoke-all path; missing-file exemption writes no audit row; never throw)"
  - "specs/001-tor-route/data-model.md §1.1 (validation table + narrowed memory-erasure claim: the mutable byte[] HMAC input buffer is zeroed before the next entry; SnakeYAML Strings NOT claimed erased)"
  - "specs/001-tor-route/data-model.md §1.5 (verifier = HMAC-SHA-256 under the 32-byte install-time pepper; no salt)"
  - "specs/001-tor-route/data-model.md §1.6 (entity invariants incl. the T092 failure-semantics table)"
  - "specs/001-tor-route/data-model.md §1.7 (§1.7 write order: store → generation → ReloadTokens; full-set rewrite incl. unchanged labels)"
  - "specs/001-tor-route/data-model.md §1.8 (token_generation singleton; propose last + 1; stale + DB-wipe reconciliation)"
  - "specs/001-tor-route/data-model.md §1.9 (configured_tokens is the manual-YAML record home; enrolled_devices reserved)"
  - "specs/001-tor-route/data-model.md §4 (audit row vocabulary: enrolled/revoked/config_error; target=label for diff rows, tokens.yaml for config_error; detail_json fixed shapes; actor=tokens.yaml derived by the sink)"
  - "specs/001-tor-route/contracts/control-grpc.md §ReloadTokens (PushResult stale handshake fields)"
decision_refs:
  - "specs/001-tor-route/tickets/T092-amend-token-verifier-lifecycle.md (the contract amendment; ticket §Notes T092 block is authoritative over the pre-amendment body)"
  - "specs/001-tor-route/tickets/T093-test-token-verifier-lifecycle.md (landed cross-plane oracle: mint determinism, buffer-clear reference model, failure decision table, last+1 proposal)"
  - "specs/001-tor-route/tickets/T035a-unit-test-for-tokenloaderjava-t035-diff.md (landed test-first suite + TokenLoaderContract seam; §Analysis pins the surface this ticket must conform to; §Out-of-scope forbids editing its artifacts)"
  - "SECURITY-DECISIONS.md §Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T035: Implement `control-plane/core/src/main/java/.../TokenLoader.java`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/core/src/main/java/.../TokenLoader.java` — parse `/etc/stargate/tokens.yaml` (**FR-017** — fixed-path config; same file FR-018's startup-only-reload contract reads) per data-model.md §1.1 validation table; for each token, draw a fresh 16-byte salt from `java.security.SecureRandom` (data-model.md §1.2 — per-token salt, never reused across tokens or across loads of the same token); argon2id-hash each plaintext using shared `Argon2idParams` (T011) with that salt; populate the per-token `TokenHash{hash, salt}` on the outgoing `ReloadTokensRequest`; zero the plaintext `byte[]` after hashing; log warnings without token bytes on validation failure. Diff the post-load label set against the previous generation's `enrolled_devices` rows (injected Panache repository) and emit, via `AuditLogService` (T036): `enrolled` for each label new this load, `revoked` for each label present in the previous generation but absent from the new file, `config_error` for each load failure (`detail_json.kind = "parse"|"validation"|"io"` per data-model.md §4 — `parse` on YAML syntax errors with the parser-reported line number, `validation` on per-entry format violations with the offending label, `io` on file-unreadable conditions like `AccessDeniedException`; no token bytes ever appear in `detail_json` or in the warning logs). Treat `FileNotFoundException`/`NoSuchFileException` as the legitimate first-boot state — log a single warning, write **no** audit row, push an empty `ReloadTokensRequest`, return cleanly (per FR-018: never throw on missing/unreadable file — the CP must come up healthy with an empty generation so the DP keeps serving per Principle II). Update `enrolled_devices` to match the new label set as part of the same transaction.

## Analysis

Required (`privacy_critical: true`) — full property map. Grounded 2026-09-05
against the landed T035a suite + `TokenLoaderContract.java` (the seam this
ticket fills), T093's `TokenLifecycleContractTest`, `AuditLogService` (T036,
the production `AuditSink`), and data-model.md §1.1/§1.5–§1.9/§4 as amended
by T092. **The pre-amendment ticket body above is retired where it conflicts
with the T092 amendment (§Notes)** — same five contradictions T035a §Analysis
resolved; the body's salt/Argon2id/`enrolled_devices`/"missing file pushes an
empty request" wording is NOT implemented.

**Scope (binding):** one production file — `TokenLoader.java`. T035a's
§Out-of-scope forbids editing `TokenLoaderTest.java` and
`TokenLoaderContract.java`; the pinned surface (one constructor: `Path,
byte[], ConfiguredTokenStore, GenerationStore, AuditSink, ReloadChannel,
VerifierMinter`; one no-arg `load()`) is the binding. Production adapters —
the Panache `configured_tokens` store, the gRPC `ReloadChannel`, the
production `VerifierMinter`, the T041 wiring that reads the FR-017 path and
the §1.7 pepper file — are other tickets'; the loader is path/pepper-agnostic
by construction (both constructor-injected).

- **Must hold (property map)**
  - **Diff → audit rows (§4/FR-018):** `enrolled` per label new this load,
    `revoked` per stored label absent now; `target` = the label;
    `detail_json` = `{"source":"tokens.yaml","generation":<gen>}`. The sink
    (T036) derives `actor=tokens.yaml`.
  - **`config_error` rows (§4):** `target="tokens.yaml"` always; `kind=parse`
    with the parser-reported line (≥1) on YAML syntax errors; `kind=validation`
    with the offending record's line on per-entry/structure violations (detail
    keys ⊆ {kind, line}); `kind=io` with `line=null` on unreadable-file
    conditions. Offending label goes to the warning log, never the audit
    detail.
  - **First-boot missing file (§1.1/§4):** zero audit rows, zero store/generation
    writes, NO `ReloadTokens` call, no throw — single path-only warning.
  - **Failure ⇒ no push (§1.6/Principle II):** unreadable file, parse error,
    structural validation failure (missing/typed-wrong `tokens` key, empty
    document), and a file whose records ALL fail validation each leave store,
    generation record, and DP untouched — the DP keeps its last-known list and
    keeps serving. Never throws (FR-018); an `InvocationTargetException` on
    any input is a test-visible violation.
  - **Explicit `tokens: []` = sole revoke-all (§1.6):** one `revoked` row +
    one delete per stored label, generation bump, ONE push with an EMPTY
    verifier set — the only failure-shaped input that pushes.
  - **Partial-failure tolerance (§1.1):** per-record violations (token not
    32-char lowercase hex; label empty/`>`64 code points/NUL/duplicate; record
    not a mapping) each emit one `validation` row + a label-only warning
    (never token bytes) and are skipped; valid records still enroll, persist,
    push.
  - **§1.7 full-set write + order:** every successful load rewrites the FULL
    current record set (unchanged labels get fresh verifiers — the pepper-
    rotation property) inside one begin/commit pair with every store mutation
    and diff row inside it; the generation is recorded, then `ReloadTokens`
    pushes — push strictly last.
  - **Generation proposal (§1.8):** `lastGeneration() + 1` — a restarted CP
    proposes `last + 1`, never 1.
  - **Verifier mint (§1.5/§1.1):** through the injected `VerifierMinter` only;
    the loader fills a mutable `byte[]` with the token's UTF-8 bytes, mints,
    and zeroes that buffer before the next record (the narrowed erasure claim
    — no claim about SnakeYAML `String`s). Pushes and store writes carry
    verifiers only.
  - **Stale reconciliation (T035 note (c), §1.3/§1.8):** on a
    `PushResult{stale=true}` the loader adopts `currentGeneration + 1`,
    records it, and retries — bounded (a misbehaving DP reply must not spin
    the CP; the DP reply is IPC edge input), warning on exhaustion, never
    throwing.
  - **No plaintext/pepper escapes (§1.6):** no token bytes or pepper in any
    audit field, warning reason, journal-observable payload, or pushed set.
- **Gated (verify.sh catches fail-closed once this file lands)**
  - The entire behavioral surface above is pinned by the landed T035a
    loader-driving cases (`TokenLoaderTest` — 12 `@Test`s, currently
    self-skipping; the reflective probe lifts them the moment this class
    exists, so they bite inside this ticket's own verify run) plus T093's
    `TokenLifecycleContractTest` (mint properties, failure decision table,
    last+1 proposal) and the green-today oracle layer.
  - Error Prone + NullAway (parent-pom compile gate, T104); license-header
    check; `lint-ticket.py` clean.
- **Residue (no gate catches; scoped for review/redteam)**
  - **Log-line content.** §1.1's warning properties (label-only on token
    violations; single path-only line on missing file) are log-surface claims
    the unit suite cannot capture without over-pinning the logging seam
    (T035a residue, accepted there). The no-plaintext sweep covers audit/RPC/
    store surfaces; log shape gates at T041's wiring layer.
  - **Stale-retry path is fake-invisible:** the T035a `FakeReload` returns
    non-stale only, so the reconciliation branch is exercised by review, not
    by the suite (T093 pinned the proposal rule; T020 row 6 pins the DP side).
  - **All-records-invalid ⇒ no-push** and **structure violations** (missing/
    non-sequence `tokens` key; empty document; non-mapping records) are
    §1.1-file-row consequences not in T035a's case list — implemented here,
    review-focus items. Deliberately NOT a revoke-all: §1.6 reserves that for
    a successfully-parsed explicit empty list.
  - **A loader that bypasses its injected `VerifierMinter`** stays
    unobservable through the seams (T035a residue) — design review finding.
  - **Label sub-rules** (NUL, >64, duplicate) implemented per §1.1 but
    unit-pinned only for the token-format rows.

## Acceptance

Named production artifact: `control-plane/core/src/main/java/app/zcat/
stargate/auth/TokenLoader.java` — the ONLY new file (files_budget 8 ⇒ 1 used;
`Argon2idParams`/`TokenLoaderContract` untouched). Named gating suites (NOT
edited by this ticket): `control-plane/core/src/test/java/app/zcat/stargate/
auth/TokenLoaderTest.java` (T035a) and `.../TokenLifecycleContractTest.java`
(T093). Runnable commands: `scripts/verify.sh` green from repo root; fast
inner loop `cd control-plane && ./mvnw -B -q -pl core test`.

1. The T035a reflective probe conforms: the class exposes the pinned
   constructor surface + no-arg `load()`; all 12 loader-driving cases LIFT
   (skip count drops to zero for `TokenLoaderTest`) and PASS inside this
   ticket's verify: first-load enroll+push (a), minter-buffer zeroing (h),
   unchanged-reload rewrite (b), remove (c), add (d), mixed atomicity (e),
   malformed-entry tolerance (f), unparseable YAML (g), missing file (i),
   unreadable file (j), explicit `[]` revoke-all, restart proposes `last+1`.
2. The T093 suite stays green (mint/erasure-reference/failure-decision
   conformance) and the green-today oracle layer stays green.
3. `load()` never throws on any file input the suites exercise (missing,
   unreadable, unparseable, all-invalid, valid) — asserted by construction:
   an `InvocationTargetException` fails the T035a harness.
4. `scripts/verify.sh` fully green from repo root (all gates; data plane and
   extension untouched — zero diff outside `control-plane/core` + this
   ticket).
5. Apache-2.0 header present (`scripts/check-license-headers.sh` green);
   no secrets in source (the pepper arrives via constructor; test fixtures
   stay in the test files T035a already allowlisted).

## Out-of-scope

- **`TokenLoaderTest.java` / `TokenLoaderContract.java`** — T035a artifacts;
  a surface that cannot host the design is a refine escalation against
  T035a, not a test edit.
- **Production adapters:** Panache `configured_tokens` store +
  `token_generation` persistence, the gRPC `ReloadChannel` (T038), the
  production `VerifierMinter`, and the T041 wiring (`@QuarkusMain` startup
  sequence; reads the FR-017 path + §1.7 pepper file). The loader is
  path/pepper-agnostic.
- **DP-side stale rejection** (`APPLY_STATUS_STALE_GENERATION`) — T020 row 6.
- **Log-shape gating** (warning texts) — T041's wiring layer.
- **`Argon2idParams.java`** — retired by T092/§1.5; removal is housekeeping
  for a follow-up, not this ticket (surgical-changes doctrine).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.**
`TokenLoader.java` must: (a) compute verifiers as `HMAC-SHA-256(pepper,
token)` reading the 32-byte pepper from `/etc/stargate/keys/pepper.key`
(`data-model.md` §1.7), NOT Argon2id; (b) read+write the monotonic
generation from the persisted `token_generation` record and propose
`last + 1` (`data-model.md` §1.8); (c) on a stale `ReloadTokens` reply,
retry with `current_generation + 1` from the DP's response
(`data-model.md` §1.3); (d) on missing/unreadable/invalid/unparseable
`tokens.yaml`, log `config_error` and **NOT call `ReloadTokens`** (DP
keeps last-known) — only a successfully-parsed `tokens: []` revokes all
(`data-model.md` §1.6); (e) persist manual tokens to `configured_tokens`
(NOT `enrolled_devices`) — `enrolled_devices` is reserved for future
dashboard enrollment (`data-model.md` §1.9 / arch §6.1/§6.6). Tests-first
discipline is discharged by T093 (blocked_by T092); this ticket runs
after T093.
