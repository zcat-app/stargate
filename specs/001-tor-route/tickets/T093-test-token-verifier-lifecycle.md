---
id: T093
title: 'Test the amended token verifier and lifecycle'
status: pending
created: 2026-07-11
last_updated: 2026-07-15
source: review/sol-review.md#B5+M1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T092]
parallel: false
files_budget: 11
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for authentication"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/data-model.md §1
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens"
decision_refs: []
remediates: T020
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T093: Test the amended token verifier and lifecycle

## Context

T092 changes an authentication and cross-plane contract. Principle VII
requires executable tests before T035/T044 or related wiring is implemented.

## Analysis

Property map (grounding-verified 2026-07-15; `privacy_critical: true` AND
`complexity: high` → required per `docs/process/analysis.md`). Constitution
principles land here as concrete properties, not prose. Grounding read the
amended `data-model.md` §1/§1.5/§1.6/§1.8, `contracts/control-grpc.md`
§"ReloadTokens · Tests" rows 1–6, `control.proto` (post-T092), the drifted
`grpcpb/control.pb.go` (still `TokenHash{hash,salt}`), the T020 contract
test + `dpharness_test.go` (argon2 `mintToken`, `snapshotFile{Hashes[].{Hash,Salt}}`),
the V001 migration (`configured_tokens`, `token_generation`), and the
consuming tickets T044 / T035 / T035a / T079a.

- **Must hold**
  - **Proto drift eliminated (#6, the hard gate).** The regenerated
    `grpcpb/control.pb.go` + `control_grpc.pb.go` declare `TokenVerifier{
    verifier bytes}`, `ReloadTokensResponse.current_generation`, and NO
    `TokenHash`/`salt` symbol. The T020 contract test
    (`reload_tokens_test.go`) + harness (`dpharness_test.go`) reference
    `TokenVerifier` and the HMAC mint helper only; the `snapshotFile` shape
    is `schemaVersion: 2` / `verifiers[].verifier` (base64); the salt-length
    invalid-length rows are dropped (single shared pepper → no per-token
    salt); the reconciliation-retry sub-test (contract row 6) is added.
    `grep -r 'TokenHash\|salt' proto/stargate/v1/grpcpb/
    tests/contract/control-grpc/{reload_tokens,dpharness}_test.go` is empty.
  - **One HMAC per candidate (#1).** The verifier computes
    `HMAC-SHA-256(pepper, candidate)` exactly ONCE per request and compares
    that single 32-byte tag against every stored verifier — O(1) hash work
    regardless of token-list size N (Constitution Principle III — no
    per-request memory-DoS vector; sol-review B5).
  - **Constant-time across the set (#1).** The comparison loop does NOT
    short-circuit on the first match (short-circuit leaks which slot
    matched via timing); the candidate tag is compared against all N
    verifiers every request (Principle III side-channel resistance).
  - **Malformed rejected before verification (#1).** A candidate that is
    not a 32-char lowercase-hex token is rejected BEFORE any HMAC work
    (data-model.md §1.1 validation rule; no hash allocated for garbage).
  - **No secret in logs (#1).** No verifier byte, pepper byte, or plaintext
    byte appears in any test-captured output / failure message (Principle
    III; index-only hygiene like `assertNoSecretLeak`).
  - **Configured-token persistence shape (#2).** `configured_tokens(label
    PK, verifier BLOB NOT NULL 32 B, created_at, last_seen_hour,
    revoked_at)` and the singleton `token_generation(generation)`
    apply cleanly via V001 (arch §6.6/§6.7) — the manual-token home separate
    from `enrolled_devices` (device pubkey NOT NULL).
  - **Mutable-buffer clearing (#2).** The mutable `byte[]` HMAC input
    buffer is zeroed (`Arrays.fill`) after each HMAC op — the NARROWED
    erasure claim (not the SnakeYAML `String` objects the loader cannot
    reach; data-model.md §1.1 "Memory-erasure claim is deliberately
    narrow").
  - **Failure → no ReloadTokens (#2).** A missing / unreadable / invalid /
    unparseable `tokens.yaml` triggers a `config_error` audit row and does
    NOT call `ReloadTokens` — the DP keeps its last-known list and keeps
    serving (Principle II "continue routing"). Only a successfully-parsed
    explicit `tokens: []` is the revoke-all path.
  - **Cross-plane restart convergence (#3).** A restarted CP reads its
    persisted generation record, proposes `last + 1`; if the DP reports a
    higher `current_generation` the CP adopts `current + 1` and retries
    deterministically; the last-known token list is NOT dropped during the
    restart window (Principle II + the reconciliation handshake).
  - **Peak-RSS under flood (#4).** 200 concurrent unauthenticated attempts
    keep peak RSS inside a documented memory ceiling — the falsifier for
    sol-review B5 (the prior Argon2id path allocated ~12.8 GiB here).

- **Gated** — `scripts/go-workspace-gate.py` compile + vet of every
  workspace module (a test referencing a missing symbol → FAIL, so the
  Go unit tests compile against existing symbols only); Maven `verify`
  compiles + runs the JVM tests; the license-header check gates SPDX; the
  reworked T020 contract suite content-gates via `startDP` on T045/T050
  and self-skips at runtime (so the #6 regen + rework lands green). T076's
  JSON skip accounting means an all-skip package is SKIP, never a
  masquerade PASS.

- **Residue** (accepted; named for redteam + the self-lifting content-gates)
  - **Constant-time is not fully catchable by functional tests.** A timing
    side-channel in the comparison loop survives a test that only checks
    match-position independence functionally. Receives `stargate-redteam`
    adversarial review (this ticket is `privacy_critical: true`) in
    addition to the functional assertion that the loop visits every
    verifier.
  - **Tests-first lifecycle.** The Go unit tests (#1) and JVM contract
    tests (#2) establish the executable algorithm/persistence spec against
    existing symbols (stdlib crypto + the V001 schema + test-local
    decision helpers); they pass today and pin the contract T044/T035 must
    conform to. The cross-plane restart test (#3) and the reworked T020
    suite (#6) content-gate on the DP/CP impl files (T035/T044/T045/T050)
    and self-lift when those land — at which point a buggy impl is FAIL,
    not SKIP. This is the repo's established tests-first + content-gate
    discipline (Constitution Principle VII; see
    `tests/contract/socks5/connect_auth_success_test.go` lines 31–40,
    95–107).
  - **No secret-bearing failure lines.** Test failure messages use
    index-only hygiene (mirror `assertNoSecretLeak` /
    `loginvariants.AssertNoSecrets`); a failing run must not itself leak
    verifier/pepper/plaintext bytes into CI logs.

## Acceptance

1. Add Go unit tests for one candidate HMAC per request, comparison across the
   full verifier set, malformed input rejection before verification, and no
   secret-bearing logs.
2. Add JVM tests for configured-token persistence, mutable-buffer clearing,
   missing/unreadable/parse failure causing no `ReloadTokens`, and explicit
   valid empty input causing revoke-all.
3. Add a cross-plane restart test: CP restart observes DP generation N,
   proposes N+1, retries deterministically on stale status, and converges
   without dropping the last-known token list.
4. Extend T079a's design with peak-RSS and unauthenticated-flood assertions;
   200 concurrent attempts must remain inside a documented memory ceiling.
5. Tests are authored before production implementation, fail for the intended
   missing behavior, and are then content-gated only where the repository's
   incremental green-gate policy requires it.
6. **Eliminate the proto-source-vs-generated-stub drift left by T092.**
   Regenerate `proto/stargate/v1/grpcpb/{control.pb.go,control_grpc.pb.go}`
   from the amended `proto/stargate/v1/control.proto` (now `TokenVerifier{
   verifier}`, no `salt`, response `current_generation`) so the committed
   stubs match the contract of record; rework the T020 contract test
   (`tests/contract/control-grpc/reload_tokens_test.go`, `remediates: T020`)
   off the retired `TokenHash{hash,salt}` onto `TokenVerifier` + the HMAC
   mint helper, drop the salt-length table rows, add the reconciliation-retry
   sub-test (contract §"ReloadTokens · Tests" row 6), and re-baseline the
   snapshot content match onto `schemaVersion: 2` verifier-only shape. The
   gate passes when `scripts/verify.sh` is GREEN with the regenerated stubs
   in place and no `TokenHash`/`salt` reference remains in the regenerated
   `grpcpb` package or the T020 test — i.e. the T092 `KNOWN DRIFT` block in
   `control.proto` is resolved, not merely documented.

## Out-of-scope

Implementing T035, T041, T044, or T046; those tickets consume this contract.

## Notes

**T092 dependency (2026-07-15).** T092 amended the contract this ticket
pins (`data-model.md` §1; `contracts/control-grpc.md` §"ReloadTokens";
`proto/stargate/v1/control.proto`). The stub regeneration + T020
remediation that T092 deferred (its `control.proto` `KNOWN DRIFT` block)
is **acceptance item #6 above** — a hard gate, not just a note. Without
it the proto source and the generated `grpcpb` stubs drift; both land
here, test-first, before T035/T041/T044/T046 resume.
