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

- **Must hold** — correct HMAC acceptance/rejection, fixed comparison work,
  no pepper in snapshots/logs, restart-safe generations, and no accidental
  revoke on file failure.
- **Gated** — named JVM, Go, and cross-plane tests cover each property and are
  included by the single green gate through T076.
- **Residue** — constant-time behavior receives adversarial review in addition
  to functional tests; tests must not print secret-bearing failure lines.

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
