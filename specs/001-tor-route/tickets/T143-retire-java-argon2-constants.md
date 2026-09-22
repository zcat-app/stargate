---
id: "T143"
title: "Retire obsolete Java token-verifier constants"
status: done
created: "2026-09-12"
last_updated: 2026-09-22
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T011", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "low"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T011"
tests_first: []
reviews: { round: 1, date: 2026-09-22, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T143: Retire obsolete Java token-verifier constants

## Context

Existing finding 20260727-003: Go was migrated by T044, but Java constants and tests still describe the superseded Argon2id verifier as current.

## Analysis

- **Must hold:** FR-017 and data-model.md §1.5/§1.7 retain HMAC-SHA-256
  with the 32-byte install-time pepper. The retired Java `Argon2idParams`
  API and its parameter assertions must disappear without changing the
  active minter, loader, or HMAC/pepper tests (Acceptance 1–2).
- **Gated:** the Java reactor catches remaining consumers at compilation;
  `TokenLifecycleContractTest` preserves the HMAC/pepper contract and
  `TokenLoaderTest` preserves loader behavior. The new
  `RetiredTokenVerifierTest.retiredArgon2idParametersAreNotAvailable`
  checks the retired class is absent from the active classpath, with the
  current minter as a positive control. It does not scan historical prose.
- **Residue:** compilation cannot establish historical tests-first ordering
  or explain supersession. Acceptance 3's record below and both independent
  reviewers check those claims (Principles V, VII and VIII). This cleanup
  adds no cryptographic mechanism or trust boundary and leaves §5.14's
  pepper-compromise and timing limitations intact.

## Acceptance

1. Verify no active Java consumer needs the obsolete constants; remove the retired implementation and assertions without touching HMAC verification semantics.
2. Keep current HMAC/pepper contract coverage and add a scoped check for retired active symbols if needed; do not ban historical discussion text.
3. Record T011/T092 supersession honestly without rewriting approved commits or claiming historical tests-first evidence.
4. Run affected Java suites, scripts/verify.sh, and both required reviews.

## Out-of-scope

Token algorithms, parameter migration for unrelated password uses, or global comment churn.

## Notes

### T011/T092 supersession

T011's Argon2id constants and parameter assertions describe the former
verifier contract. T092 superseded that contract with HMAC-SHA-256 plus an
install-time pepper; T044 migrated the Go verifier. T143 removes the unused
Java remainder. The T011 and T092 approved commits and ticket records remain
historical; this removal does not retroactively establish tests-first
compliance for either ticket. The new absence regression is T143 evidence;
the unchanged HMAC suites are regression coverage for existing behavior.

### T143 verification evidence (2026-09-22)

- Pre-fix HEAD: `3010f676a54800c32767c97bb2cf96b7946e9ca5`.
  The new `RetiredTokenVerifierTest` was written and run before deleting
  either Argon2id source. From `control-plane`,
  `sh mvnw -B -q -pl core -am -Dtest=RetiredTokenVerifierTest -Dsurefire.failIfNoSpecifiedTests=false test`
  failed with one assertion failure: expected `ClassNotFoundException`,
  but none was thrown. The current-minter positive control passed.
- After deleting the unused class and obsolete parameter tests,
  `sh mvnw -B -q -pl core -am clean test` passed all 31 core tests,
  including the new regression, 10 token-lifecycle contract tests and
  14 loader tests, with no failures or skips. A clean build removes stale
  compiled copies of the deleted class before testing the active classpath.
- Local logs and pre-fix inputs are retained under `target/runs/T143.*`:
  `red.log`, `red-head`, `red.patch`, `red-test.java`, and `java-green.log`.
  The pre-fix patch SHA-256 is
  `009c0e324ab7df827924ee2ae328f16e9d09842797ebf477a44be6cf62874869`;
  the regression source SHA-256 is
  `1677c72806ddf69a378a7bc6837297e22a7770bcf5add1245bfc9144e417630c`.

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
