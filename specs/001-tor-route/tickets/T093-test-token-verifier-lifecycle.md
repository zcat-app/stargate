---
id: T093
title: 'Test the amended token verifier and lifecycle'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#B5+M1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T092]
parallel: false
files_budget: 8
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

## Out-of-scope

Implementing T035, T041, T044, or T046; those tickets consume this contract.
