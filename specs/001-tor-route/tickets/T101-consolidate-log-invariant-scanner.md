---
id: T101
title: 'Consolidate the privacy log-invariant scanner'
status: in-review
created: 2026-07-11
last_updated: 2026-07-12
source: review/sol-review.md#A2
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: true
files_budget: 6
privacy_critical: true
constitution_refs:
  - "III: Aggregate-only privacy-safe logs"
  - "VII: Tests-first for leak paths"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §FR-006
  - specs/001-tor-route/spec.md §FR-008
decision_refs: []
remediates: T025
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T101: Consolidate the privacy log-invariant scanner

## Context

The shared scanner is stronger than the older control-gRPC copy, but neither
currently defines allowed fields tightly enough and a failing assertion can
echo the secret-bearing line into CI output.

## Analysis

- **Must hold** — one scanner covers raw, hex, base64, and decimal secret
  forms; allowed message classes also constrain fields; failures never print
  captured content.
- **Gated** — scanner self-tests include a raw plaintext leak, an allowed
  message with a forbidden extra field, and safe index/length-only diagnostics.
- **Residue** — novel encodings remain red-team fuzzing input, not a reason to
  duplicate scanners.

## Acceptance

1. Make `tests/internal/loginvariants` the only scanner implementation and
   migrate all contract/integration callers to it.
2. Define an allowlist of message classes and permitted field names; reject
   extra fields even when `msg=` itself is allowed.
3. Failure diagnostics contain only source index, byte length, and rule ID;
   never the rejected line or matched secret.
4. Add regression tests for the false-assurance cases in review A2 and run all
   consuming Go modules through T076/verify.

## Out-of-scope

Changing production log vocabulary beyond what existing contracts require.
