---
id: T092
title: 'Amend the token verifier and lifecycle contract'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#B5+M1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
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
  - specs/001-tor-route/spec.md §FR-006
  - specs/001-tor-route/spec.md §FR-013
  - specs/001-tor-route/data-model.md §1
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens"
decision_refs: []
spec_amend_for: specs/001-tor-route/data-model.md §1
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T092: Amend the token verifier and lifecycle contract

## Context

Per-request Argon2id can allocate roughly 12.8 GiB for 200 simultaneous
one-token authentications even though the token already has 128 random bits.
The same design lacks a persistent generation source and treats file I/O
failure as revoke-all.

## Analysis

- **Must hold** — bounded-memory authentication; one candidate digest per
  request; constant-time comparison across stored verifiers; monotonic
  generation survives CP restart; I/O/parse failure preserves DP state;
  explicit valid `tokens: []` alone means revoke-all.
- **Gated** — T093 pins correctness, restart reconciliation, failure
  semantics, peak RSS, and unauthenticated-flood behavior before production
  implementation resumes.
- **Residue** — the install-time pepper is a new secret and must be covered by
  installer permissions, export/wipe policy, and the threat model.

## Acceptance

1. Replace Argon2id for random bearer tokens with HMAC-SHA-256 using a
   dedicated 32-byte install-time pepper shared by CP and DP. Hash each
   candidate once and compare against every verifier with constant-time
   operations; keep the pepper out of `dp-snapshot.json`.
2. Specify pepper generation, ownership, backup/export/import, rotation, and
   wipe behavior; update T088 provisioning acceptance as needed.
3. Persist a CP generation record and define reconciliation using the DP's
   current generation, including explicit retry behavior after stale status.
4. Preserve the DP's last-known generation on missing, unreadable, invalid, or
   unparseable input. Only a successfully parsed explicit empty list revokes
   all tokens.
5. Separate manual configured-token records from enrollment-only fields so no
   insert requires nonexistent device public keys.
6. Narrow Java memory-erasure claims to mutable buffers the implementation can
   actually clear; do not claim SnakeYAML-created `String` values were erased.
7. Update spec, plan, data model, proto contract, threat model, and
   `SECURITY-DECISIONS.md`; refine T020a/T035a/T035/T041/T044/T046/T079a.

## Out-of-scope

Human-memorable passwords and dashboard enrollment are separate features.
