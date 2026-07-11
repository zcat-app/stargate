---
id: T095
title: 'Complete the inter-plane wire contract'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#M5
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T090]
parallel: false
files_budget: 10
privacy_critical: true
constitution_refs:
  - "II: Versioned authenticated inter-plane contract"
  - "VII: Contract test-first"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §5.3
  - specs/000-architecture/spec.md §5.4
  - specs/001-tor-route/contracts/control-grpc.md §"Transport invariants"
decision_refs: []
remediates: T022
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T095: Complete the inter-plane wire contract

## Context

T022 was completed while deferring real UID/GID, peer authentication,
unknown-major rejection, and plane-restart behavior. Production tickets must
not invent the missing wire contract.

## Analysis

- **Must hold** — both UDS peers are mutually authenticated by pinned Ed25519
  identities; protocol major/minor is authenticated and rejected before any
  RPC handler accepts behavior; filesystem roles work under real service IDs.
- **Gated** — container-level tests exercise modes/owners, allowed and denied
  dials, wrong certificates, unknown major, minor compatibility, and plane
  restart survival.
- **Residue** — certificate validity/rotation policy is operator-visible and
  must be recorded in the threat model and decision log.

## Acceptance

1. Specify Ed25519 X.509 certificate derivation, peer public-key pinning,
   validity policy, UDS authority/SAN handling, and key ownership.
2. Define authenticated gRPC metadata carrying protocol major/minor and
   capabilities on every RPC; an interceptor rejects an unknown major before
   invoking application behavior. Additive minor versions remain compatible.
3. Update architecture, control contract, proto-generation notes, installer
   key contract, and `SECURITY-DECISIONS.md` before implementation tickets.
4. Add container-level regression tests for socket ownership/mode, peer-group
   dial success, out-of-group `EACCES`, wrong-key rejection, major mismatch,
   minor compatibility, no TCP transport, and CP restart survival.
5. Refine T038/T045/T050 to consume the exact contract; do not leave any
   acceptance row deferred to implementation detail.
6. Wire the tests into T076's exhaustive module accounting and pass verify.

## Out-of-scope

Remote TCP gRPC and automated certificate rotation.
