---
id: T189
title: 'Resolve surviving transport-area redteam minors'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 1 minors that survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 10
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "I: Dumb Router (NON-NEGOTIABLE)"
  - "III: Privacy-Preserving by Construction"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/socks5-auth.md
  - specs/001-tor-route/spec.md#FR-002
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T189: Resolve surviving transport-area redteam minors

## Context

The 2026-09-29 cumulative redteam (snapshot 694dbd8) was followed by a
falsification pass. Only findings that survived it, with their corrected
claims, are listed here. Falsified or accepted items (half-close, clock jump,
errortpl, username shape, loadedAt, single-request byte count, T061 threshold,
IPv6 loopback) are recorded in the review report and are not in scope.

## Analysis

- Must hold: each item below is fixed with a discriminating regression, or its
  normative text is corrected so no claim exceeds what is enforced.
- Gated: `scripts/verify.sh`; mutation evidence per item where a test is added.
- Residue: none beyond what each item states.

## Acceptance

1. Upstream method selection (defence in depth): the DP offers Tor only RFC 1929
   username/password and treats any other selected method as ROUTE_REFUSED with
   zero forwarded bytes. The regression uses a stub that selects no-auth whenever
   offered. Optionally forbid `PreferSOCKSNoAuth` in the torrc invariants.
2. Pre-auth flood: bound concurrent pre-auth connections (sized against the
   512m memory limit) and do not exit on temporary Accept errors; test both.
3. Log tests: pin that the DP's fds 1/2 are `/dev/null` (e.g. `/proc/<pid>/fd`)
   and point the no-per-request-log assertions at the retained channels
   (state volume, /tmp, RPC payloads) with a positive control.
4. Stale username wording: correct `contracts/socks5-auth.md:86-89`,
   `THREAT-MODEL.md:1098-1101`, `contracts/torrc.md:52`, `spec.md:142` and the US2
   acceptance scenario at `spec.md:170` to the opaque `sg1:` HMAC username.
5. Constant-time claim: add a test that fails when the production verifier loop
   exits early (e.g. an internal compare-count hook), or correct
   `socks5-auth.md:137` and the leak_test header to what is actually tested.

## Out-of-scope

Behaviour changes to the sg1 username contract; T079a memory bounds beyond item 2.
