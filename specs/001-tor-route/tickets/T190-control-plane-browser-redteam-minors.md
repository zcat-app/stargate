---
id: T190
title: 'Resolve surviving control-plane and browser redteam minors'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 2 minors that survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 12
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "II: Plane Separation"
  - "III: Privacy-Preserving by Construction"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-004
  - specs/001-tor-route/data-model.md
decision_refs:
  - "architecture spec §14.5 Part 2: WebRTC read at startup and on browser restart (item 1 needs a spec decision)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T190: Resolve surviving control-plane and browser redteam minors

## Context

Surviving items from the 2026-09-29 cumulative redteam area 2 after
falsification. The stale `control.sock` finding was falsified (shipped Netty
unlinks before bind) and the skip-when-missing extension tests were falsified
(other suites fail); they are out of scope except the misleading javadoc noted
below.

## Analysis

- Must hold: each item is fixed with a discriminating regression or corrected text.
- Gated: extension and CP test suites, `scripts/verify.sh`.
- Residue: item 1 requires a maintainer/spec decision before code.

## Acceptance

1. WebRTC re-audit: decide in the spec whether FR-004(b) requires a fresh check
   per protected decision. If so, re-read `peerConnectionEnabled` per decision
   (`onChange` alone misses about:config edits) and fail closed while pending;
   test a mid-session flip. Otherwise document the startup-only residue in the
   threat model.
2. Zero-row timeline: keep a single current zero checkpoint for `enrolled`
   (not one per closed hour), never write a zero for an hour not observed, and
   test the total row count.
3. Remove the unused `management` permission (or land its specified consumer)
   and update `manifest.test.js`.
4. Exclude tests, `run-tests.sh`, README and untracked files from
   `extension/package.sh` output; test the archive listing.
5. CP capabilities: mount `stargate-keys` read-only in the CP with ownership that
   keeps the directory non-CP-writable, and update `control_mount_test.sh`. (The
   orphan `stargate-tor-config` mount is T191 item 7.)
6. Nits: token input `type="password"`; stale "non-persistent" comment in
   `hardening.js`; drop or constrain unused timestamped V001 tables before any
   writer lands; correct the `ControlGrpcService` and `HealthEndpoint` javadocs.

## Out-of-scope

Blocked-result semantics (T186); revocation status (T187); private-window access (T188).
