---
id: T190
title: 'Resolve surviving control-plane and browser redteam minors'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 2 minors that survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 17   # raised 12 -> 17 for T155 attempt-2 additions (maintainer-approved 2026-10-01): TokenLoader.java, TokenLoaderTest.java, data-model.md, quickstart.md, THREAT-MODEL.md
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


Added 2026-10-01 from the T155 attempt-2 redteam (`reviews/redteam-20261001-79d49e9.md`),
maintainer-approved:

- Item 1 addition (A2-M1 gap): `hardening.test.js` re-calls `auditHardening()`
  (`hardening.js:48`; test :184, :196, `reauditObservesChangedProfileState` :341) but no
  production path does; the only production call is load-time (`hardening.js:129`) and the
  `:29` comment ("re-reads the setting every call") implies otherwise. Either add a
  production re-read caller (per protected decision, failing closed) or relabel those
  tests as API-contract-only and fix the comment.

7. THREAT-MODEL.md:707 "The destination service does not learn the user's IP address"
   is scoped to the onion route: in 001 only `.onion` destinations are Tor-routed, and
   clearnet resources an onion page causes the browser to fetch go Direct (with local DNS),
   revealing the user's IP and resolver to those hosts (cf. §2.5, §6.2; spec.md:123). (A2-M3)
8. `TokenLoader` (`TokenLoader.java:145` uses SnakeYAML `compose()`, which keeps duplicate
   keys; `:184-189` takes the first top-level `tokens`; `:216-225` keeps the last duplicate
   within a record) rejects the whole file on any duplicate key at document, top-level or
   record level as `config_error` (no store, generation or push), documented in data-model
   §1.1. TokenLoaderTest covers a duplicate top-level `tokens` (e.g. an appended
   `tokens: []`) and duplicate `label`/`token` in a record. (A2-M4)
9. Quickstart "Check token delivery (and revocation)" (`quickstart.md:122-137`) states that
   `scripts/stargate status` reflects only the credential set the running control plane
   last loaded, so `stargate-control` must be restarted after editing `tokens.yaml` before
   checking; the `ACKNOWLEDGED(<generation>)` row at :134 is made true. (A2-m6)

## Out-of-scope

Blocked-result semantics (T186); revocation status (T187); private-window access (T188).
