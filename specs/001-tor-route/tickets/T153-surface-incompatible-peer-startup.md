---
id: "T153"
title: "Surface incompatible peer versions at CP startup"
status: in-review
created: "2026-09-12"
last_updated: 2026-09-23
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T041", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T041"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T153: Surface incompatible peer versions at CP startup

## Context

Browser/control audit C3: GrpcReloadChannel catches FAILED_PRECONDITION like transient unavailability, despite wire-auth section 5.2 startup-error wording.

## Analysis

- Must hold: wire-auth §5.2 version rejection aborts CP startup; temporary outage
  remains contained. Neither path alters DP forwarding (Principle II), bypasses
  version interceptors, or retains peer-controlled error detail (Principle III).
- Gated: `PeerVersionStartupTest` drives production bootstrap over mTLS/UDS and
  distinguishes incompatible peers in both directions from compatible dispatch
  and transient rejection; checks the fixed error, absent cause/suppressed detail,
  zero rejected application dispatch and cleanup of the partially bound listener.
  Existing `InterPlaneWireTest` and Go controlclient tests cover interceptor rules.
- Residue: Java fixture evidence is not a live mixed-version deployment test;
  production diagnostic suppression is covered separately by T152's gates.
  Missing/invalid token files produce no RPC and cannot discover incompatibility.
  Durable retry/reconciliation is T132's scope. This repairs an existing startup
  error contract without changing trust boundaries or cryptographic authority.

## Acceptance

1. Add a CP startup integration case against a peer rejecting its major version and assert the documented startup error is observable.
2. Distinguish incompatible-version rejection from transient transport outage without changing DP independence or bypassing version interceptors.
3. Preserve closed error vocabulary and suppress peer-supplied detail in operational logs.
4. Run cross-plane version tests, scripts/verify.sh and both required independent reviews.

## Out-of-scope

Protocol major bumps, general retry semantics (T132), or accepting incompatible RPC application dispatch.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

### T153 tests-first evidence

- Pre-fix HEAD: `efc9b0285ec35ab78ad26786e90226c9744cd8f1`; source hashes and
  patch in `target/runs/T153-pre-fix.{sha256,patch}`.
- Red command: `cd control-plane && sh mvnw -B -q -pl runtime -am
  -Dtest=PeerVersionStartupTest -Dsurefire.failIfNoSpecifiedTests=false test`.
  Four cases ran: both incompatible-major cases failed because bootstrap returned
  successfully instead of throwing; compatible and transient controls passed.
  Log: `target/runs/T153-red.log`.
- Green: the same command with `-Dtest=PeerVersionStartupTest,InterPlaneWireTest`
  passed all 13 cases (no skips); log `target/runs/T153-green.log`.
  `cd data-plane && go test ./internal/protoversion ./internal/controlclient`
  passed; protoversion has no standalone tests, controlclient runs the Go version probes.
