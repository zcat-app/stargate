---
id: "T153"
title: "Surface incompatible peer versions at CP startup"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
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

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

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
