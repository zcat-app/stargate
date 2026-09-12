---
id: "T138"
title: "Define an enforced Tor observation boundary"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T094a", "T139", "T134", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T094a"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T138: Define an enforced Tor observation boundary

## Context

Existing finding 20260727-001 was independently rediscovered: CP holds the full Tor cookie, so its Java command allowlist cannot constrain a compromised CP.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Map the CP credential and reachable Tor commands against Constitution II/III and the threat model, distinguishing disclosed residue from enforced restrictions.
2. Compare removal of direct CP control credentials with an independently enforced narrow observer; specify sanitized allowed outputs and failure behavior.
3. Define negative acceptance probes from CP production context for stream observation and configuration commands, plus a positive sanitized-health probe. Do not issue dangerous commands against an operator stack.
4. Deliver a design for review and an explicit unresolved-decision list before production changes; no risk acceptance or constitution amendment is authorized here.

### Required planning refinement


Completion requires a reviewed recommendation and concrete implementation follow-up tickets with
`remediates`, spec/contract references, a tests-first regression, and measurable closure criteria.
Before marking this investigation done, add every required follow-up to T155 `blocked_by`
and to affected consumers (including deployment, CONNECT tests, or event consumers as applicable).
A recommendation alone does not close the finding. Unresolved authoritative conflicts remain
blocking; this ticket cannot authorize a constitution amendment or accept the risk.

## Out-of-scope

Implementing a new sidecar or relaxing privacy guarantees before the design is settled.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
