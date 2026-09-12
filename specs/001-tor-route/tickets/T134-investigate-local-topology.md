---
id: "T134"
title: "Investigate a constitution-compliant local topology"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T125", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T125"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T134: Investigate a constitution-compliant local topology

## Context

B1/M1: T125 wildcard binding and no-masquerade reasoning do not establish the constitutional deployment boundary. Investigate alternatives before choosing implementation.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Reproduce strict native wildcard refusal versus the STARGATE_IN_CONTAINER exception using disposable state; preserve the audit evidence.
2. Compare at least two concrete alternatives under the T156 constitution, including loopback ingress, DP/CP/Tor authority, destination DNS and cold-start operation.
3. For candidate prototypes outside production, assert loopback reachability, non-loopback refusal and packet-level DNS/TCP/UDP isolation with positive capture controls; report environment assumptions and failed alternatives.
4. Deliver a reviewable design recommendation and explicitly list any remaining authoritative conflict. Do not implement a disputed design or amend the constitution under this ticket.

### Required planning refinement


Completion requires a reviewed recommendation and concrete implementation follow-up tickets with
`remediates`, spec/contract references, a tests-first regression, and measurable closure criteria.
Before marking this investigation done, add every required follow-up to T155 `blocked_by`
and to affected consumers (including deployment, CONNECT tests, or event consumers as applicable).
A recommendation alone does not close the finding. Unresolved authoritative conflicts remain
blocking; this ticket cannot authorize a constitution amendment or accept the risk.

## Out-of-scope

Production behavior changes, constitution amendments, or accepting T125 residual risk.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
