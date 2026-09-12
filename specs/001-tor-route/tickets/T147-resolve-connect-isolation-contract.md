---
id: "T147"
title: "Resolve HTTP CONNECT first-party isolation"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T043", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T043"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T147: Resolve HTTP CONNECT first-party isolation

## Context

Audit transport M2: supported HTTP CONNECT passes no upstream isolation credential, unlike the extension SOCKS path; Constitution III has no corresponding exception.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Trace authenticated CONNECT through Tor.Dial and document the existing NO_AUTH behavior and available first-party context.
2. Compare an explicitly supported first-party transport contract with refusal of an ingress that cannot meet the invariant; destination-only isolation is not equivalent.
3. Specify a same-destination/distinct-first-party regression and migration behavior before implementing any contract decision.
4. Return a reviewable recommendation under the T156 constitution; no silent privacy exception or implementation is authorized by this investigation ticket.

### Required planning refinement


Completion requires a reviewed recommendation and concrete implementation follow-up tickets with
`remediates`, spec/contract references, a tests-first regression, and measurable closure criteria.
Before marking this investigation done, add every required follow-up to T155 `blocked_by`
and to affected consumers (including deployment, CONNECT tests, or event consumers as applicable).
A recommendation alone does not close the finding. Unresolved authoritative conflicts remain
blocking; this ticket cannot authorize a constitution amendment or accept the risk.

## Out-of-scope

Constitution amendment, target-based isolation presented as first-party isolation, or modifying the working SOCKS path.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
