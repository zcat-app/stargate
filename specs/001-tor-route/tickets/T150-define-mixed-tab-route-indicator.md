---
id: "T150"
title: "Define truthful mixed-tab route indicator semantics"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T057", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T057"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T150: Define truthful mixed-tab route indicator semantics

## Context

Browser Minor m1: the unqualified Route: Tor label reflects the latest subresource; the spec does not define main-document or mixed-tab scope.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Specify the indicator scope explicitly against Principle V and the existing per-tab acceptance before changing UI behavior.
2. Add direct-main/onion-resource and onion-main/direct-resource cases; require labels matching the selected scope rather than an arbitrary last-request overclaim.
3. Preserve unknown-tab and unreadable-state handling and document that a route decision is not proof of successful tunnel establishment.
4. Run router/popup tests, scripts/verify.sh and both required reviews.

## Out-of-scope

Changing actual routing, or presenting this audit observation as proven direct traffic leakage.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
