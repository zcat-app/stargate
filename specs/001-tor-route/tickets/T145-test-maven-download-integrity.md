---
id: "T145"
title: "Test Maven wrapper checksum enforcement"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T098", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: false
complexity: "low"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T098"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T145: Test Maven wrapper checksum enforcement

## Context

Existing finding 20260727-009 core mechanism is fixed by f2ac787; checksum presence and corrupt-download negative coverage still lack an owner.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Use a controlled local fixture to exercise the actual only-script wrapper with valid bytes and a matching distributionSha256Sum.
2. Demonstrate changed bytes and missing required checksum cannot execute an unverified distribution; add the necessary presence gate without inert wrapperSha256Sum settings.
3. Preserve the checksum mechanism and record the original missing-checksum defect as fixed separately from this follow-up.
4. Run wrapper/gate fixtures and scripts/verify.sh; document Constitution IV/VI integrity scope.

## Out-of-scope

Maven upgrades, changing JVM reproducibility scope, or contacting a production artifact service in negative fixtures.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
