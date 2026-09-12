---
id: "T144"
title: "Preserve privacy-test ordering evidence honestly"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T096", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: false
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T096"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T144: Preserve privacy-test ordering evidence honestly

## Context

Existing finding 20260727-013 and early ticket evidence gaps: declared dependency ordering exists, but retained in-ticket RED evidence is not established.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Document the audited historical gaps without inventing approvals or ordering, including T001-T009 and the distinct T094 decomposition record.
2. Define durable per-ticket test baseline, failing property/probe result, and implementation snapshot evidence for future privacy-critical work; do not equate shared commit membership with a violation.
3. Add workflow fixtures that reject missing/mismatched required evidence while supporting declared tests_first/test_for dependencies and legitimate test-only tickets.
4. Run workflow tests and scripts/verify.sh; preserve Constitution VII and independent review requirements.

## Out-of-scope

Rewriting past commits, fabricating historical RED runs, or blanket file-name pairing prohibitions.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
