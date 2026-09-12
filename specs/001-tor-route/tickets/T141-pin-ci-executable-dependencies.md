---
id: "T141"
title: "Pin CI Actions and agent installation dependencies"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T096", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
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

# T141: Pin CI Actions and agent installation dependencies

## Context

Existing findings 20260727-005/006: executable Actions use mutable tags and agent installers use floating releases in credential-bearing jobs.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Inventory external Actions and agent CLI installation inputs; pin exact reviewed versions/commit identities and verify downloaded executable artifacts.
2. Add negative fixtures rejecting mutable external uses references, floating curl installers and unversioned package installations; exempt local uses references explicitly.
3. Keep job permissions minimal and ensure installer changes do not broaden credential exposure; obtain upstream identities through primary sources during grounding.
4. Run workflow contract checks and scripts/verify.sh; document manual pin-update procedure under Constitution IV/VI.

## Out-of-scope

Publishing workflow execution, provider changes, secrets rotation, or claiming pinning alone confines the executing agent (T142).

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
