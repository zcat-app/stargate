---
id: "T152"
title: "Replace detailed operational journals with hourly aggregates"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T036", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T036"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T152: Replace detailed operational journals with hourly aggregates

## Context

Browser/control audit C1: lower-level contracts require Unix-second lifecycle/token rows while Constitution III literally permits only hourly aggregate logs.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Apply Constitution III and foundation-boundaries.md aggregate-only policy; there is no
   administrative timestamp exception. Inventory Java/Go/sidecar diagnostic writers and stdout/
   stderr/container retention. Derive failing tests for forbidden fields and per-event records.
2. Implement fixed-category completed-hour operational aggregates, retention and no per-user
   labels/details. Current finite health/static error responses must not become historical logs.
3. Specify and test legacy-row cleanup including WAL/backup guidance; do not claim forensic host
   erasure. Update schemas/contracts/threat model in the same reviewed implementation.
4. Demonstrate all relevant writers obey the rule, run scripts/verify.sh and independent reviews.
   If the work exceeds the budget, decompose and add every child to T155 and affected consumers.

## Out-of-scope

Constitution amendments, silently rewriting the threat model to match code, or claiming a browsing log leak from administrative timestamps alone.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
