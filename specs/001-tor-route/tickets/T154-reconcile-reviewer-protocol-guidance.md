---
id: "T154"
title: "Reconcile stale reviewer authentication guidance"
status: "deferred"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T133"]
parallel: false
files_budget: 8
privacy_critical: false
complexity: "low"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T133"
tests_first: []
deferred_reason: "decomposed"
replaced_by: "T156"
deferred_on: "T156"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T154: Reconcile stale reviewer authentication guidance

## Context

Audit found reviewer checklist text forbidding DP auth and prescribing 0600 sockets although current versioned contracts require bearer auth and role-specific 0660 sockets.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Read current constitution and wire/SOCKS contracts; replace obsolete concrete claims with accurate role-scoped requirements and authoritative references.
2. Preserve fresh-context, no-delegation and reviewer-owned verdict rules; do not change approval semantics or runtime guarantees.
3. Run scripts/sync-agents.sh and verify canonical/mirror agreement plus scripts/verify.sh; cite Constitution II/V/VII in the guidance.
4. Add a narrow source-consistency check only if it verifies real contract drift rather than matching incidental wording.

## Out-of-scope

Provider/model changes, runtime code, loosening review scope, or changing privacy guarantees.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
