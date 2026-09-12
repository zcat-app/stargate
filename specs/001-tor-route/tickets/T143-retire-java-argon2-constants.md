---
id: "T143"
title: "Retire obsolete Java token-verifier constants"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T011", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "low"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T011"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T143: Retire obsolete Java token-verifier constants

## Context

Existing finding 20260727-003: Go was migrated by T044, but Java constants and tests still describe the superseded Argon2id verifier as current.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Verify no active Java consumer needs the obsolete constants; remove the retired implementation and assertions without touching HMAC verification semantics.
2. Keep current HMAC/pepper contract coverage and add a scoped check for retired active symbols if needed; do not ban historical discussion text.
3. Record T011/T092 supersession honestly without rewriting approved commits or claiming historical tests-first evidence.
4. Run affected Java suites, scripts/verify.sh, and both required reviews.

## Out-of-scope

Token algorithms, parameter migration for unrelated password uses, or global comment churn.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
