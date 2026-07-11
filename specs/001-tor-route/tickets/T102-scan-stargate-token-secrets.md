---
id: T102
title: 'Scan for Stargate bearer-token secrets'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#A3
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T076]
parallel: true
files_budget: 5
privacy_critical: true
constitution_refs:
  - "III: Privacy-preserving by construction"
  - "VI: Open and auditable"
complexity: low
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §FR-017
decision_refs: []
remediates: T006
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T102: Scan for Stargate bearer-token secrets

## Context

The fallback pre-commit scanner does not recognize a 32-hex Stargate token,
and optional local hooks have no CI/history mirror.

## Analysis

- **Must hold** — contextual token/bearer/test-token assignments with 32 hex
  characters fail closed without flagging unrelated hashes or documented
  placeholders.
- **Gated** — fixture tests cover true positives, false positives, allowed
  examples, staged files, and full-history CI scanning.
- **Residue** — entropy-only detection is intentionally avoided because its
  false-positive rate would undermine the gate.

## Acceptance

1. Add a contextual fallback rule for 32-hex values adjacent to `token`,
   `bearer`, or `STARGATE_TEST_TOKEN`, with a narrow documented-example
   allowlist.
2. Add regression fixtures proving real secrets fail and ordinary digests,
   fingerprints, and approved test placeholders pass.
3. Run gitleaks (or the pinned equivalent) over commits/history in CI at push
   and release cadence; local fallback remains useful on fresh machines.
4. Scanner output identifies path/rule without echoing the secret value.
5. The scanner tests and `scripts/verify.sh` pass.

## Out-of-scope

Revoking any real credential; no real secret may be added as a fixture.
