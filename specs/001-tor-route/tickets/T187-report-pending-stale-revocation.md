---
id: T187
title: 'Report pending or stale revocation; count only after DP ack'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 2 M3, survived falsification, narrowed to observability)"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 7
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "II: Plane Separation"   # report pending delivery, not success
  - "III: Privacy-Preserving by Construction"   # finite current status, no event history
complexity: high
risk: medium
round_cap: 3
spec_refs:
  - specs/001-tor-route/data-model.md
  - THREAT-MODEL.md
decision_refs:
  - "data-model §1.8 / T159: keeping DP state on a stale reply is required and stays"
  - "T178: this silence already hid a real initial token-load failure"
remediates: "T159"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-005-revocation-status-invisible"]
clarity_check: {}
---

# T187: Report pending or stale revocation; count only after DP acknowledgement

## Context

`TokenLoader` writes the `revoked`/`enrolled` aggregates inside the store
transaction, before `ReloadTokens` is delivered. With CP logging off, stdout and
stderr sent to /dev/null and no status surface (`scripts/stargate` has only
`init`), an operator cannot see that a revocation is pending (DP unreachable) or
was refused as stale (e.g. after CP state loss while the DP holds a newer
generation). The only persisted trace counts the revocation as done. The
constitution's failure table says "Report pending delivery, not success"; the
threat model §5.15 says the operator must not be told it succeeded before the DP
acknowledges. The stale-reply mechanism itself is specified (data-model §1.8)
and is not changed here.

## Analysis

- Must hold: the operator can read a finite, current delivery state
  (e.g. PENDING, ACKNOWLEDGED(generation), STALE_CONFLICT) with no history,
  timestamps or labels; `revoked`/`enrolled` aggregates count only acknowledged
  application.
- Gated: CP tests for unreachable, stale and acknowledged DP replies.
- Residue: the stale-conflict recovery remains an explicit operator procedure.

## Acceptance

1. Add a finite current-state status readable through local administration
   (e.g. `scripts/stargate status` over an authenticated local channel, or a
   static exit/refusal), within Constitution III's lifecycle-enum allowance.
2. Move aggregate counting after exact DP acknowledgement.
3. Tests first: unreachable DP → PENDING and revoked stays 0; stale reply →
   STALE_CONFLICT and revoked stays 0; acknowledgement → ACKNOWLEDGED(gen) and
   revoked counts after the hour closes. Record red before green.
4. Document the stale-conflict recovery in the quickstart/operator procedure and
   reconcile data-model/threat-model text.

## Out-of-scope

Changing stale-generation handling; terminating established pipes on revocation.
