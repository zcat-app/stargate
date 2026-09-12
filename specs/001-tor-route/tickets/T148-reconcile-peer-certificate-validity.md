---
id: "T148"
title: "Reconcile peer certificate validity policy"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T095", "T139", "T135", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T095"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T148: Reconcile peer certificate validity policy

## Context

Both Go and Java implement key-only trust while threat-model/wire-auth text promises certificate expiry enforcement; expired peers were accepted by the Go probe.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Apply the chosen T156 policy: private-key possession, current pin and valid certificate on
   full/resumed handshakes in both roles. Specify clock tolerance, renewal before expiry and
   established-channel key rotation/revocation deadlines before code; no manual monthly restart.
2. Derive failing expired/not-yet-valid/current/pin-replaced probes with synthetic identities;
   test renewal while CP unavailable and existing-channel lifecycle without losing valid routing.
3. Implement the policy on both peers, preserve T135 resumption checks, reconcile old expiry
   rationale and update the threat model with actual evidence and remaining limits.
4. Run real cross-plane contracts and verify with independent reviews. If decomposed, every
   implementation/validation child blocks T155 and the relevant reconnect consumers.

## Out-of-scope

Claiming public-certificate possession enables impersonation, or folding the definite pin-resumption fix (T135) into this decision.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
