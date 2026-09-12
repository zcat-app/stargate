---
id: "T139"
title: "Prevent required verification coverage from disappearing"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T076", "T156"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T076"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T139: Prevent required verification coverage from disappearing

## Context

Existing findings 20260727-007/008 remain: executable-bit changes skip required scripts and go.work removal can omit a required module.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Add negative fixtures clearing each named required gate executable bit; existing checks must run through an interpreter or fail, never silently SKIP.
2. Add a required-module omission fixture for each current mandatory workspace module; removing it from go.work must fail verification while additional module discovery remains supported.
3. Preserve genuine absent-substrate and opt-in cadence skip semantics; explicitly distinguish missing mandatory coverage from optional coverage.
4. Run the gate contract tests and scripts/verify.sh; document the boundary under Constitution VII.

5. T156 review identified a related evidence gap: the driver's git-diff snapshot/count omits
   unstaged new files. Derive a failing regression adding/changing an intended untracked source
   after review; approval must not remain usable. Enforce a complete source inventory/staging
   precondition, all-path budget count and reviewer snapshot invalidation (including new files).
   Test ordinary staged tracked/new files still work and unrelated ignored build artifacts do
   not masquerade as intended source. Manual manifest checks are required until this lands.

## Out-of-scope

Verification-log concurrency (T120), static analyzer rollout (T114), or changing production tests to obtain green.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
