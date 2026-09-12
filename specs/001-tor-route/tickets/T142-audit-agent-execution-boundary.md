---
id: "T142"
title: "Make agent execution-boundary claims demonstrable"
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
complexity: "high"
risk: "high"
round_cap: 3
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

# T142: Make agent execution-boundary claims demonstrable

## Context

Existing finding 20260727-010: the OpenCode adapter advertises denies that do not constrain its ordinary --auto implementation agent.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Trace the effective ordinary-agent configuration separately from reviewer-specific permissions and list actual credentials/files/process capabilities.
2. Define a reviewable containment policy or explicitly remove unsupported containment claims; do not call an arbitrary nonempty deny map a sandbox.
3. Add an effective-configuration regression and synthetic prohibited-action probes that include interpreter/shell alternatives; never use real credentials.
4. Require a concrete reviewed policy before changing permissions; preserve reviewer no-delegation/fail-fast rules and run scripts/verify.sh.

### Required planning refinement


A policy decision alone does not satisfy closure: deliver the accepted implementation and
regressions, or create focused follow-up tickets and add them to T155 and affected consumers
before completing this ticket. No finding is accepted implicitly by documentation changes.

## Out-of-scope

Broadening existing permissions, weakening review gates, or exercising real exfiltration.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
