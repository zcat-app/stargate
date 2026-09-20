---
id: "T166"
title: "Remove shrink escalation and preserve review evidence"
status: done
created: "2026-09-20"
last_updated: 2026-09-20
source: "maintainer request during T138 review"
phase: "Foundation audit remediation"
story: "-"
blocked_by: []
parallel: false
files_budget: 12
privacy_critical: false
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/review-loop.md", "docs/process/workflow.md"]
decision_refs: []
reviews: { round: 2, date: 2026-09-20, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T166: Remove shrink escalation and preserve review evidence

## Context

T138's second review was interrupted by a mechanical diff-growth rule even
though the previous reviewers had requested the added material. The driver
deleted the imported reviewer files during that escalation. The maintainer
explicitly requested removal of the shrink rule and preservation of review
files on every escalation.

## Analysis

- **Must hold:** round cap and reviewer `ESCALATE` still stop work; neither
  escalation path deletes the reviewer files or review-set manifest.
- **Gated:** a hermetic driver test covers growth during rework and both
  escalation paths, plus `scripts/verify.sh`.
- **Residue:** T138 still needs a new review after its design findings are
  addressed; this process ticket does not approve T138.

## Acceptance

1. Remove the diff-growth or must-shrink rule from the driver, canonical
   reviewer role and its generated mirror, reviewer prompt, review-loop policy
   and active workflow documentation. Preserve the round cap.
2. On both a reviewer `ESCALATE` and a `REWORK` at the cap, retain the complete
   reviewer files and manifest on disk for inspection. Invalid or changed
   snapshots still cannot approve a commit.
3. Add hermetic regression checks for growth during rework and preservation of
   both reviewer reports and the manifest on each escalation path; run
   `scripts/verify.sh` green before review.

## Out-of-scope

Changing approval validation, reviewer identities, the round cap, or T138's
observer design.
