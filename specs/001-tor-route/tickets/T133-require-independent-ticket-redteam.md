---
id: T133
title: 'Require independent redteam before privacy-critical ticket commits'
status: in-review
created: 2026-09-12
last_updated: 2026-09-12
source: maintainer-approved review-stage correction
phase: Polish
story: '-'
blocked_by: []
parallel: false
files_budget: 14
privacy_critical: false
complexity: medium
risk: high
round_cap: 2
spec_refs:
  - docs/process/workflow.md §Adversarial passes (redteam + perf)
  - docs/process/ticket-template.md privacy_critical
constitution_refs:
  - 'VII: Tests-first for privacy-critical and contract code'
  - 'VIII: Adversarial review at milestones'
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T133: Require independent redteam before privacy-critical ticket commits

## Context

The maintainer approved one review stage with two independent reviewers for
privacy-critical tickets. The driver currently commits on codereview approval
alone, contrary to the pre-commit redteam requirement in the workflow and ticket
schema. Restore that gate without removing baseline security from codereview or
the milestone-wide redteam sweep. This changes development tooling, not the
proxy's runtime privacy surfaces.

## Acceptance

1. Hermetic workflow tests demonstrate that a privacy-critical ticket with only
   codereview approval emits REDTEAM and cannot commit or become done.
2. The root caller dispatches a fresh independent redteam reviewer, which writes
   its own verdict. Both approvals are required; non-privacy tickets retain the
   single-review path. Reviewers cannot delegate.
3. Redteam REWORK uses the existing shared round cap; ESCALATE stops. Missing,
   malformed, legacy, or mismatched redteam verdicts cannot authorize a commit.
4. Redteam approval identifies the reviewed snapshot. Changes to HEAD, the
   tracked diff, staged content, or codereview verdict invalidate that approval;
   changes during the final verification also prevent commit.
5. Successful privacy-critical commits record both reviewer trailers. The root
   driver owns commits and status transitions and never pushes automatically.
6. Reconcile workflow, review loop, reviewer instructions, and run skill with
   this contract; regenerate OpenCode mirrors. Keep milestone review intact.
7. The workflow harness and scripts/verify.sh pass.

## Out-of-scope

Runtime code, feature contracts, Constitution amendments, provider/model changes,
and general instruction-file cleanup. The existing workflow harness S6/S7 may
be replaced because their former assertions explicitly required bypassing the
now-restored gate; other existing behavior must remain covered. No automated
acceptance of security findings or new override mechanism.
