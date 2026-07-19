---
id: T096
title: 'Enforce the canonical ticket workflow'
status: done
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#M6
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: false
files_budget: 8
privacy_critical: false
constitution_refs:
  - "VII: Tests-first for privacy-critical code"
  - "VIII: Adversarial review at milestones"
complexity: high
risk: medium
round_cap: 3
spec_refs:
  - docs/process/workflow.md §"The unit of work"
  - docs/process/workflow.md §"The flow"
  - .specify/memory/review-loop.md §"The loop"
decision_refs:
  - "review/sol-review.md#M6 (workflow driver != canonical workflow)"
tests_first: []
reviews: { round: 1, date: 2026-07-11, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T096: Enforce the canonical ticket workflow

## Context

The driver can mark work done without creating a ticket branch/commit or
enforcing the privacy red-team gate, while dependency derivation can order an
implementation before its required test. The script and canonical workflow
must describe one executable process.

## Analysis

*(Required — `complexity: high`.)*

**Branch model decision (M6 "decide").** Maintainer-chosen canonical model:
**direct commits on the feature integration branch** (`001-tor-route`); the
feature branch squash-merges to `main` at milestone close. Rationale: `main`
has no `scripts/` directory (verified at grounding), so acceptance #2's literal
"branch from `main`" is unbuildable mid-feature, and the 87 prior commits on
`001-tor-route` (`Implement 001-tor-route: T0NN …`) never used per-ticket
branches. Acceptance #2/#4/#6 are reconciled to this model: "branch" = the
feature integration branch, derived from `.specify/feature.json`; per-ticket
squash-merge becomes milestone-scope (feature branch → main). Historical
commits are grandfathered (acceptance #6).

- **Must hold**
  - Starting a pending ticket refuses ambiguous/multiple ticket filename
    matches and lands the caller on the feature integration branch (creating
    it from `main` if absent) before `status:` may flip to `in-progress`.
  - `APPROVE` is fail-closed: it cannot set `done` unless `verify.sh` is
    fresh-green, a codereview APPROVE verdict is present, a privacy-critical
    red-team CLEAN verdict is present (when `privacy_critical: true`), AND a
    focused commit with the `Reviewed-by:` trailer exists on the feature
    branch. `run-task.sh` creates that commit itself (staged paths only) so
    the invariant holds by construction, not by caller discipline.
  - Merge targets the recorded feature branch only; the milestone squash-merge
    (`--merge`) refuses a dirty tree, refuses when the branch is absent, and
    never pushes.
  - Dependency derivation no longer infers ordering from the ambiguous
    `Pairs with` prose; direction is declared explicitly via a `tests_first:`
    field on implementation tickets. The linter rejects a privacy-critical
    implementation runnable before a test it names in `tests_first:`. This
    makes Constitution Principle VII (tests-first) machine-checkable per
    ticket rather than a discipline the driver must remember.
- **Gated** — the new hermetic regression harness
  (`tests/contract/workflow/run_task_test.sh`) drives `run-task.sh` through
  pending start, approval, privacy red-team, commit, merge, dirty-tree
  refusal, and rework in a throwaway sandbox repo; `bash -n` gates syntax;
  `scripts/verify.sh` runs the harness as Gate 4.
- **Residue**
  - The harness is structural/behavioural against a sandbox; it cannot prove
    the live `stargate-redteam` subagent returns CLEAN, only that the script
    fail-closes when its verdict file is absent or carries FINDINGS. Mitigation:
    the gate is absence-sensitive (missing file ⇒ refuse), so a real redteam
    run is always requested for `privacy_critical: true` tickets.
  - Commit-message prose quality is bounded by extraction from §Context; the
    reviewer (codereview subagent) remains the judge of message adequacy.

## Acceptance

1. Add a hermetic workflow-driver regression harness covering pending start,
   approval, privacy red-team, commit, merge, dirty-tree refusal, and rework.
2. Starting a pending ticket creates/checks out the filename-derived branch
   from `main` and refuses ambiguous/multiple ticket matches.
3. `APPROVE` cannot set `done` until verify is fresh, codereview approval is
   present, privacy-critical red-team is clean, and the focused commit with
   required trailers exists.
4. Merge targets the recorded ticket branch, squash-merges only that branch,
   and never guesses from the caller's current branch or pushes.
5. Replace `Pairs with` dependency inference with explicit directed metadata;
   lint rejects privacy-critical implementation tickets runnable before their
   named test tickets.
6. Reconcile docs and existing ticket metadata with the chosen canonical
   branch model. Historical commits remain history and are not rewritten.
7. `bash -n`, the new regression harness, and `scripts/verify.sh` pass.

## Out-of-scope

Building the future unattended `/run` wrapper or pushing/creating remote PRs.
