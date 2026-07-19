---
id: T103
title: 'Add a scoped shell quality gate'
status: done
created: 2026-07-11
last_updated: 2026-07-18
source: review/sol-review.md#A4
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T088, T096]
parallel: false
files_budget: 10
privacy_critical: false
constitution_refs:
  - "VI: Open and auditable"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - CONTRIBUTING.md §"Code style"
  - docs/process/workflow.md §"The flow"
decision_refs: []
reviews: { round: 1, date: 2026-07-18, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T103: Add a scoped shell quality gate

## Context

Installer and workflow scripts are release-critical, but the green gate does
not run `bash -n` or ShellCheck. Current findings include ambiguous control
flow, fragile file selection, unchecked `cd`, and missing shell context.

## Acceptance

1. Add `bash -n` for all Bash entrypoints to `scripts/verify.sh`.
2. Add a pinned/scoped ShellCheck gate with narrow inline rationales only for
   intentional parser/array constructs; absence of ShellCheck is accounted as
   SKIP locally and required in CI.
3. Fix the current findings in installer/workflow scripts without unrelated
   refactors or formatting churn.
4. Add a regression check that newly added shell files are discovered
   automatically.
5. `scripts/verify.sh` reports the shell gates explicitly and passes.

## Out-of-scope

Changing installer behavior beyond T088 or workflow semantics beyond T096.
