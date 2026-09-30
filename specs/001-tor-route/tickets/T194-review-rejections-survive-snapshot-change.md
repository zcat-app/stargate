---
id: T194
title: 'Keep review rejections and red evidence when the candidate changes'
status: done
created: 2026-09-30
last_updated: 2026-09-30
source: "maintainer decision 2026-09-30 session: driver defect observed live on T193 (round-1 REWORK deleted unarchived); scope extended to the single-red evidence overwrite seen on the same ticket"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T193"]
parallel: false
files_budget: 9   # ticket + generated STATUS.md + evidence/T194-tests-first.json
                  # + scripts/run-task.sh + scripts/review-task.sh (import-time history, if the fix lives there)
                  # + scripts/test-first-evidence.py
                  # + tests/contract/workflow/run_task_test.sh + tests/contract/workflow/review_task_test.sh
                  # + docs/process/workflow.md
privacy_critical: true   # verification/review-gate integrity (same class as T139)
tests_first: []
test_for: []
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"   # verdicts bind a candidate; changes invalidate approvals, not rejections
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - scripts/run-task.sh
  - scripts/review-task.sh
  - scripts/test-first-evidence.py
  - docs/process/workflow.md
  - .specify/memory/review-loop.md
decision_refs:
  - "Maintainer decision 2026-09-30: fix the driver so rejections stick and approvals expire, keep an append-only verdict history, make --reset archive first, and never silently overwrite a red evidence record; run after T193 and before T184"
reviews: { round: 2, date: 2026-09-30, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T194: Keep review rejections and red evidence when the candidate changes

## Context

Observed on T193 (2026-09-30), confirmed in code by the orchestrator:

1. **Unprocessed verdicts are erased on a snapshot change.** In the
   `in-review` phase, `scripts/run-task.sh` compares the reviewed snapshot with
   the current one and, when they differ, calls `invalidate_reviews`
   (`run-task.sh` ~line 419, reached from ~line 779). That deletes the review
   set, snapshot and per-reviewer verdict files without archiving them,
   without counting the round and without acting on the verdict. A developer
   who changes the candidate after a REWORK or ESCALATE, before re-invoking the
   driver, therefore erases the rejection and gets a fresh review in the same
   round: the round cap and the escalation stop are silently bypassed. T193's
   round-1 Astra REWORK was lost this way and cannot be recovered (Codex runs
   `--ephemeral`; the launcher removes its temporary directory).
2. **`--reset` erases the same state** (`run-task.sh` ~line 186) and zeroes the
   round without any record.
3. **A round ≥ 2 handoff silently omits a missing prior verdict** (~line 725):
   reviewers are not told the prior round's findings are unavailable.
4. **Red evidence is overwritten silently.** `scripts/test-first-evidence.py red`
   replaces the single stored red record. On T193 a re-recorded red replaced
   the baseline red that demonstrated the discovery property, which later
   escalated the ticket at the round cap.

## Analysis

- Must hold: a complete, valid imported review set is consumed before
  anything else can clear it. REWORK advances the round and returns the
  ticket to in-progress; ESCALATE sets `escalated`; at the cap REWORK
  escalates as today. APPROVE / APPROVE-WITH-FIXES on a changed snapshot
  expire (Constitution VIII: changes invalidate approvals) but are still
  archived. Every imported verdict set is kept in an append-only per-ticket
  history that no driver path deletes. `--reset` archives first and records
  the reset in the ticket's `aborted_attempts`. A missing prior verdict is
  stated explicitly in the round ≥ 2 handoff. A second `red` never silently
  replaces the first: earlier red records are kept, or the overwrite is
  refused unless explicitly requested and recorded in the evidence file.
- Gated: `tests/contract/workflow/run_task_test.sh`,
  `review_task_test.sh` and an evidence-tool regression.
- Residue: host-level deletion of `target/runs/` by a same-user process is
  outside this protection; the committed scorecard remains the durable record.

## Acceptance

1. Tests first (red before green with `scripts/test-first-evidence.py`):
   a. REWORK imported, candidate changed, driver re-invoked → verdict archived,
      round incremented, status `in-progress`, no fresh handoff in the same round.
   b. ESCALATE imported, candidate changed → archived, status `escalated`.
   c. APPROVE imported, candidate changed → archived, approval expired, no commit.
   d. `--reset` → prior verdicts preserved in history; reset recorded in
      `aborted_attempts`.
   e. Round ≥ 2 with the prior archive missing → the handoff states it explicitly.
   f. A second `red` run keeps the first red record (or refuses without an
      explicit, recorded override).
2. Implement the behaviour in `scripts/run-task.sh` (and `review-task.sh` if
   import-time history lives there) and `scripts/test-first-evidence.py`.
3. `docs/process/workflow.md` states the rule in plain words: a changed
   candidate invalidates approvals; it never erases a REWORK, an ESCALATE or a
   red record.
4. `scripts/verify.sh` is green.

## Out-of-scope

Reviewer matrix, reviewer prompts, round-cap values, the escalation menu, and
recovering T193's lost round-1 verdict.
