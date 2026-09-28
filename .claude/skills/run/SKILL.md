---
name: run
description: Drive a Stargate ticket through implementation, verification and required independent reviews. Use for /run <id> or /run next.
argument-hint: "<T-NNN | next>"
---

# Run a Stargate ticket

Follow `docs/process/workflow.md` and `.specify/memory/review-loop.md`.
`scripts/run-task.sh` owns status transitions, verdict validation and local
commits. This skill dispatches its handoffs; it does not implement another
state machine. If procedure and driver disagree, report the conflict before
executing the disputed action.

## Drive

Resolve `next` with `scripts/next-task.sh --json --count 1`. Invoke
`bash scripts/run-task.sh <id>` and handle the emitted handoff. Inspect ticket
status after each invocation; do not replay a stale prompt after a transition.

- START: ground on the ticket and cited contracts, fill required analysis,
  lint the ticket, and signal readiness as the prompt directs.
- IMPLEMENT: implement acceptance, tests first where required, run the
  ticket's own tests, stage explicit ticket paths, and signal readiness. Do
  not run `scripts/verify.sh` by hand; the driver runs it once and re-runs it
  only after an executable-code change.
- REVIEW: run `scripts/review-task.sh <id>` exactly as the driver directs —
  the single gate. It launches one GLM and one Codex Astra reviewer in
  separate native sessions with candidate copies and imports their private
  verdicts manifest-last; both cover correctness and security in one pass and
  may not spawn subagents. Never invoke a review CLI directly or transcribe a
  verdict, and never include the implementer's rationale.
- APPLY-FIXES: apply only authorized comment/doc corrections, stage those
  paths and signal completion. The driver still owns verify and commit.
- COMMIT: stage the requested explicit paths and re-invoke the driver.
- MERGE/done: report the local commit and required review results. Do not
  create a second ticket commit. In the `docs: mark <id> done` follow-up,
  append every round's verdicts and dispositioned findings to
  `docs/process/reviewer-scorecard.md` (found / missed / dismissed per
  reviewer) — never in the ticket's own candidate. Push or milestone merge requires user
  authorization already present in the session or a separate user decision.

Continue through authorized local work and bounded rework. Stop on clarity
failure, scope-budget breach, unresolvable verification failure, review
ESCALATE or round cap. Never change acceptance, waive a security finding,
forge a verdict or bypass a gate to reach done. A stale snapshot requires
fresh reviews of the changed work; a malformed verdict must be corrected by
its reviewer. If a reviewer cannot write its file, surface that failure.

## Tool bindings

The root is the developer; no developer subagent. Review dispatch is only
through `review-task.sh`; missing CLI/authentication, a partial set or a stale
candidate fails closed. OpenCode deny rules are tool controls. Codex runs
without an OS sandbox and receives read-only inspection instructions; fresh
contexts and separate copies do not claim OS containment.
Never use `git add -A`, force-push, skip tests or hooks, or discard unrelated
work. Stage only the ticket's explicit paths.
