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
- IMPLEMENT: implement acceptance, tests first where required, verify, stage
  explicit ticket paths, and signal readiness.
- REVIEW: the root spawns fresh-context `stargate-codereview` with the driver
  inputs. The reviewer writes its own verdict; never transcribe it.
- APPLY-FIXES: apply only authorized comment/doc corrections, stage those
  paths, verify and signal completion. The driver still owns commit.
- REDTEAM: the root independently spawns fresh-context `stargate-redteam`
  in ticket-review mode with exactly the driver inputs. Do not include the
  implementer's rationale or current codereview findings. The reviewer writes
  its own `.redteam.verdict`; neither reviewer may spawn subagents.
- COMMIT: stage the requested explicit paths and re-invoke the driver.
- MERGE/done: report the local commit and required review results. Do not
  create a second ticket commit. Push or milestone merge requires user
  authorization already present in the session or a separate user decision.

Continue through authorized local work and bounded rework. Stop on clarity
failure, scope-budget breach, unresolvable verification failure, review
ESCALATE or round cap. Never change acceptance, waive a security finding,
forge a verdict or bypass a gate to reach done. A stale snapshot requires
fresh reviews of the changed work; a malformed verdict must be corrected by
its reviewer. If a reviewer cannot write its file, surface that failure.

## Tool bindings

The root is the developer; no developer subagent. For unattended OpenCode,
use its configured `--auto` execution mode with the explicit reviewer deny
rules intact. Reviewers keep `task: deny`, read-only shell inspection, and
scoped verdict-file writes. Tool denials are failures to surface, not grounds
for widening permissions. Never use `git add -A`, force-push, skip tests or
hooks, or discard unrelated work. Stage only the ticket's explicit paths.
