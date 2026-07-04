---
name: run
description: Drive a stargate ticket through the full workflow unattended — start → implement → verify.sh → codereview → commit, stopping only on bright-line conditions (clarity FAIL / files_budget exceeded / verify-not-green / review round cap / redteam FINDINGS). Use when the user invokes `/run <T-NNN>` or `/run next`.
argument-hint: "<T-NNN | next>"
---

# /run — stargate autopilot

This skill is a **thin wrapper around `scripts/run-task.sh`**. The procedure
it drives lives in `docs/process/workflow.md`; the loop driver is the shell
script; this skill is the agent-CLI binding that feeds run-task's emitted
handoff prompts back to itself, advancing the ticket through phases without
per-phase human confirmation on the green path.

If this skill ever conflicts with `docs/process/workflow.md` or with
`scripts/run-task.sh`'s actual behavior, **those win** — flag the drift and
stop. The skill body is binding only on *how the agent reads and acts on
run-task.sh's prompts*, nothing else.

## Invocation

`/run <T-NNN>` — drive a named ticket.
`/run next` — pick the lowest-id runnable ticket via `scripts/next-task.sh`
and drive that.

## What autopilot IS

- It removes the per-phase human rubber-stamp that `run-task.sh`'s
  sentinel-file mechanism asks for (`touch target/runs/<id>.grounded` etc.).
  Where `run-task.sh` emits a prompt and waits for the caller to signal,
  `/run` does the prompted work and signals automatically.
- It is safe because the **bright-line stops** (below) are absolute, the
  `stargate-codereview` subagent is fresh-context and independent, and
  `run-task.sh` never pushes — even the auto squash-merge is local and
  revertible (`git revert <sha>`).

## What autopilot is NOT

- It does NOT remove a gate or skip a phase. The developer (this skill's
  agent, acting as the developer) still writes the code at the implement
  phase. There is no developer-subagent.
- It does NOT push. Push stays manual — it's the outward, irreversible step.
- It does NOT self-override a bright-line stop. On any stop below, surface
  to the user and exit cleanly.

## Bright-line stops — hand back to the user, never push past

These mirror `scripts/run-task.sh`'s exit-1 conditions and
`docs/process/workflow.md` §"Autonomous runs":

1. **Clarity FAIL** — `scripts/lint-ticket.py` returns non-zero, or the
   ticket's `privacy_critical: true` AND §Analysis is unfilled.
2. **Scope** — `files_budget` would be exceeded by the implementation you're
   about to write. Stop BEFORE writing, not after.
3. **Build** — `scripts/verify.sh` not green after addressing a rework round.
4. **Review** — REWORK round cap hit (default 2; 3 if `round_cap: 3`), or
   `ESCALATE` verdict.
5. **Redteam** — `FINDINGS` from `stargate-redteam` (only fires when
   `privacy_critical: true`; not yet wired into run-task.sh's main loop, so
   /run performs the redteam gate explicitly — see step 5 below).
6. **Must-shrink** — a rework round grew files+added+removed simultaneously
   without a citable mandate.

When in doubt, **stop and surface**.

## Procedure

The skill re-invokes `scripts/run-task.sh <id>` in a loop. Each invocation
either (a) advances the state machine deterministically and exits, or (b)
emits a handoff prompt to `target/runs/<id>.prompt` and exits. The skill
reads the prompt, does the prompted work, signals the sentinel, and
re-invokes. Pseudocode:

```
1. Resolve ticket id (next → scripts/next-task.sh --json --count 1; else arg)
2. Loop:
   a. Bash: scripts/run-task.sh <id>
   b. Read target/runs/<id>.prompt if it exists; otherwise exit loop (the
      state machine reached a terminal state: done, escalated, or refused).
   c. Read the prompt's "kind" from its first line:
      - START     → ground: Read ticket + cited anchors + on-disk verify;
                    if privacy_critical, fill §Analysis (property map per
                    docs/process/analysis.md); run scripts/lint-ticket.py;
                    if FAIL → STOP (bright-line 1). Else signal grounded:
                    Bash("touch target/runs/<id>.grounded")
      - IMPLEMENT → write the diff per §Acceptance (tests first if
                    privacy_critical per Principle VII); when verify.sh is
                    green locally, signal verified:
                    Bash("touch target/runs/<id>.verified")
                    If files_budget about to be exceeded → STOP (bright-line 2).
      - REVIEW    → spawn stargate-codereview (Task tool, subagent) with the
                    diff + ticket + verify log + (round ≥2) prior diffstat;
                    write the verdict block to target/runs/<id>.verdict
                    (Bash: heredoc-redirect or Write tool).
                    If verdict APPROVE → loop continues (run-task transitions
                    to done).
                    If verdict REWORK and round ≤ cap → loop continues
                    (run-task bumps round and transitions to in-progress).
                    If verdict REWORK at cap, or ESCALATE → STOP (bright-line 4).
      - MERGE     → STOP (do not auto-merge in /run v1; surface to user with
                    the exact `scripts/run-task.sh <id> --merge` command).
                    Rationale: merging locally is reversible, but the user's
                    explicit "drive this ticket" grant is per-ticket, not
                    per-ticket-AND-per-merge. They confirm the merge.
   d. Continue the loop.
3. Privacy-critical redteam gate (only fires when ticket.privacy_critical is
   true AND the ticket has reached status: done):
   a. Spawn stargate-redteam (Task tool, subagent) against the cumulative diff.
   b. CLEAN → continue (proceed to merge handoff).
   c. FINDINGS → STOP (bright-line 5). Surface the per-severity summary and
      the recommended `scripts/run-task.sh <id> --reset` + manual review path.
4. Final report: print the phase-by-phase summary (clarity verdict · files/
   +/- · review verdict+round · redteam verdict if fired · final status).
   End with: "Pushed nothing — push is your call."
```

## Cross-cutting rules this skill must obey

- **Never push.** `run-task.sh --merge` is local-only; push is the user's call.
- **No developer-subagent.** This skill's agent IS the developer (per the
  main-conversation-is-the-developer rule from workflow.md). Subagents this
  skill spawns are limited to: `stargate-codereview` at REVIEW, and
  `stargate-redteam` at the privacy-critical gate.
- **No destructive shortcuts** (`--no-verify`, `-DskipTests`, `git reset --hard`
  to discard work, force-push) to make obstacles disappear. Escalate instead.
- **Never `git add -A` for a ticket commit.** Stage explicit paths only —
  the ticket's changed files plus the ticket file. (`scripts/run-task.sh`
  does the staging for squash-merge; the rule binds you when you're staging
  implementation changes before signaling `verified`.)
- **Status transitions only via `scripts/run-task.sh`.** Do not flip
  `status:` by hand — that skips the gates the driver enforces.
- **If this skill's procedure conflicts with `docs/process/workflow.md`,
  `docs/process/reviewer-prompt.md`, or the actual behavior of
  `scripts/run-task.sh`, those win.** Stop and surface the conflict.
