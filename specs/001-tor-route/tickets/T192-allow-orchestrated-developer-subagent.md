---
id: T192
title: 'Allow a per-ticket developer subagent under an orchestrator'
status: done
created: 2026-09-29
last_updated: 2026-09-29
source: "maintainer decision 2026-09-29 session: orchestrated run of plan steps 9–10 with one developer subagent per ticket"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: false
files_budget: 6   # ticket + .claude/skills/run/SKILL.md + .opencode/skills/run/SKILL.md
                  # + docs/process/workflow.md + generated STATUS.md
                  # + docs/process/analysis.md:126 ("developer (main conversation)"),
                  # an orphan this ticket makes stale (user-authorized, no deferral)
privacy_critical: false   # process text only; no runtime, reviewer or gate change
tests_first: []
test_for: []
constitution_refs:
  - "VIII: Adversarial Review at Milestones"   # review gates unchanged by delegation
complexity: low
risk: medium
round_cap: 2
spec_refs:
  - docs/process/workflow.md
  - .claude/skills/run/SKILL.md
decision_refs:
  - "Maintainer decision 2026-09-29: an orchestrating root may delegate one ticket's whole /run lifecycle to one fresh subagent"
reviews: { round: 1, date: 2026-09-29, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T192: Allow a per-ticket developer subagent under an orchestrator

## Context

The procedure currently forbids a developer subagent: `.claude/skills/run/SKILL.md:52`
("The root is the developer; no developer subagent"), its OpenCode mirror
`.opencode/skills/run/SKILL.md:50`, and `docs/process/workflow.md:125` ("IS the
developer (never a developer-subagent)"). The maintainer wants a long run of
tickets driven by an orchestrating root that keeps its context small and
delegates each ticket to one fresh subagent. `scripts/run-task.sh:42` and
`workflow.md:97` say the *script* never spawns a developer; that remains true
and is out of scope.

This is the first ticket of the orchestrated run and is delivered under the
current rule: the root is its developer.

## Analysis

- Must hold: after the change, exactly one developer owns a ticket at a time.
  Either the root, or one fresh subagent the root dispatches, and that
  subagent runs every driver phase (START through the done follow-up) itself.
  The orchestrator never edits the ticket's files, stages paths, transcribes
  verdicts, invokes review CLIs or bypasses gates. Delegated developers never
  spawn another developer. Reviewer dispatch, reviewer rules and gates are
  unchanged.
- Gated: independent review via `scripts/review-task.sh`; consistency grep that
  no stale "no developer subagent" statement remains in skill/workflow text.
- Residue: whether a subagent can invoke the Skill tool or spawn read-only
  reviewers is an environment property; the text must not claim it.

## Acceptance

1. Amend `.claude/skills/run/SKILL.md` §Tool bindings and `docs/process/workflow.md`
   step 2 to permit the orchestrated shape above, stating the orchestrator's
   limits and that a delegated developer never spawns another developer.
2. Keep `.opencode/skills/run/SKILL.md` consistent with the Claude skill (same
   rule, tool-appropriate wording).
3. No change to `scripts/run-task.sh`, `scripts/review-task.sh`, reviewer agent
   definitions, round caps or verdict handling.
4. Consistency probe recorded in Notes: `grep -rn "no developer subagent\|never a
   developer-subagent"` over `.claude/`, `.opencode/`, `docs/` returns nothing stale,
   and `scripts/verify.sh` is green.

## Out-of-scope

Changing who may dispatch reviewers; parallel ticket execution; autopilot.md rewrite.

## Notes

- Consistency probe (Acceptance 4), run on the candidate before review:
  `grep -rn "no developer subagent\|never a developer-subagent" .claude/ .opencode/ docs/`
  returns no matches (exit 1). `scripts/run-task.sh:42` ("The script NEVER spawns a
  developer-subagent") is about the driver script and stays true; it is out of scope.
- Orphan fixed in this ticket: `docs/process/analysis.md` named the developer as
  "main conversation"; it now names the ticket's developer (root or its one delegated
  subagent). `files_budget` raised 5 → 6 for it (user-authorized, no deferral).
- The `.claude/skills/run/SKILL.md` edit was applied by the maintainer via a
  prepared script after the agent's edit was denied as self-modification.
- `scripts/verify.sh` green is recorded by the driver's pre-review gate.
