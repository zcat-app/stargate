# Review Loop — bounded rework with a human escape hatch

This is the per-task discipline that wraps `/speckit-implement`. It exists so
that **autonomous runs converge or stop** — they never thrash silently, and
they never let an AI quietly decide which rule to bend. It is the safety
harness that makes unattended implementation (a `/loop`, a scheduled routine, a
cloud agent reviewed from a phone) safe to point at this repo.

It is adopted from an external team's AI-assisted workflow and adapted to
Stargate's spec-kit + constitution. The constitution remains authoritative;
where this doc and the constitution conflict, the constitution wins.

## The loop

For one task `[ID]` from `specs/NNN-*/tasks.md`:

1. **Ground.** Read the full task text + the spec acceptance scenarios it
   cites + any named contract. Verify current state on disk. (Do not pair the
   read with the action that consumes it in one blind step.)
2. **Implement** the task. For privacy-critical categories (DNS, routing,
   headers, auth, sidecar/contract surfaces) the test is written **first** and
   failing before the implementation — Principle VII, no exception.
3. **Gate green.** `scripts/verify.sh` must be GREEN (exit 0) before review;
   `scripts/run-task.sh` runs it at the pre-review gate. A green run stays
   valid while the executable content is unchanged, so the driver re-runs it
   at APPROVE only after a code change (not for status, evidence or plain
   comment edits).
4. **Review.** Run `scripts/review-task.sh <id>` for every ticket — the
   single gate. ONE invocation, ONE pass: the fail-closed launcher concurrently
   runs two fresh contexts — one GLM and one Codex Astra — in native CLI
   sessions against separately materialized copies of one candidate. Each
   reviewer covers correctness AND adversarial security/privacy in that pass;
   there is no second phase. Every expected reviewer must approve before
   commit; none delegates. A missing/partial set, failed CLI session, or
   changed reviewed snapshot invalidates the approvals rather than falling
   back to the live checkout. The strongest verdict wins
   (ESCALATE > REWORK > APPROVE-WITH-FIXES > APPROVE) and shares the round
   cap. Milestone redteam remains an additional cumulative review.
5. **Act on the verdict:**
   - `APPROVE` → commit the task (one task = one focused commit; squash-merge
     folds a feature's task-commits into `main` per CONTRIBUTING PR norms).
   - `REWORK` → address the named items, then go to step 3. Subject to the
     round cap below.
   - `ESCALATE` → stop; surface the menu (below) to the human. Do not proceed.

## Round cap

- **Round cap = 2** rework rounds (3 for a task explicitly marked high
  complexity/risk). Hitting the cap fires the escalation menu — it is not a
  licence to keep going.
## Escalation menu (the human decides; the agent never picks)

When the round cap is hit or the reviewer returns `ESCALATE`, present exactly
these five options and **stop**. For an unattended routine, this is the moment
to open a PR / notification for human review rather than to push further.
Escalation must preserve the reviewer reports and review manifest on disk.

1. **refine** — the acceptance criteria were ambiguous or wrong-grained.
   Rewrite the task's acceptance, or run `/speckit-clarify` on the spec, then
   restart the loop. Cheapest and most common resolution.
2. **override** — the reviewer was too strict; the code is correct as-is.
   Override and record one line of *why*. If the overridden finding was a
   security/privacy one, the rationale goes in `SECURITY-DECISIONS.md`
   (append-only) — there is no AI exception to Principle VIII.
3. **decompose** — the task is too large to land in the round cap. Split it
   into smaller `[ID]` tasks in `tasks.md` and run them independently.
4. **defer** — the task is blocked on work that does not exist yet. Mark it
   deferred, file the follow-up task, move on.
5. **amend** — the spec or the constitution itself is wrong. Two weights:
   - **amend-spec** — revise `specs/NNN-*/spec.md` (and re-run `/speckit-plan`'s
     Constitution Check). Lighter.
   - **amend-constitution** — follow the active Governance section in
     `.specify/memory/constitution.md`. Pre-release session authorization and
     post-release PR/comment rules differ. Any security/privacy/governance-impacting
     amendment requires independent redteam wherever it is located. Finding acceptance
     cannot waive a principle. The maintainer decides an unresolved policy change.

## Bypass

Pure-documentation changes without changes to privacy/security guarantees
(a `docs:`-prefixed commit per CONTRIBUTING PR norms) skip this loop. Changes
to those guarantees use the privacy-critical review path. Keep the prefix
grep-able so tooling can still tell change classes apart.

## Process doctrine: deletion over addition

This loop is process surface, and process surface grows easily and shrinks only
deliberately. When a check in this loop produces repeated false positives
(≥3), the default response is to **delete or narrow the check**, not to add
rules around it. A one-off failure is evidence to fix the task; a *pattern* is
evidence the check is wrong. Don't patch a one-off into a permanent rule.
