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
3. **Gate green.** Run `scripts/verify.sh`. It must be GREEN (exit 0) before
   review. A green run is valid only while the tree is unchanged — do not edit
   after gating and before committing without re-running.
4. **Review.** Invoke the `stargate-codereview` agent (fresh context, blind to
   your rationale). It returns `APPROVE | REWORK | ESCALATE`.
5. **Act on the verdict:**
   - `APPROVE` → commit the task (one task = one focused commit; squash-merge
     folds a feature's task-commits into `main` per CONTRIBUTING PR norms).
   - `REWORK` → address the named items, then go to step 3. Subject to the
     round cap below.
   - `ESCALATE` → stop; surface the menu (below) to the human. Do not proceed.

## Round cap and must-shrink

- **Round cap = 2** rework rounds (3 for a task explicitly marked high
  complexity/risk). Hitting the cap fires the escalation menu — it is not a
  licence to keep going.
- **Must-shrink:** each rework round should converge. If a fix-only round grows
  on files touched **and** lines added **and** lines removed *simultaneously*,
  that is scope creep wearing a fix's clothes — flag it (`non-converging`)
  unless a prior review item explicitly mandated the growth.

## Escalation menu (the human decides; the agent never picks)

When the round cap is hit or the reviewer returns `ESCALATE`, present exactly
these five options and **stop**. For an unattended routine, this is the moment
to open a PR / notification for human review rather than to push further.

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
   - **amend-constitution** — heavyweight governance: a PR modifying
     `.specify/memory/constitution.md`, a **7-day** public comment period, and
     for Principles **I, III, or V** (the privacy-critical ones) a **passing
     `stargate-redteam` run** against the proposed change. Never a casual
     side-exit. See the constitution's Governance section.

## Bypass

Pure-documentation changes (a `docs:`-prefixed commit per CONTRIBUTING PR
norms) skip this loop — there is no acceptance criterion or privacy surface for
it to bite on. Keep the prefix grep-able so tooling can still tell change
classes apart.

## Process doctrine: deletion over addition

This loop is process surface, and process surface grows easily and shrinks only
deliberately. When a check in this loop produces repeated false positives
(≥3), the default response is to **delete or narrow the check**, not to add
rules around it. A one-off failure is evidence to fix the task; a *pattern* is
evidence the check is wrong. Don't patch a one-off into a permanent rule.
