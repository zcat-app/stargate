# Autopilot — the unattended outer driver

This is the **outer loop** that drives `review-loop.md` across many tasks
without a human at the keyboard, while staying observable and stoppable from a
phone. `review-loop.md` is the *inner* per-task loop (ground → implement →
gate → review → act); this doc says how to run that loop autonomously, task
after task, and exactly when to stop and ask a human.

The constitution remains authoritative. Where this doc conflicts with
`constitution.md` or `review-loop.md`, **they win** — autopilot never invents a
licence to bend a rule that the inner loop would have caught.

## Preconditions (verified once, at start of a run)

- Running inside a persistent session that survives logoff — `tmux`/`screen` on
  the VPS, or a `systemd` unit. (Remote Control is a *viewport*, not life
  support; if the process dies, so does the phone link.)
- Remote Control paired to the phone, so `PushNotification` actually delivers
  and the operator can type a steer/stop. If it is not connected, pushes are
  no-ops — the run still proceeds, just blind.
- `scripts/verify.sh` is GREEN on the starting tree. A run never begins on red.

## One iteration = one task

For the next unchecked `[ ]` task in `specs/NNN-*/tasks.md`, in dependency order
(respect `[P]`, story order, and any "MUST be authored and failing before"
gate):

1. **STOP-CHECK first.** If the most recent operator message asks to stop /
   pause / halt, do **not** start a new task. Push a one-line summary
   (`■ Autopilot stopped at <ID> — N tasks done this run`) and exit the loop
   *without* re-arming. Cooperative stop lands on a task boundary, so the tree
   is never left mid-task or uncommitted.
2. **Run the inner loop** (`review-loop.md` steps 1–5) for this task: ground on
   the full task text + cited spec scenarios + named contract; implement
   tests-first for every privacy-critical category (Principle VII, no
   exception); gate `scripts/verify.sh` green; invoke `stargate-codereview`
   (blind); act on `APPROVE | REWORK | ESCALATE`.
3. **On APPROVE:** mark the task `[X]` in `tasks.md`, commit it as one focused
   commit (one task = one commit; **never** bundle a failing test with its
   implementation — the failing-test signal is part of the audit trail), then
   **push telemetry** (see below).
4. **On ESCALATE or round-cap:** run the **Hurdle Protocol** (below) and stop.
5. **Advance** to the next task. Within a single turn, keep going task after
   task — do not yield to the user between green tasks. Yield (and re-arm, see
   Pacing) only at an escalation, a stop, an exhausted task list, or a
   deliberate budget-reflection pause.

## Hurdle Protocol — the ultrathink-defend gate

A "hurdle" is any point where the path forward is not mechanically obvious: a
review `ESCALATE`, a hit round-cap, a spec ⇄ constitution tension, a
privacy-critical design fork, or a step that has failed twice. At a hurdle:

1. **Rethink the options.** Enumerate the real candidate solutions (≥2). Do not
   anchor on the first.
2. **Defend the best one by trying to *falsify* it** (think hard / ultrathink).
   Name what would make the chosen option wrong, and check *that* against the
   constitution, the spec, the threat model, and the contracts. Re-reading your
   own rationale is confirmation, not verification (`ai-working-doctrine`).
3. **Decide:**
   - **Proceed autonomously** only if *all* hold: the action is reversible; one
     option is clearly best after the falsification pass; and it touches **no**
     privacy-critical surface in a contested way (DNS, routing, headers, auth,
     sidecar/contract — Principles I/III/V). Record the one-line *why* inline;
     if it accepts a security/privacy finding, append it to
     `SECURITY-DECISIONS.md` (Principle VIII — no AI exception).
   - **Escalate to the human** otherwise — irreversible/destructive, a genuine
     tie after falsification, a privacy-critical fork, or a spec/constitution
     conflict.

### Escalation format (what the human receives)

The push is the **headline** (≤200 chars, the OS truncates): plain problem +
the recommended option + a call to reply. Example:

> `🚧 T013 blocked: bind-check rejects ::1 in CI netns. Rec: accept loopback by parsed-IP, not iface. Reply to decide.`

The **full escalation** is printed into the session (read on the phone via
Remote Control) in exactly this shape:

1. **Problem** — one or two plain sentences. No jargon dump.
2. **Options considered** — each candidate, one line.
3. **Recommendation** — the chosen option, and **why it beats each alternative**
   (one line per rival). This is the part the operator is owed.
4. **Menu** — the applicable subset of `review-loop.md`'s five options
   (refine / override / decompose / defer / amend). The human picks; autopilot
   never picks for an `amend-constitution`, ever.
5. **The exact question** to answer.

Then **stop and wait**. Do not re-arm the loop across an open escalation.

## Telemetry — honest, per task

After each APPROVE, send one `PushNotification` (`status: "proactive"`):

> `✓ <ID> <one-clause what> — <N>/<total> done · <R> rework rounds · verify green`

Budget honesty (this is a hard rule): the live hour/week usage limit is **not
machine-readable** to an agent — there is no tool, env var, or API that exposes
"% remaining." Do **not** fabricate a token or dollar figure in a push. Report
only verifiable proxies — task progress, rework rounds, files/tests touched —
and rely on the operator glancing the **`/usage` status-bar indicator** (enable
via `/config`) on the phone for the authoritative burn. If a self-tracked rough
estimate is ever added, it must be labelled an estimate, never the real number.

Telemetry is informational only — it **never** halts the loop. The only things
that stop autopilot are: operator stop, an escalation, a red `verify.sh`, or an
exhausted task list.

## Stop / start from the phone

- **Stop / pause:** type `stop` (or `pause autopilot`) into the Remote Control
  session. Caught at the next STOP-CHECK — cooperative, one-task granularity.
  Hard stop is `Esc` while attached to the local `tmux` session.
- **Start / resume:** type the start command (the `/loop` invocation, or
  `resume autopilot`) into the session — works from the phone in an idle
  Remote Control session, or locally before you detach and log off.

## Pacing

Drive continuously *within* a turn (many tasks per turn — no artificial idle
between green tasks). Only when the turn ends with work still pending and no
escalation/stop, **re-arm** via `ScheduleWakeup` so the run is genuinely
unattended rather than waiting on a human keystroke. The work is local, so the
re-arm delay is just the loop's heartbeat (the runtime floor is 60s); the
authoritative `verify.sh` gate, not the clock, is what guards correctness.

## Guardrails (non-negotiable)

- Halt the run on a red `verify.sh` that a rework round cannot turn green within
  the round cap — that is an escalation, not a retry-forever.
- **A `verify.sh` SKIP is not a PASS.** If the task's language gate is skipped
  because its toolchain is absent (e.g. Go missing → every Go test SKIPs while
  the run still reports GREEN), the task is *unverified* — do not commit it as
  approved. Escalate with the missing-toolchain as the problem.
- One task = one commit; never bundle test + impl.
- Never auto-`amend-constitution`; never auto-`override` a security/privacy
  finding without an operator decision recorded in `SECURITY-DECISIONS.md`.
- Process is surface: if an autopilot check false-positives ≥3×, narrow or
  delete it — don't pile rules on top (`ai-working-doctrine`, deletion over
  addition).
