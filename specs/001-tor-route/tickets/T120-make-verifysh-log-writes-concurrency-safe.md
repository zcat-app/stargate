---
id: T120
title: 'Make `verify.sh` log writes concurrency-safe for parallel ticket runs'
status: done
created: 2026-09-07
last_updated: 2026-09-25
source: T063 run, 2026-09-07 — two sessions ran verify.sh concurrently (T062/T063 parallel by user instruction) and interleaved target/verify.log; 2 false socks5 FAILs burned a driver cycle
phase: "6: Polish & Cross-Cutting Concerns"
story: ''
blocked_by: ["T139", "T156"]
parallel: false
files_budget: 5   # raw-diff-path counting (T116 convention): verify.sh,
                  # run-task.sh (including doc line), regression test, ticket,
                  # and STATUS regen; fifth file approved in T120 round-2 run
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "scripts/verify.sh header (§comments): target/verify.log is 'a fixed
    path the review/commit steps can read' — the fixed-path assumption is
    what breaks under concurrency, not any gate logic"
  - "scripts/verify.sh §Opt-outs: STARGATE_VERIFY_LOG override exists
    (added for T108's nested-run probe) — the escape hatch is already
    built; only the default path is unsafe"
  - "docs/process/workflow.md §\"The flow\" steps 3–4: the driver's
    freshness check greps '^RESULT:' from the default log — must follow
    whatever log a run actually wrote"
decision_refs:
  - "T103 / T108 (driver + verify hardening precedent: mechanical
    fail-closed conventions, SKIP-sentinel exit-code discipline)"
  - "T063 run evidence, 2026-09-07: verify.log lines 41–77 show two runs'
    output interleaved (doubled '>>>' gate lines); go-workspace recorded
    go:tests/contract/socks5 pass=53 fail=2; a solo re-run immediately
    after recorded pass=55 fail=0 — the failures were collision artifacts,
    not tree state"
reviews: { round: 2, date: 2026-09-25, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T120: Make `verify.sh` log writes concurrency-safe for parallel ticket runs

## Context

Two agent sessions drove tickets in the same worktree in parallel
(T062/T063, 2026-09-07, user-directed). Both ran `scripts/verify.sh`, which
appends to the fixed `target/verify.log`. The runs overlapped: the log
interleaved both runs' output (doubled gate lines), and the combined log
recorded `go:tests/contract/socks5 pass=53 fail=2` where a solo re-run
seconds later recorded `pass=55 fail=0`. Cost: the run-task driver's
pre-review re-verify consumed the RED, one driver cycle was burned, and a
collision artifact looked exactly like a tree breakage. The hazard grows
with every parallel run — and parallel runs are now established practice.

## Analysis

Three defects, one root cause (unshared mutable log file treated as
private):

- **Interleaving** — two writers append to one file without a lock; gate
  output and the `RESULT:` line can interleave so no reader can attribute
  lines to a run.
- **False RED** — a failing line from run A is attributed to run B by any
  reader of the shared log (this is what produced the socks5 false FAIL).
- **Freshness ambiguity** — the driver's freshness check reads mtime +
  last `^RESULT:` line of the *default* path; a concurrent run's RESULT
  (GREEN or RED) can be the line the driver reads for *its* verdict.

Fix shape (pick in implementation, driven by the acceptance probes): a
`flock` on a lockfile around the whole gate run for the default-log case
(serialize, keep one canonical log — matches the "single green gate"
mental model), OR per-invocation log + atomic rename so a log is always
one run's bytes. `STARGATE_VERIFY_LOG` (T108) must keep working unchanged.
If the lock serializes: document that concurrent invocations queue rather
than corrupt (queueing is acceptable; silent corruption is not). Must
hold: the driver's freshness/RESULT read is always a *complete* run's
output; a forced-collision probe (two simultaneous invocations) yields
two well-formed logs and two correct verdicts; solo-run behavior is
byte-identical to today. Residue: queueing serializes long verify runs —
acceptable for the current 2-session ceiling; note it in the ticket that
lands the change.

Also in scope, one doc line: workflow.md §"The flow" (or run-task.sh
header comment) documents the shared-worktree parallel-run hazards
observed in the T062/T063 run — verify-log collisions (this ticket) and
the dirty-tree refusal at the `pending → in-progress` gate (recoverable
retry) — so the next parallel run is briefed.

## Acceptance

1. **Collision probe (the falsifier):** two `bash scripts/verify.sh`
   invocations started simultaneously both exit 0 on a green tree, and
   each leaves a log whose bytes are a single well-formed run — exactly
   one `RESULT:` line per invocation, no interleaved/doubled gate lines.
   For the lock design this means the shared default log is serialized;
   for the per-run design, `STARGATE_VERIFY_LOG` isolation is exercised.
2. **Driver freshness follows the write:** after a concurrent-collision
   scenario, `run-task.sh`'s freshness/RESULT read reflects the driver's
   OWN verify run (probe: force a stale foreign RESULT into the log the
   driver reads; the driver must not accept it as its own gate).
3. **No behavior change solo:** a single `bash scripts/verify.sh` run's
   log format and exit codes are unchanged (T108's skip-sentinel and
   RESULT conventions intact; T108's own contract probe still passes).
4. **Doc line landed:** the parallel-run hazards (verify-log collision +
   dirty-tree refusal) are documented where a parallel driver will read
   them (workflow.md §"The flow" or the run-task.sh header).
5. **Runnable:** `bash scripts/verify.sh` green; the collision probe
   recorded in §Notes with both runs' exit codes and RESULT lines.

## Out-of-scope

- Any gate's pass/fail logic (this ticket changes log plumbing and
  documentation only — a gate that FAILs solo must still FAIL).
- The reproducibility gate's cadence/behavior.
- Cross-worktree orchestration tooling (worktrees remain a documented
  manual option, not a driver feature).
- Reworking `regen-status.sh` or other shared-file writers (STATUS.md
  last-writer-wins regen was observed benign in the same run; revisit
  only if a collision is ever observed there).

## Notes

Hand-filed on 2026-09-07, mirroring the T116/T117/T118/T119 filing
convention. Origin: T063's round-1 review cycle was polluted by the
collision described in §Context (the 2 socks5 FAILs cost a re-verify and
a re-invocation before the solo-green re-run isolated them); the T062/T063
parallel run is also the evidence base for §Analysis's doc-line item.

Implementation probe (2026-09-25): a harness assembled from `verify.sh`'s
own setup and summary blocks ran two fixture gates against the default log.
Before the fix, both exited 0 but the shared log contained two interleaved
fixture starts and two `RESULT: GREEN` lines. After the lock, both exited 0,
each stdout had one `RESULT: GREEN`, and the shared log had one fixture start
and one `RESULT: GREEN`. The full collision probe started two simultaneous
`bash scripts/verify.sh` invocations on the same tree: exits `a=0`, `b=0`;
each stdout ended `RESULT: GREEN — nothing failed (2 gate(s) skipped).`;
the final shared log contained exactly one header and one identical RESULT.
The second invocation queued for the first full gate run. This serialization
cost is accepted for the current two-session ceiling.

Driver attribution probe (2026-09-25): after the full collision, the driver
completed its own GREEN recheck in `target/runs/T120.verify.log`. A foreign
`RESULT: RED` was then written to the shared `target/verify.log`; the
in-review handoff still reported the ticket-local GREEN. The retained
`verify_concurrency_test.sh` checks this with opposing fixture results and
also refuses to advance on an own RED despite a foreign GREEN. Run against
pre-fix sources, it failed for both the missing lock and the default-log
report reader; it passes with this implementation, including when the outer
driver exports `STARGATE_VERIFY_LOG` (the sandbox fixtures clear that inherited
override to exercise the default-log lock).
