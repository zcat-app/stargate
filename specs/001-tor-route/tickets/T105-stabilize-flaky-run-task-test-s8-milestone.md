---
id: T105
title: 'Stabilize the flaky run_task_test.sh S8 milestone-merge assertion'
status: in-progress
created: 2026-07-17
last_updated: 2026-07-17
source: found during /run T088 (verify.sh gate reliability)
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: []
parallel: false
files_budget: 4
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - docs/process/workflow.md §"The flow" step 8 (Merge)
  - docs/process/workflow.md §"Verification — the single green gate"
decision_refs: []
remediates: T096
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T105: Stabilize the flaky run_task_test.sh S8 milestone-merge assertion

## Context

`tests/contract/workflow/run_task_test.sh` Scenario 8 (the milestone
squash-merge assertion) fails **non-deterministically** — observed at roughly
1 failure per 3-4 runs during `/run T088`, with no code change to
`run-task.sh`, `lint-ticket.py`, or the test itself. S8's sandbox is hermetic
(a fresh `mktemp -d` git repo that copies in only `run-task.sh` +
`lint-ticket.py`), so the flake is in run-task's `--merge` path or the
assertion, not in caller state.

This matters beyond the test: `verify.sh` is the **single green gate**
(workflow.md §"Verification"). A gate that fails ~25-50% of the time when
nothing is wrong makes every `verify.sh` invocation a coin-flip — which in
turn makes `run-task.sh`'s pre-review re-check non-deterministic and can stall
the autopilot on a false "Build" bright-line. The integrity of this gate is
what makes Constitution Principle VII (tests-first) operationally meaningful:
a privacy-critical regression test is worthless as a guarantee if the gate
that runs it flips green/red by chance. Per the process doctrine ("repeated
false positives (≥3) → delete or narrow the check"), a flaky gate is a defect
to fix, not noise to tolerate.

## Repro

```bash
for i in $(seq 1 8); do
  bash tests/contract/workflow/run_task_test.sh >/dev/null 2>&1 \
    && echo run "$i": PASS || echo run "$i": FAIL
done
```

Observed during T088: `pass=3 fail=1` over 4 runs, then a separate `1 fail / 1
pass` pair — i.e. intermittent, not deterministic.

The failing assertion (the SECOND S8 assert; the first — `--merge exits 0` —
passes):

```
assert 'git log --oneline | grep -q "milestone squash"' "S8: main has the milestone squash commit"
```

i.e. `run_task T307 --merge` exits 0 but main ends up with NO "milestone
squash" commit.

## Suspect root cause (to confirm at grounding)

`scripts/run-task.sh:623-636` — the `--merge` path:

- Line 622-625: `NCOMMITS="$(git rev-list --count main..$FEATURE_BRANCH)"`; if
  `0`, prints "Nothing to merge" and `exit 0` **without** creating any squash
  commit. If `git rev-list --count` ever undercounts (e.g. a checkout/branch
  timing issue in the sandbox where the feature branch tip is not yet visible
  relative to main), run-task exits 0 with no commit → S8's grep fails while
  the "exits 0" assert passes.
- Line 629-632: `git merge --squash` succeeds, then `git commit` runs. If the
  commit does not land (e.g. nothing staged, or a hooks-induced non-zero that
  run-task does not check — the `git commit` return value is not captured),
  run-task still falls through to the "merge complete" echo and exits 0 with no
  commit on main.

Either path produces exactly the observed symptom (exit 0, no "milestone
squash" commit). Grounding should trace a failing run (`bash -x
scripts/run-task.sh T307 --merge` inside a reproducing sandbox) to confirm
which branch fires.

## Acceptance

1. S8 passes **deterministically**: the repro loop above (8 runs) shows
   `pass=8 fail=0`, repeated across at least 3 independent invocations.
2. The fix is in `run-task.sh` (capture the `git commit` return value and fail
   non-zero if the milestone commit does not land; and/or make the
   `NCOMMITS==0` early-exit impossible in the merge scenario) OR in the test
   (narrow S8 to assert what is actually deterministic) — the chosen fix is
   justified against the process doctrine (narrow/delete on false positives),
   not papered over with a retry loop.
3. `scripts/verify.sh` is GREEN, and a run of `for i in $(seq 1 8); do
   scripts/verify.sh; done` (or the gate subset) shows no intermittent FAIL.

## Out-of-scope

- Rewriting the milestone-merge mechanism itself (T096's design stays); this
  ticket only makes the gate deterministic.
- The `run_task_test.sh` flakiness is the ONLY known intermittent gate; other
  scenarios (S1-S7, S9-S11) appear stable and are not in scope.

## Notes

Found while running `/run T088` — T088's own gates are all green; this test
flips independent of T088's diff (the sandbox copies only untouched
`run-task.sh` + `lint-ticket.py`). Filed separately so T088 stays surgical.

### Grounding finding (falsifies the §"Suspect root cause")

Empirical repro under concurrent host load (40+ parallel full-harness
instances: ~6-10% fail rate; sequential/single-invoked: 0%) showed the
ticket's stated hypothesis — "run-task exits 0 with no milestone commit" — is
**false**. Across 50+ reproducing sandboxes, `refs/heads/main` ALWAYS carried
the squash commit and run-task's exit code was always 0; the FIRST S8 assert
(`--merge exits 0`) always passed; only the SECOND (the grep) ever failed, and
it passed when re-run on the same sandbox moments later. So the run-task
`--merge` logic is correct. The flake is a transient **read-side** failure of
S8's own post-merge git subprocess under heavy concurrent load, not a write
bug. Fixes applied:
  1. `scripts/run-task.sh` `--merge` path hardened to fail-closed (capture the
     `git commit` rc; confirm `main` advanced; exit non-zero + stay on main
     with staged changes if the milestone commit does not land). This was a
     real latent fail-open even though it was not the flake's cause, and is
     authorised by §Acceptance #2.
  2. `tests/contract/workflow/run_task_test.sh` S8 narrowed to assert the
     deterministic property (main's TIP is the milestone commit) via
     `git show -s --format=%s main` — a single read-only op against one
     object, no mutating `git checkout`, minimal subprocess surface. This
     replaces the prior two-step `git checkout -q main` + `git log --oneline |
     grep` (more subprocesses + a branch switch). Deterministic under normal
     verify.sh operation (3×8 sequential repro: pass=8/8 each; 2×40 parallel:
     80/80). A residual transient git-infra failure under *artificial extreme*
     parallelism is not eliminable without a retry band-aid, which §Acceptance
     #2 and the process doctrine forbid.

