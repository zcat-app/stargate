#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/workflow/run_task_test.sh — hermetic regression harness for
# the canonical ticket-workflow driver (T096 §Acceptance #1).
#
# Drives scripts/run-task.sh through the scenarios the sol-review M6 finding
# showed were unenforced: pending start (feature-branch checkout + ambiguous
# refusal + dirty-tree refusal), APPROVE fail-closed (verify re-run, red-team
# gate for privacy_critical, focused commit with Reviewed-by trailer, refuses
# done without staged paths), milestone merge (targets recorded branch, dirty
# refusal, never pushes), and rework (round-cap escalation).
#
# HERMETIC: every scenario runs in a throwaway git repo under a mktemp -d
# sandbox (one fresh repo per scenario — no cross-scenario contamination).
# The real scripts/run-task.sh + scripts/lint-ticket.py are copied in;
# verify.sh and regen-status.sh are minimal stubs (their behaviour is not
# under test here — only run-task's orchestration of them). No network, no
# Docker, no dependency on the host feature's tickets. Cleanup is trap-based.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
RUN_TASK_SRC="$REPO_ROOT/scripts/run-task.sh"
LINT_SRC="$REPO_ROOT/scripts/lint-ticket.py"
DERIVE_DEPS_SRC="$REPO_ROOT/scripts/derive-deps.sh"
[ -f "$RUN_TASK_SRC" ]     || { echo "FAIL: $RUN_TASK_SRC missing" >&2; exit 1; }
[ -f "$LINT_SRC" ]        || { echo "FAIL: $LINT_SRC missing" >&2;     exit 1; }
[ -f "$DERIVE_DEPS_SRC" ] || { echo "FAIL: $DERIVE_DEPS_SRC missing" >&2; exit 1; }

errs=()
bail() { errs+=("$*"); }
# assert <cond> <label>
assert() { local cond="$1" label="$2"; if eval "$cond"; then :; else bail "ASSERT FAIL [$label]: $cond"; fi; }

ROOT_SANDBOX="$(mktemp -d -t stargate-t096-XXXXXX)"
cleanup() { rm -rf "$ROOT_SANDBOX"; }
trap cleanup EXIT

# setup_sandbox <scenario-tag> — build a FRESH repo (clean tree) with the real
# run-task.sh + lint-ticket.py copied in and stub collaborators. The scaffold
# is committed so the working tree starts clean. Leaves CWD inside the repo.
setup_sandbox() {
  local tag="$1"
  SANDBOX="$ROOT_SANDBOX/$tag"
  mkdir -p "$SANDBOX"
  cd "$SANDBOX"
  git init -q -b main
  git config user.email "t096@test.local"
  git config user.name "T096 Test"
  git config commit.gpgsign false

  mkdir -p scripts .specify specs/001-testfeat/tickets

  cp "$RUN_TASK_SRC" scripts/run-task.sh
  cp "$LINT_SRC"    scripts/lint-ticket.py
  chmod +x scripts/run-task.sh

  # verify.sh stub: writes target/verify.log, exits 0 (green). Behaviour under
  # test is run-task's invocation of it, not its gates.
  cat > scripts/verify.sh <<'VRF'
#!/usr/bin/env bash
mkdir -p target
echo "stub-verify GREEN" >> target/verify.log
exit 0
VRF
  chmod +x scripts/verify.sh

  # regen-status.sh stub: no-op (run-task best-efforts its failure).
  cat > scripts/regen-status.sh <<'RGS'
#!/usr/bin/env bash
exit 0
RGS
  chmod +x scripts/regen-status.sh

  printf '{"feature_directory": "specs/001-testfeat"}\n' > .specify/feature.json
  # .keep so the empty tickets dir survives the commit.
  : > specs/001-testfeat/tickets/.keep
  # target/ holds run-task's transient state (sentinels, verdicts, verify.log)
  # — gitignored in production; mirror that here so sentinels don't dirty the
  # tree and trip ensure_feature_branch's clean-tree precondition.
  printf 'target/\n' > .gitignore

  git add -A
  git commit -q -m "scaffold"
}

# write_ticket <id> <title> <privacy> <status> [blocked_by-inline]
write_ticket() {
  local id="$1" title="$2" priv="$3" status="$4" bb="${5:-[]}"
  local f="specs/001-testfeat/tickets/${id}-fixture.md"
  cat > "$f" <<EOF
---
id: $id
title: '$title'
status: $status
created: 2026-07-11
last_updated: 2026-07-11
source: tasks.md#$id
phase: "1: Setup"
story: '-'
blocked_by: $bb
parallel: false
files_budget: 8
privacy_critical: $priv
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# $id: $title

## Context

Fixture ticket for the T096 workflow harness. Exercises run-task.sh phase
transitions in a hermetic sandbox.

## Acceptance

- The workflow driver transitions this fixture correctly.

## Out-of-scope

Nothing — this is a test fixture, not real work.
EOF
  printf '%s\n' "$f"
}

# commit_working_tree <msg> — stage everything and commit (clean-up helper).
commit_all() { git add -A; git commit -q -m "$1"; }

# fm_field <file> <key> — extract a YAML frontmatter scalar (best-effort).
fm_field() { grep -m1 "^$2:" "$1" | sed -E "s/^$2:[[:space:]]*//" | sed -E "s/[[:space:]]*#.*\$//"; }

# run_task <args...> — capture stdout+stderr + exit code.
run_task() { rt_out="$(bash scripts/run-task.sh "$@" 2>&1)"; rt_rc=$?; }

# ===========================================================================
# Scenario 1: pending START — feature-branch creation from main
# ===========================================================================
setup_sandbox s1
write_ticket T300 "start creates feature branch" false pending >/dev/null
commit_all "add T300 ticket"
mkdir -p target/runs; touch target/runs/T300.grounded
assert '[ ! -e .git/refs/heads/001-testfeat ]' "S1 pre: feature branch absent"
assert '[ "$(git rev-parse --abbrev-ref HEAD)" = main ]' "S1 pre: on main"
run_task T300
assert '[ "$rt_rc" -eq 0 ]' "S1: start exits 0 (got $rt_rc)"
assert '[ "$(git rev-parse --abbrev-ref HEAD)" = 001-testfeat ]' "S1: caller landed on feature branch"
assert '[ "$(fm_field specs/001-testfeat/tickets/T300-fixture.md status)" = in-progress ]' "S1: status -> in-progress"
assert 'git show-ref --verify --quiet refs/heads/001-testfeat' "S1: feature branch ref exists"

# ===========================================================================
# Scenario 2: pending START — ambiguous ticket match refused
# ===========================================================================
setup_sandbox s2
write_ticket T301 "ambiguous a" false pending >/dev/null
mv specs/001-testfeat/tickets/T301-fixture.md specs/001-testfeat/tickets/T301-first.md
write_ticket T301 "ambiguous b" false pending >/dev/null
mv specs/001-testfeat/tickets/T301-fixture.md specs/001-testfeat/tickets/T301-second.md
commit_all "add two T301 tickets"
run_task T301
assert '[ "$rt_rc" -eq 2 ]' "S2: ambiguous match exits 2 (got $rt_rc)"
echo "$rt_out" | grep -qi "ambiguous" || bail "S2: stderr should mention 'ambiguous'"

# ===========================================================================
# Scenario 3: pending START — dirty-tree refusal
# ===========================================================================
setup_sandbox s3
write_ticket T302 "dirty tree refused at start" false pending >/dev/null
commit_all "add T302 ticket"
mkdir -p target/runs; touch target/runs/T302.grounded
printf 'uncommitted\n' > dirty.txt   # makes the tree dirty AFTER the clean baseline
run_task T302
assert '[ "$rt_rc" -ne 0 ]' "S3: dirty tree at start exits non-zero (got $rt_rc)"
echo "$rt_out" | grep -qi "dirty" || bail "S3: stderr should mention dirty"
assert '[ "$(fm_field specs/001-testfeat/tickets/T302-fixture.md status)" = pending ]' "S3: status stays pending"

# ===========================================================================
# Scenario 4: APPROVE — focused commit with Reviewed-by trailer
# (non-privacy ticket: redteam gate skipped)
# ===========================================================================
setup_sandbox s4
write_ticket T303 "approve commits on feature branch" false in-review >/dev/null
commit_all "add T303 ticket"
git checkout -q -b 001-testfeat main
printf 'real impl\n' > src.txt
git add src.txt specs/001-testfeat/tickets/T303-fixture.md
mkdir -p target/runs
printf 'VERDICT: APPROVE\nround 1\n' > target/runs/T303.verdict
PRE_COMMIT="$(git rev-parse HEAD)"
run_task T303
assert '[ "$rt_rc" -eq 0 ]' "S4: APPROVE exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T303-fixture.md status)" = done ]' "S4: status -> done"
assert '[ "$(git rev-parse HEAD)" != "$PRE_COMMIT" ]' "S4: a new commit was created"
assert 'git log -1 --format=%B HEAD | grep -q "Reviewed-by: stargate-codereview (VERDICT: APPROVE"' \
  "S4: tip commit carries the Reviewed-by trailer"
assert 'git log -1 --format=%s HEAD | grep -qE "^Implement 001-testfeat: T303 "' \
  "S4: subject is 'Implement <feature>: T303 ...'"

# ===========================================================================
# Scenario 5: APPROVE — refuses done with nothing staged (commit invariant)
# ===========================================================================
setup_sandbox s5
write_ticket T304 "approve needs staged paths" false in-review >/dev/null
commit_all "add T304 ticket"
git checkout -q -b 001-testfeat main
mkdir -p target/runs
printf 'VERDICT: APPROVE\nround 1\n' > target/runs/T304.verdict
run_task T304
assert '[ "$rt_rc" -eq 0 ]' "S5: no-staged-paths emits COMMIT handoff, exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T304-fixture.md status)" = in-review ]' \
  "S5: status stays in-review (done refused without commit)"
echo "$rt_out" | grep -qi "COMMIT" || bail "S5: handoff should mention COMMIT"
assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S5: no commit created on feature branch"

# ===========================================================================
# Scenario 6: APPROVE — privacy_critical red-team gate (missing -> refuse)
# ===========================================================================
setup_sandbox s6
write_ticket T305 "privacy needs redteam" true in-review >/dev/null
commit_all "add T305 ticket"
git checkout -q -b 001-testfeat main
printf 'impl\n' > p.txt; git add p.txt specs/001-testfeat/tickets/T305-fixture.md
mkdir -p target/runs
printf 'VERDICT: APPROVE\nround 1\n' > target/runs/T305.verdict
run_task T305
assert '[ "$rt_rc" -eq 0 ]' "S6: missing redteam emits REDTEAM handoff, exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = in-review ]' \
  "S6: status stays in-review (done refused without redteam)"
echo "$rt_out" | grep -qi "redteam\|REDTEAM" || bail "S6: handoff should mention REDTEAM"
# Supply CLEAN -> proceeds to commit + done.
printf 'VERDICT: CLEAN\n' > target/runs/T305.redteam
run_task T305
assert '[ "$rt_rc" -eq 0 ]' "S6b: CLEAN redteam proceeds, exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = done ]' \
  "S6b: status -> done with CLEAN redteam"

# ===========================================================================
# Scenario 7: APPROVE — privacy_critical redteam FINDINGS -> hard stop
# ===========================================================================
setup_sandbox s7
write_ticket T306 "privacy redteam findings" true in-review >/dev/null
commit_all "add T306 ticket"
git checkout -q -b 001-testfeat main
printf 'impl\n' > p.txt; git add p.txt specs/001-testfeat/tickets/T306-fixture.md
mkdir -p target/runs
printf 'VERDICT: APPROVE\nround 1\n' > target/runs/T306.verdict
printf 'VERDICT: FINDINGS\nBlocker: DNS leak in path X\n' > target/runs/T306.redteam
run_task T306
assert '[ "$rt_rc" -ne 0 ]' "S7: FINDINGS redteam exits non-zero (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T306-fixture.md status)" = in-review ]' \
  "S7: status stays in-review on FINDINGS"

# ===========================================================================
# Scenario 8: MERGE — milestone squash-merge of feature branch into main
# ===========================================================================
setup_sandbox s8
write_ticket T307 "milestone merge" false done >/dev/null
commit_all "add T307 ticket"
git checkout -q -b 001-testfeat main
printf 'work\n' > w.txt; git add w.txt; git commit -q -m "Implement 001-testfeat: T307 work"
run_task T307 --merge
assert '[ "$rt_rc" -eq 0 ]' "S8: milestone merge exits 0 (got $rt_rc)"
git checkout -q main
assert 'git log --oneline | grep -q "milestone squash"' "S8: main has the milestone squash commit"
assert 'git show-ref --verify --quiet refs/heads/001-testfeat' "S8: feature branch retained"

# ===========================================================================
# Scenario 9: MERGE — dirty-tree refusal
# ===========================================================================
setup_sandbox s9
write_ticket T308 "merge dirty refusal" false done >/dev/null
commit_all "add T308 ticket"
git checkout -q -b 001-testfeat main
printf 'work\n' > w.txt; git add w.txt; git commit -q -m "Implement 001-testfeat: T308 work"
printf 'uncommitted\n' > extra.txt   # dirty the tree
run_task T308 --merge
assert '[ "$rt_rc" -ne 0 ]' "S9: dirty merge exits non-zero (got $rt_rc)"
echo "$rt_out" | grep -qi "dirty" || bail "S9: stderr should mention dirty"

# ===========================================================================
# Scenario 10: REWORK at round cap -> escalated
# (round_cap default 2; start the fixture AT round 2 in-review so a single
#  REWORK verdict hits the cap without needing a re-verify cycle.)
# ===========================================================================
setup_sandbox s10
write_ticket T309 "rework cap" false in-review >/dev/null
commit_all "add T309 ticket"
git checkout -q -b 001-testfeat main
mkdir -p target/runs
echo 2 > target/runs/T309.round                      # already at cap
printf 'VERDICT: REWORK\nfix the thing\n' > target/runs/T309.verdict
run_task T309
assert '[ "$rt_rc" -ne 0 ]' "S10: REWORK at cap exits non-zero (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T309-fixture.md status)" = escalated ]' \
  "S10: status escalated at round cap"
# Negative: a REWORK at round 1 (below cap) returns to in-progress (round bump).
setup_sandbox s10b
write_ticket T319 "rework r1 returns" false in-review >/dev/null
commit_all "add T319 ticket"
git checkout -q -b 001-testfeat main
mkdir -p target/runs
echo 1 > target/runs/T319.round
printf 'VERDICT: REWORK\nfix it\n' > target/runs/T319.verdict
run_task T319
assert '[ "$rt_rc" -eq 0 ]' "S10b: REWORK r1 exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T319-fixture.md status)" = in-progress ]' \
  "S10b: status -> in-progress after REWORK r1"
assert '[ "$(cat target/runs/T319.round)" = 2 ]' "S10b: round bumped to 2"

# ===========================================================================
# Scenario 11: lint — rejects privacy-critical impl runnable before its test
# (exercises scripts/lint-ticket.py directly; T096 §Acceptance #5)
# ===========================================================================
setup_sandbox s11
cat > specs/001-testfeat/tickets/T310-impl.md <<'EOF'
---
id: T310
title: 'impl runnable before its test'
status: pending
source: tasks.md#T310
phase: "1: Setup"
story: '-'
blocked_by: []
parallel: false
files_budget: 8
privacy_critical: true
tests_first: [T309b]
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs: []
reviews: {}
---

# T310

## Context

lint fixture: names a test in tests_first but omits it from blocked_by.
EOF
lint_out="$(python3 scripts/lint-ticket.py specs/001-testfeat/tickets/T310-impl.md 2>&1)"; lint_rc=$?
assert '[ "$lint_rc" -ne 0 ]' "S11: lint rejects privacy impl runnable before test (got $lint_rc)"
echo "$lint_out" | grep -q "TESTS-FIRST-VIOLATION" || bail "S11: lint should emit TESTS-FIRST-VIOLATION"
sed -i 's/^blocked_by: \[\]/blocked_by: [T309b]/' specs/001-testfeat/tickets/T310-impl.md
lint_out="$(python3 scripts/lint-ticket.py specs/001-testfeat/tickets/T310-impl.md 2>&1)"; lint_rc=$?
assert '[ "$lint_rc" -eq 0 ]' "S11b: lint passes once test is in blocked_by (got $lint_rc)"

# ===========================================================================
# Scenario 12: derive-deps — 'Pairs with' is no longer an inference rule
# (regression guard against re-introducing the M6 inversion source)
# ===========================================================================
assert '! grep -Eq "re.compile.*Pairs with" "$DERIVE_DEPS_SRC"' \
  "S12: no 'Pairs with' regex remains in derive-deps.sh"
assert 'grep -q "Pairs with" "$DERIVE_DEPS_SRC" && grep -q "REMOVED" "$DERIVE_DEPS_SRC"' \
  "S12: derive-deps documents 'Pairs with' removal"

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T096 run-task harness (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T096 workflow-driver regression harness (12 scenarios) — start, approve, redteam, commit, merge, dirty refusal, rework, lint"
exit 0
