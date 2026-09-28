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
REVIEW_MATRIX_SRC="$REPO_ROOT/scripts/review-matrix.json"
EVIDENCE_SRC="$REPO_ROOT/scripts/test-first-evidence.py"
[ -f "$RUN_TASK_SRC" ]     || { echo "FAIL: $RUN_TASK_SRC missing" >&2; exit 1; }
[ -f "$LINT_SRC" ]        || { echo "FAIL: $LINT_SRC missing" >&2;     exit 1; }
[ -f "$DERIVE_DEPS_SRC" ] || { echo "FAIL: $DERIVE_DEPS_SRC missing" >&2; exit 1; }
[ -f "$REVIEW_MATRIX_SRC" ] || { echo "FAIL: $REVIEW_MATRIX_SRC missing" >&2; exit 1; }

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
  cp "$REVIEW_MATRIX_SRC" scripts/review-matrix.json
  if [ -f "$EVIDENCE_SRC" ]; then cp "$EVIDENCE_SRC" scripts/test-first-evidence.py; fi
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
test_for: $([ "$priv" = true ] && echo '[T999]' || echo '[]')
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

# T139: fixture reviewers return the identity of the handoff they inspected.
review_manifest() {
  local id="$1" snapshot="$2" round="$3"; shift 3
  local manifest="target/runs/$id.review-set" file
  {
    printf 'SNAPSHOT: %s\nROUND: %s\nGATE: review\n' "$snapshot" "$round"
    for file in "$@"; do sha256sum "target/runs/$file" | sed 's#  target/runs/#  #'; done
  } > "$manifest"
}

gate_verdict() {
  local id="$1" kind="$2" details="${3:-}"
  local snapshot round
  if [ ! -s "target/runs/$id.review-snapshot" ]; then
    run_task "$id" >/dev/null
  fi
  snapshot="$(cat "target/runs/$id.review-snapshot")"
  round="$(cat "target/runs/$id.round")"
  printf 'VERDICT: %s\nREVIEWER: glm\nTOOL: opencode\nMODEL: zai-coding-plan/glm-5.3-flash\nEFFORT: xhigh\nSNAPSHOT: %s\nROUND: %s\nSUMMARY: fixture gate\nFINDINGS: fixture\n%s\n' \
    "$kind" "$snapshot" "$round" "$details" > "target/runs/$id.review-glm.verdict"
  printf 'VERDICT: %s\nREVIEWER: astra\nTOOL: codex\nMODEL: gpt-6-astra\nEFFORT: high\nSNAPSHOT: %s\nROUND: %s\nSUMMARY: fixture gate\nFINDINGS: fixture\n%s\n' \
    "$kind" "$snapshot" "$round" "$details" > "target/runs/$id.review-astra.verdict"
  review_manifest "$id" "$snapshot" "$round" \
    "$id.review-glm.verdict" "$id.review-astra.verdict"
}

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
assert '[ -s target/runs/T300.start-sha ]' "S1: review base SHA recorded at start"

# ===========================================================================
# Scenario 1b: in-review REVIEW handoff — mechanical report + verdict self-write
# ===========================================================================
setup_sandbox s1b
write_ticket T321 "mechanical report handoff" false in-review >/dev/null
commit_all "add T321 ticket"
git checkout -q -b 001-testfeat main
printf 'x\n' > a.txt; printf 'y\n' > b.txt
git add a.txt b.txt specs/001-testfeat/tickets/T321-fixture.md
mkdir -p target/runs
run_task T321   # no verdict file -> emits REVIEW handoff
assert '[ "$rt_rc" -eq 0 ]' "S1b: REVIEW handoff exits 0 (got $rt_rc)"
echo "$rt_out" | grep -qi "MECHANICAL REPORT" || bail "S1b: handoff should contain the mechanical report"
echo "$rt_out" | grep -q "files touched: 2 of files_budget=" || bail "S1b: files-vs-budget line missing or miscounted"
echo "$rt_out" | grep -qi "private verdict\|own verdict" || bail "S1b: handoff should say each reviewer writes its own verdict"
echo "$rt_out" | grep -q "out-of-scope" || bail "S1b: out-of-scope block missing"
snapshot="$(cat target/runs/T321.review-snapshot)"
printf 'VERDICT: APPROVE\nSNAPSHOT: %s\nROUND: 1\n' "$snapshot" > target/runs/T321.review-glm.verdict
before="$(git rev-parse HEAD)"
run_task T321
assert '[ "$rt_rc" -ne 0 ]' "S1b: a partial verdict set without the manifest cannot advance"
assert '[ "$(git rev-parse HEAD)" = "$before" ]' "S1b: incomplete review set cannot commit"

# A complete-looking set is still rejected when one reviewer identity is
# wrong, even if the canonical reviewer approved.
setup_sandbox s1c
write_ticket T322 "review identity binding" false in-review >/dev/null
commit_all "add T322 ticket"
git checkout -q -b 001-testfeat main
printf 'candidate\n' > candidate.txt
git add candidate.txt
mkdir -p target/runs
run_task T322
gate_verdict T322 APPROVE
sed -i 's/^REVIEWER: astra$/REVIEWER: glm/' target/runs/T322.review-astra.verdict
review_manifest T322 "$(cat target/runs/T322.review-snapshot)" 1 \
  T322.review-glm.verdict T322.review-astra.verdict
before="$(git rev-parse HEAD)"
run_task T322
assert '[ "$rt_rc" -ne 0 ]' "S1c: peer-mismatched review identity is rejected"
assert '[ "$(git rev-parse HEAD)" = "$before" ]' "S1c: mismatched review cannot commit"

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
# Scenario 4: APPROVE — focused commit with Reviewed-by trailers
# (the single gate reviews every ticket the same way; no second phase)
# ===========================================================================
setup_sandbox s4
write_ticket T303 "approve commits on feature branch" false in-review >/dev/null
commit_all "add T303 ticket"
git checkout -q -b 001-testfeat main
printf 'real impl\n' > src.txt
git add src.txt specs/001-testfeat/tickets/T303-fixture.md
mkdir -p target/runs
run_task T303  # T139: bind approval to the emitted review candidate.
gate_verdict T303 APPROVE
PRE_COMMIT="$(git rev-parse HEAD)"
run_task T303
assert '[ "$rt_rc" -eq 0 ]' "S4: APPROVE exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T303-fixture.md status)" = done ]' "S4: status -> done"
assert '[ "$(git rev-parse HEAD)" != "$PRE_COMMIT" ]' "S4: a new commit was created"
assert 'git log -1 --format=%B HEAD | grep -q "Reviewed-by: stargate-review (glm; opencode; model zai-coding-plan/glm-5.3-flash; effort xhigh; VERDICT: APPROVE"' \
  "S4: tip commit carries the GLM Reviewed-by trailer"
assert 'git log -1 --format=%B HEAD | grep -q "Reviewed-by: stargate-review (astra; codex; model gpt-6-astra; effort high; VERDICT: APPROVE"' \
  "S4: tip commit carries the Astra Reviewed-by trailer"
assert 'git log -1 --format=%s HEAD | grep -qE "^Implement 001-testfeat: T303 "' \
  "S4: subject is 'Implement <feature>: T303 ...'"

# Mixed APPROVE/AWF sets preserve each reviewer's actual decision in commit
# evidence rather than stamping the aggregate result onto every identity.
setup_sandbox s4b
write_ticket T323 "individual review trailers" false in-review >/dev/null
commit_all "add T323 ticket"
git checkout -q -b 001-testfeat main
printf 'real impl\n' > src.txt
git add src.txt
mkdir -p target/runs
run_task T323
gate_verdict T323 APPROVE
sed -i 's/^VERDICT: APPROVE$/VERDICT: APPROVE-WITH-FIXES/' target/runs/T323.review-astra.verdict
review_manifest T323 "$(cat target/runs/T323.review-snapshot)" 1 \
  T323.review-glm.verdict T323.review-astra.verdict
run_task T323
assert '[ "$rt_rc" -eq 0 ]' "S4b: mixed set emits APPLY-FIXES"
touch target/runs/T323.awf-applied
run_task T323
assert '[ "$rt_rc" -eq 0 ]' "S4b: mixed set commits after sentinel"
assert 'git log -1 --format=%B HEAD | grep -q "Reviewed-by: stargate-review (glm; opencode; model zai-coding-plan/glm-5.3-flash; effort xhigh; VERDICT: APPROVE;"' \
  "S4b: GLM trailer preserves its APPROVE"
assert 'git log -1 --format=%B HEAD | grep -q "Reviewed-by: stargate-review (astra; codex; model gpt-6-astra; effort high; VERDICT: APPROVE-WITH-FIXES;"' \
  "S4b: Astra trailer preserves its APPROVE-WITH-FIXES"

# ===========================================================================
# Scenario 5: APPROVE — refuses done with nothing staged (commit invariant)
# ===========================================================================
setup_sandbox s5
write_ticket T304 "approve needs staged paths" false in-review >/dev/null
commit_all "add T304 ticket"
git checkout -q -b 001-testfeat main
mkdir -p target/runs
run_task T304
gate_verdict T304 APPROVE
run_task T304
assert '[ "$rt_rc" -eq 0 ]' "S5: no-staged-paths emits COMMIT handoff, exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T304-fixture.md status)" = in-review ]' \
  "S5: status stays in-review (done refused without commit)"
echo "$rt_out" | grep -qi "COMMIT" || bail "S5: handoff should mention COMMIT"
assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S5: no commit created on feature branch"

# ===========================================================================
# Scenario 6/7 (T142): the single gate reviews privacy-critical tickets in
# the same ONE pass as ordinary tickets; malformed, partial, stale or
# tampered inputs never commit.
privacy_fixture() {
  setup_sandbox "$1"
  write_ticket T305 "single gate" true in-review >/dev/null
  commit_all "add ticket"
  git checkout -q -b 001-testfeat main
  printf 'first\n' > p.txt
  git add p.txt
  mkdir -p target/runs
  run_task T305
}
bad_index=0
for bad in 'APPROVE-BOGUS' $'APPROVE\nVERDICT: REWORK'; do
  bad_index=$((bad_index + 1))
  privacy_fixture "s6-invalid-verdict-$bad_index"
  gate_verdict T305 "$bad"
  run_task T305
  assert '[ "$rt_rc" -ne 0 ]' "S6: malformed gate verdict cannot advance"
  assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S6: malformed gate verdict cannot commit"
done
privacy_fixture s6
run_task T305
assert '[ "$rt_rc" -eq 0 ]' "S6: emits handoff"
assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = in-review ]' "S6: waits for the gate"
assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S6: no premature commit"
echo "$rt_out" | grep -q '(REVIEW,' || bail "S6: missing REVIEW handoff"
echo "$rt_out" | grep -qi 'review-task.sh T305$' || bail "S6: handoff must name the single-gate launcher"
gate_verdict T305 APPROVE
run_task T305
assert '[ "$rt_rc" -eq 0 ]' "S6: gate approval commits a privacy-critical ticket"
assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = done ]' "S6: done after one gate pass"
assert 'git log -1 --format=%B | grep -q "Reviewed-by: stargate-review (glm; opencode; model zai-coding-plan/glm-5.3-flash; effort xhigh; VERDICT: APPROVE"' "S6: GLM trailer"
assert 'git log -1 --format=%B | grep -q "Reviewed-by: stargate-review (astra; codex; model gpt-6-astra; effort high; VERDICT: APPROVE"' "S6: Astra trailer"

privacy_fixture s7
printf 'VERDICT: CLEAN\n' > target/runs/T305.review-glm.verdict
run_task T305
assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S7: legacy output cannot approve"
for bad in 'VERDICT: APPROVE-BOGUS' $'VERDICT: APPROVE\nVERDICT: REWORK' 'VERDICT: APPROVE'; do
  run_task T305 >/dev/null
  gate_verdict T305 APPROVE
  printf '%s\nSNAPSHOT: wrong\nROUND: 1\n' "$bad" > target/runs/T305.review-glm.verdict
  review_manifest T305 "$(cat target/runs/T305.review-snapshot)" 1 \
    T305.review-glm.verdict T305.review-astra.verdict
  run_task T305
  assert '[ "$rt_rc" -ne 0 ]' "S7: invalid verdict rejected"
  assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S7: invalid output cannot commit"
done
for field in SUMMARY FINDINGS; do
  for malformed in missing duplicate; do
    run_task T305 >/dev/null
    gate_verdict T305 APPROVE
    if [ "$malformed" = missing ]; then
      sed -i "/^$field:/d" target/runs/T305.review-glm.verdict
    else
      printf '%s: duplicate\n' "$field" >> target/runs/T305.review-glm.verdict
    fi
    review_manifest T305 "$(cat target/runs/T305.review-snapshot)" 1 \
      T305.review-glm.verdict T305.review-astra.verdict
    before="$(git rev-parse HEAD)"
    run_task T305
    assert '[ "$rt_rc" -ne 0 ]' "S7: $malformed $field rejected"
    assert '[ "$(git rev-parse HEAD)" = "$before" ]' "S7: $malformed $field cannot commit"
    assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = in-review ]' "S7: $malformed $field retains review state"
  done
done
run_task T305 >/dev/null
gate_verdict T305 REWORK
run_task T305
assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = in-progress ]' "S7: gate rework"
assert '[ "$(cat target/runs/T305.round)" = 2 ]' "S7: round increment"
assert '[ ! -e target/runs/T305.review-glm.verdict ] && [ ! -e target/runs/T305.review-astra.verdict ]' "S7: both approvals removed"

for mutation in worktree index head verdict privacy verify; do
  privacy_fixture "s7-$mutation"
  if [ "$mutation" = verify ]; then
    # The booby-trapped stub is part of the reviewed candidate; it fires only
    # when target/mutate appears, changing p.txt during the APPROVE verify.
    sed -i '/^exit 0$/i [ ! -f target/mutate ] || echo changed >> p.txt' scripts/verify.sh
    git add scripts/verify.sh
  fi
  run_task T305
  gate_verdict T305 APPROVE
  case "$mutation" in
    worktree) echo changed >> p.txt ;;
    index) printf 'second\n' > p.txt; git add p.txt; printf 'first\n' > p.txt ;;
    head) git commit -q -m 'intervening commit' ;;
    verdict) echo 'changed review' >> target/runs/T305.review-glm.verdict ;;
    privacy) sed -i 's/privacy_critical: true/privacy_critical: false/' specs/001-testfeat/tickets/T305-fixture.md ;;
    verify) touch target/mutate ;;
  esac
  before="$(git rev-parse HEAD)"
  run_task T305
  assert '[ "$rt_rc" -ne 0 ]' "S7-$mutation: changed snapshot rejected"
  assert '[ "$(git rev-parse HEAD)" = "$before" ]' "S7-$mutation: no commit"
  assert '[ ! -e target/runs/T305.review-glm.verdict ] && [ ! -e target/runs/T305.review-astra.verdict ]' "S7-$mutation: fresh review required"
done

for verdict in REWORK ESCALATE; do
  privacy_fixture "s7-cap-$verdict"
  echo 2 > target/runs/T305.round
  rm -f target/runs/T305.review-set target/runs/T305.review-glm.verdict \
    target/runs/T305.review-astra.verdict target/runs/T305.review-snapshot
  run_task T305
  gate_verdict T305 "$verdict"
  run_task T305
  assert '[ "$rt_rc" -ne 0 ]' "S7-cap: gate $verdict stops"
  assert '[ "$(fm_field specs/001-testfeat/tickets/T305-fixture.md status)" = escalated ]' "S7-cap: escalated"
  assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S7-cap: no commit"
  assert '[ -s target/runs/T305.review-glm.verdict ] && [ -s target/runs/T305.review-astra.verdict ]' \
    "S7-cap: $verdict preserves both reviewer reports"
  assert '[ -s target/runs/T305.review-set ]' "S7-cap: $verdict preserves the manifest"
done

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
# T105: assert the milestone commit landed on main by reading main's TIP
# subject directly — `git show -s --format=%s main` is a single read-only op
# against one object, independent of HEAD/working-tree (no branch switch).
#
# Grounding finding (falsified the ticket's hypothesis): the run-task --merge
# logic is correct — across 50+ reproducing sandboxes refs/heads/main ALWAYS
# carried the squash commit and run-task's rc was 0. The flake is a transient
# read-side failure under heavy CONCURRENT host load (40+ parallel instances),
# where a git subprocess intermittently returns partial/empty output. The prior
# form (`git checkout -q main` then `git log --oneline | grep`) had TWO
# load-sensitive subprocesses plus a mutating checkout; eliminating the
# checkout and reading the tip subject directly minimises the subprocess
# surface. This makes the assertion deterministic under normal (single-invoked,
# reasonably-loaded) verify.sh operation, which is what the acceptance repro
# (8 sequential runs) exercises. A residual transient-infra failure under
# artificial extreme parallelism is not eliminable without a retry band-aid,
# which §Acceptance #2 and the process doctrine forbid.
assert 'git show -s --format=%s main | grep -q "milestone squash"' "S8: main tip is the milestone squash commit"
assert 'git show-ref --verify --quiet refs/heads/001-testfeat' "S8: feature branch retained"
assert '[ "$(git rev-parse main^{tree})" = "$(git rev-parse 001-testfeat^{tree})" ]' "S8: main carries the feature tip"
# Second milestone: main holds only a squash of the feature branch, so a
# plain `merge --squash` sees the old merge base and conflicts on every file
# both sides added. The driver must fold in only the commits since the
# feature commit main's tree equals (live failure at T182's milestone).
git checkout -q 001-testfeat
printf 'more\n' >> w.txt; git add w.txt; git commit -q -m "Implement 001-testfeat: T307 more work"
run_task T307 --merge
assert '[ "$rt_rc" -eq 0 ]' "S8b: second milestone merge exits 0 (got $rt_rc)"
assert '[ "$(git rev-parse main^{tree})" = "$(git rev-parse 001-testfeat^{tree})" ]' "S8b: main carries the new feature tip"
assert 'git show -s --format=%s main | grep -q "milestone squash (1 ticket commits)"' "S8b: counts only commits since the last milestone"
assert '[ "$(git branch --show-current)" = 001-testfeat ] && [ -z "$(git status --porcelain)" ]' "S8b: back on a clean feature branch"
# Diverged main (content not on the feature branch) that conflicts: the
# squash must be undone, leaving main unchanged and the tree clean.
git checkout -q main
printf 'main-only\n' > w.txt; git add w.txt; git commit -q -m "diverging main edit"
main_before="$(git rev-parse main)"
git checkout -q 001-testfeat
printf 'feature\n' >> w.txt; git add w.txt; git commit -q -m "Implement 001-testfeat: T307 conflicting work"
run_task T307 --merge
assert '[ "$rt_rc" -ne 0 ]' "S8c: conflicting merge exits non-zero (got $rt_rc)"
assert '[ "$(git rev-parse main)" = "$main_before" ]' "S8c: main unchanged on conflict"
assert '[ "$(git branch --show-current)" = 001-testfeat ] && [ -z "$(git status --porcelain)" ]' "S8c: conflict leaves a clean feature branch"

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
run_task T309
gate_verdict T309 REWORK 'fix the thing'
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
run_task T319
gate_verdict T319 REWORK 'fix it'
run_task T319
assert '[ "$rt_rc" -eq 0 ]' "S10b: REWORK r1 exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T319-fixture.md status)" = in-progress ]' \
  "S10b: status -> in-progress after REWORK r1"
assert '[ "$(cat target/runs/T319.round)" = 2 ]' "S10b: round bumped to 2"

# Diff growth does not itself escalate. The old must-shrink rule would reject
# this round even though the reviewer asked for the additional material.
setup_sandbox s10d
write_ticket T326 "rework growth allowed" false in-review >/dev/null
sed -i 's/^round_cap: 2$/round_cap: 3/' specs/001-testfeat/tickets/T326-fixture.md
commit_all "add T326 ticket"
git checkout -q -b 001-testfeat main
mkdir -p target/runs
echo 2 > target/runs/T326.round
printf '1 file changed, 1 insertion(+), 1 deletion(-)\n' > target/runs/T326-r1.diffstat
printf '2 files changed, 2 insertions(+), 2 deletions(-)\n' > target/runs/T326-r2.diffstat
run_task T326
gate_verdict T326 REWORK 'add required evidence'
run_task T326
assert '[ "$rt_rc" -eq 0 ]' "S10d: growth during rework does not escalate (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T326-fixture.md status)" = in-progress ]' \
  "S10d: required rework proceeds despite larger diff"
assert '[ "$(cat target/runs/T326.round)" = 3 ]' "S10d: round advances normally"
assert '! grep -Eiq "must.?shrink|non-converging|convergence \(rework" "$REPO_ROOT/.claude/agents/stargate-review.md" "$REPO_ROOT/.opencode/agent/stargate-review.md"' \
  "S10d: active reviewer roles cannot restore the removed growth rule"

# ===========================================================================
# Scenario 10c: APPROVE-WITH-FIXES — two-step, fail-closed
# Step 1 (no sentinel): emits APPLY-FIXES handoff, exits 0, NO commit.
# Step 2 (sentinel): falls through to the normal APPROVE path and commits
# with the AWF Reviewed-by trailer. Mirrors S4's sandbox shape.
# ===========================================================================
setup_sandbox s10c
write_ticket T320 "approve with fixes commits after sentinel" false in-review >/dev/null
commit_all "add T320 ticket"
git checkout -q -b 001-testfeat main
printf 'real impl\n' > src.txt
git add src.txt specs/001-testfeat/tickets/T320-fixture.md
mkdir -p target/runs
run_task T320
gate_verdict T320 APPROVE-WITH-FIXES $'FIX ITEMS:\n  - fix a comment'
run_task T320   # step 1: no sentinel yet
assert '[ "$rt_rc" -eq 0 ]' "S10c-1: first sight exits 0 (got $rt_rc)"
echo "$rt_out" | grep -qi "APPLY-FIXES" || bail "S10c-1: handoff should mention APPLY-FIXES"
assert '[ "$(fm_field specs/001-testfeat/tickets/T320-fixture.md status)" = in-review ]' \
  "S10c-1: status stays in-review before fixes applied"
assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S10c-1: no commit created"
touch target/runs/T320.awf-applied                # caller signals fixes applied
run_task T320   # step 2: sentinel present -> commit path
assert '[ "$rt_rc" -eq 0 ]' "S10c-2: post-sentinel exits 0 (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T320-fixture.md status)" = done ]' \
  "S10c-2: status -> done"
assert 'git log -1 --format=%B HEAD | grep -q "Reviewed-by: stargate-review (glm; opencode; model zai-coding-plan/glm-5.3-flash; effort xhigh; VERDICT: APPROVE-WITH-FIXES; round"' \
  "S10c-2: trailer carries the AWF verdict kind"
assert '[ ! -e target/runs/T320.awf-applied ]' "S10c-2: awf sentinel cleaned up at done"

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

# ===========================================================================
# Scenario 11 (T142 round 2): a concurrent review-set replacement during the
# driver's final verification must not be outrun by the cached APPROVE —
# the commit decision consumes the set that exists AFTER verification.
setup_sandbox s11race
write_ticket T324 "replacement race" false in-review >/dev/null
commit_all "add T324 ticket"
git checkout -q -b 001-testfeat main
printf 'impl\n' > r.txt
git add r.txt
mkdir -p target/runs
run_task T324
gate_verdict T324 APPROVE
# Booby-trapped verify: holds while target/hold exists until target/release.
cat > scripts/verify.sh <<'VSTUB'
#!/bin/bash
mkdir -p target
echo "RESULT: GREEN" > target/verify.log
if [ -f target/hold ]; then
  : > target/holding
  while [ ! -e target/release ]; do sleep 0.05; done
fi
exit 0
VSTUB
chmod +x scripts/verify.sh
git add scripts/verify.sh
run_task T324                 # candidate changed -> fresh handoff
gate_verdict T324 APPROVE     # approved set for the trapped candidate
touch target/hold
bash scripts/run-task.sh T324 > target/race.log 2>&1 &
race_pid=$!
for i in $(seq 1 200); do
  [ -f target/holding ] && break
  sleep 0.05
done
assert '[ -f target/holding ]' "S11: driver reached final verification"
# While the driver is blocked in verify, a concurrent launcher invocation
# retires the approved set and imports a REWORK replacement for the SAME
# candidate (review-task.sh does exactly this before launching reviewers).
rm -f target/runs/T324.review-set target/runs/T324.review-glm.verdict target/runs/T324.review-astra.verdict
gate_verdict T324 REWORK
touch target/release
wait "$race_pid"; race_rc=$?
assert '[ "$race_rc" -ne 0 ]' "S11: replacement during verification must refuse commit (got $race_rc)"
assert '[ "$(git rev-list --count main..HEAD)" = 0 ]' "S11: no commit on a replaced approval"
assert '[ "$(fm_field specs/001-testfeat/tickets/T324-fixture.md status)" != done ]' "S11: ticket not done on a replaced approval"
assert '[ ! -e target/runs/T324.review-set ]' "S11: refused advance clears the replaced set"

# ===========================================================================
# Scenario 12 (T142 round 3): approval consumption is serialized with the
# launcher through the gate lock — while a (re)launch holds it, the driver
# must refuse to commit; once released, the same approval is consumable.
setup_sandbox s12
write_ticket T325 "approval lock" false in-review >/dev/null
commit_all "add T325 ticket"
git checkout -q -b 001-testfeat main
printf 'impl\n' > l.txt
git add l.txt
mkdir -p target/runs
run_task T325
gate_verdict T325 APPROVE
mkdir target/runs/T325.review.lock   # a concurrent review-task.sh is mid-flight
before="$(git rev-parse HEAD)"
run_task T325
assert '[ "$rt_rc" -ne 0 ]' "S12: driver must not consume approval while a (re)launch holds the gate lock"
assert '[ "$(git rev-parse HEAD)" = "$before" ]' "S12: no commit under a held gate lock"
assert '[ "$(fm_field specs/001-testfeat/tickets/T325-fixture.md status)" = in-review ]' "S12: refusal retains review state for retry"
assert '[ -s target/runs/T325.review-set ]' "S12: refusal preserves the approved set"
rmdir target/runs/T325.review.lock
run_task T325
assert '[ "$rt_rc" -eq 0 ]' "S12: approval is consumable after the launch finishes (got $rt_rc)"
assert '[ "$(fm_field specs/001-testfeat/tickets/T325-fixture.md status)" = done ]' "S12: done after lock release"

# T144: implementation work requires durable red/green evidence tied to the
# task baseline and staged source. A declared test-only ticket stays runnable.
setup_sandbox s144
write_ticket T344 "privacy implementation evidence" true in-progress >/dev/null
sed -i 's/^test_for: \[T999\]$/test_for: []/' specs/001-testfeat/tickets/T344-fixture.md
sed -i 's/^blocked_by: \[\]$/blocked_by: [T343]/' specs/001-testfeat/tickets/T344-fixture.md
sed -i '/^test_for: \[\]$/a tests_first: [T343]' specs/001-testfeat/tickets/T344-fixture.md
commit_all "add T344 ticket"
git checkout -q -b 001-testfeat main
mkdir -p target/runs
git rev-parse HEAD > target/runs/T344.start-sha
printf 'failing test\n' > property_test.txt
python3 -c 'from pathlib import Path; Path("latin1_test.txt").write_bytes(b"\xe9")'
git add property_test.txt latin1_test.txt
probe='from pathlib import Path; text = Path("property_impl.txt").read_text() if Path("property_impl.txt").exists() else ""; present = "fixed" in text; print("property holds" if present else "property absent"); raise SystemExit(0 if present else 1)'
python3 scripts/test-first-evidence.py red T344 -- python3 -c "$probe" >/dev/null 2>&1
red_rc=$?
assert '[ "$red_rc" -eq 0 ]' "T144: red capture succeeds for a failing property probe"
printf 'broken implementation\n' > property_impl.txt
git add property_impl.txt
printf 'fixed implementation\n' > property_impl.txt
green_mismatch="$(python3 scripts/test-first-evidence.py green T344 -- python3 -c "$probe" 2>&1)"; mismatch_rc=$?
assert '[ "$mismatch_rc" -ne 0 ]' "T144: unstaged passing fix cannot validate staged broken source"
[[ "$green_mismatch" = *'staged source differs from working source'* ]] || bail "T144: reject must identify staged source divergence"
git add property_impl.txt
python3 scripts/test-first-evidence.py green T344 -- python3 -c 'print("unrelated passing probe")' >/dev/null 2>&1
bad_green_rc=$?
assert '[ "$bad_green_rc" -ne 0 ]' "T144: green cannot substitute a different probe"
python3 scripts/test-first-evidence.py green T344 -- python3 -c "$probe" >/dev/null 2>&1
green_rc=$?
assert '[ "$green_rc" -eq 0 ]' "T144: green capture succeeds"
git add specs/001-testfeat/evidence/T344-tests-first.json
printf 'unstaged change\n' >> property_impl.txt
touch target/runs/T344.verified
run_task T344
assert '[ "$rt_rc" -ne 0 ]' "T144: edit after green cannot advance with staged/worktree divergence"
assert '[ "$(fm_field specs/001-testfeat/tickets/T344-fixture.md status)" = in-progress ]' "T144: diverged source retains implementation state"
git checkout -- property_impl.txt
python3 scripts/test-first-evidence.py check T344 >/dev/null 2>&1
restored_rc=$?
assert '[ "$restored_rc" -eq 0 ]' "T144: restored staged and working source validates"
touch target/runs/T344.verified
run_task T344
assert '[ "$rt_rc" -eq 0 ]' "T144: matched evidence permits in-review"
assert '[ "$(fm_field specs/001-testfeat/tickets/T344-fixture.md status)" = in-review ]' "T144: status advances with matched evidence"
printf 'changed implementation\n' >> property_impl.txt
git add property_impl.txt
run_task T344
assert '[ "$rt_rc" -ne 0 ]' "T144: candidate mismatch blocks review"
[[ "$rt_out" = *'implemented source snapshot mismatch'* ]] || bail "T144: candidate mismatch must reach digest guard"
printf 'fixed implementation\n' > property_impl.txt
git add property_impl.txt
python3 - <<'PY'
import json
from pathlib import Path
p = Path('specs/001-testfeat/evidence/T344-tests-first.json')
record = json.loads(p.read_text())
record['baseline'] = '0' * 40
p.write_text(json.dumps(record, indent=2) + '\n')
PY
git add specs/001-testfeat/evidence/T344-tests-first.json
run_task T344
assert '[ "$rt_rc" -ne 0 ]' "T144: baseline mismatch blocks review"
[[ "$rt_out" = *'evidence identity or baseline mismatch'* ]] || bail "T144: baseline mismatch must reach identity guard"

setup_sandbox s144missing
write_ticket T345 "missing privacy evidence" true in-progress >/dev/null
sed -i 's/^test_for: \[T999\]$/test_for: []/' specs/001-testfeat/tickets/T345-fixture.md
commit_all "add T345 ticket"
git checkout -q -b 001-testfeat main
printf 'implementation\n' > impl.txt
git add impl.txt
mkdir -p target/runs
git rev-parse HEAD > target/runs/T345.start-sha
touch target/runs/T345.verified
run_task T345
assert '[ "$rt_rc" -ne 0 ]' "T144: missing evidence blocks transition"
assert '[ "$(fm_field specs/001-testfeat/tickets/T345-fixture.md status)" = in-progress ]' "T144: missing evidence retains status"

setup_sandbox s144testonly
write_ticket T346 "separate privacy test ticket" true in-progress >/dev/null
commit_all "add T346 ticket"
git checkout -q -b 001-testfeat main
mkdir -p tests
printf 'separately deliverable test\n' > tests/separate_test.txt
git add tests/separate_test.txt
mkdir -p target/runs
git rev-parse HEAD > target/runs/T346.start-sha
touch target/runs/T346.verified
run_task T346
assert '[ "$rt_rc" -eq 0 ]' "T144: declared test_for ticket advances without implementation evidence"
assert '[ "$(fm_field specs/001-testfeat/tickets/T346-fixture.md status)" = in-review ]' "T144: test-only status advances"

# Scenario 15: verify.sh runs once per executable-content state. The stub
# appends one line per run to target/verify.log.
verify_runs() { grep -c "stub-verify GREEN" target/verify.log 2>/dev/null || echo 0; }
gate_fixture() {
  setup_sandbox "$1"
  write_ticket "$2" "verify once" false in-progress >/dev/null
  commit_all "add $2 ticket"
  git checkout -q -b 001-testfeat main
  printf '// why\npackage x\n\nconst n = 1\n' > x.go
  git add x.go
  mkdir -p target/runs
  git rev-parse HEAD > "target/runs/$2.start-sha"
  touch "target/runs/$2.verified"
  run_task "$2"
}
gate_fixture s15 T347
assert '[ "$(fm_field specs/001-testfeat/tickets/T347-fixture.md status)" = in-review ] && [ "$(verify_runs)" = 1 ]' "S15: pre-review gate runs verify once"
gate_verdict T347 APPROVE
run_task T347
assert '[ "$rt_rc" -eq 0 ] && [ "$(fm_field specs/001-testfeat/tickets/T347-fixture.md status)" = done ]' "S15: approved ticket commits"
assert '[ "$(verify_runs)" = 1 ]' "S15: status flips alone do not re-run verify at APPROVE (runs: $(verify_runs))"

gate_fixture s15comment T348
printf '// why, reworded\npackage x\n\nconst n = 1\n' > x.go; git add x.go
run_task T348                 # candidate changed -> fresh review
gate_verdict T348 APPROVE
run_task T348
assert '[ "$(fm_field specs/001-testfeat/tickets/T348-fixture.md status)" = done ] && [ "$(verify_runs)" = 1 ]' "S15: a Go comment edit does not re-run verify (runs: $(verify_runs))"

gate_fixture s15code T349
printf '// why\npackage x\n\nconst n = 2\n' > x.go; git add x.go
run_task T349
gate_verdict T349 APPROVE
run_task T349
assert '[ "$(fm_field specs/001-testfeat/tickets/T349-fixture.md status)" = done ] && [ "$(verify_runs)" = 2 ]' "S15: a code edit re-runs verify at APPROVE (runs: $(verify_runs))"

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T096 run-task harness (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T096 workflow-driver regression harness (15 scenarios) — start, approve, single-gate review, commit, merge, dirty refusal, rework, lint, replacement race, gate lock, verify once"
exit 0
