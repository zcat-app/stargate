#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Single-gate reviewer regression for T142; deterministic CLI stand-ins, no
# provider calls. One launcher invocation runs both reviewers (OpenCode GLM
# and Codex Astra) over the same pass; there is no second phase.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="$REPO_ROOT/scripts/review-task.sh"
MATRIX="$REPO_ROOT/scripts/review-matrix.json"
SANDBOX="$(mktemp -d -t stargate-t142-XXXXXX)"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

errs=()
bail() { errs+=("$*"); }

if [ ! -x "$RUNNER" ]; then
  echo "FAIL: single-gate review launcher missing or not executable: $RUNNER" >&2
  exit 1
fi
if [ ! -f "$MATRIX" ]; then
  echo "FAIL: review matrix missing: $MATRIX" >&2
  exit 1
fi

python3 - "$MATRIX" <<'PY' || exit 1
import json, sys

matrix = json.load(open(sys.argv[1]))
expected = [
    ("glm", "opencode", "stargate-review", "zai-coding-plan/glm-5.3-flash", "xhigh",
     lambda t: f"{t}.review-glm.verdict"),
    ("astra", "codex", "stargate-review", "gpt-6-astra", "high",
     lambda t: f"{t}.review-astra.verdict"),
]
rows = matrix.get("reviewers")
if not isinstance(rows, list) or len(rows) != 2:
    raise SystemExit(f"single gate requires exactly two reviewers: {rows!r}")
for row, (rid, tool, role, model, effort, out) in zip(rows, expected):
    got = (row.get("id"), row.get("tool"), row.get("role"), row.get("model"),
           row.get("effort"), row.get("output", "").replace("{ticket}", "T900"))
    want = (rid, tool, role, model, effort, out("T900"))
    if got != want:
        raise SystemExit(f"matrix mismatch: {got!r} != {want!r}")
if "phases" in matrix:
    raise SystemExit("split-phase matrix survived: 'phases' must be gone")
PY

grep -q 'candidate_seal' "$RUNNER" ||
  bail "launcher does not verify each materialized candidate against the handoff seal"

if grep -Eq '\bdocker\b|\bbwrap\b|\bunshare\b' "$RUNNER"; then
  bail "native review runner must not launch containment infrastructure"
fi

# The retired split-phase CLI surface must be gone, not silently accepted.
"$RUNNER" T900 codereview >/dev/null 2>&1
[ "$?" -eq 2 ] || bail "legacy phase argument must be a hard usage error"

# Exercise the production orchestration path with deterministic local CLI
# stand-ins. Dummy environment values satisfy credential preflight but are
# never sent anywhere; the stand-ins make no network calls.
ACTUAL="$SANDBOX/actual"
mkdir -p "$ACTUAL/scripts" "$ACTUAL/.specify" "$ACTUAL/.claude/agents" \
  "$ACTUAL/specs/001-fixture/tickets" "$ACTUAL/fake-bin"
cp "$RUNNER" "$ACTUAL/scripts/review-task.sh"
cp "$MATRIX" "$ACTUAL/scripts/review-matrix.json"
cp "$REPO_ROOT/scripts/run-task.sh" "$ACTUAL/scripts/run-task.sh"
cp "$REPO_ROOT/scripts/test-first-evidence.py" "$ACTUAL/scripts/test-first-evidence.py"
cp "$REPO_ROOT/.claude/agents/stargate-review.md" "$ACTUAL/.claude/agents/"
printf '#!/usr/bin/env bash\nmkdir -p target\necho "RESULT: GREEN" > target/verify.log\n' > "$ACTUAL/scripts/verify.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$ACTUAL/scripts/regen-status.sh"
chmod +x "$ACTUAL/scripts/"*.sh
printf '{"feature_directory":"specs/001-fixture"}\n' > "$ACTUAL/.specify/feature.json"
printf 'target/\n' > "$ACTUAL/.gitignore"
cat > "$ACTUAL/specs/001-fixture/tickets/T900-fixture.md" <<'EOF'
---
id: T900
title: isolated fixture
status: in-review
privacy_critical: true
test_for: [T901]
files_budget: 8
round_cap: 2
reviews: {}
---
# T900
## Context
Fixture.
## Acceptance
The isolated single-gate review set is required.
## Out-of-scope
None.
EOF

cat > "$ACTUAL/fake-bin/opencode" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = run ] && [ "${2:-}" = 'Perform the attached isolated ticket review directly.' ] || {
  echo 'OpenCode positional message must precede array-valued --file' >&2
  exit 64
}
prompt=""
model=""
role=""
[[ " $* " = *" --variant xhigh "* ]] || exit 64
[[ " $* " != *" --session "* && " $* " != *" --continue "* ]] || exit 64
while [ "$#" -gt 0 ]; do
  case "$1" in
    --file) prompt="$2"; shift 2 ;;
    --dir) cd "$2"; shift 2 ;;
    --model) model="$2"; shift 2 ;;
    --agent) role="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ "$model" = zai-coding-plan/glm-5.3-flash ] || exit 64
[ "$role" = stargate-review ] || exit 64
output="$(sed -n 's/^Your verdict output path is \(.*\) in your private candidate\.$/\1/p' "$prompt" | head -1)"
[ "$output" = target/runs/T900.review-glm.verdict ] || exit 64
[[ "$PWD" = */glm/candidate ]] || exit 64
[ ! -e target/runs/T900.review-astra.verdict ] || exit 64
if [ -n "${STARGATE_FIXTURE_CALL_LOG:-}" ]; then
  printf '%s\n' "$$" >> "$STARGATE_FIXTURE_CALL_LOG"
fi
if [ -n "${STARGATE_FIXTURE_BARRIER:-}" ]; then
  while [ ! -e "$STARGATE_FIXTURE_BARRIER/release" ]; do sleep 0.05; done
fi
[ "${STARGATE_FIXTURE_FAIL:-}" != 1 ] || exit 42
[ ! -f .fixture-fail ] || exit 42
if [ -f .fixture-mutate ]; then
  python3 -c 'open("candidate.txt", "w").write("changed by reviewer")'
fi
[ "${OPENCODE_CONFIG_CONTENT:-}" != "" ] || exit 64
python3 -c 'import json,os; c=json.loads(os.environ["OPENCODE_CONFIG_CONTENT"]); assert c["provider"]["zai-coding-plan"]["models"]["glm-5.3-flash"]["variants"]["xhigh"]["reasoningEffort"] == "max"; assert c["permission"]["task"] == "deny"'
python3 -c 'import json,os; c=json.loads(os.environ["OPENCODE_CONFIG_CONTENT"]); assert c["agent"]["stargate-review"]["mode"] == "all"'
if [ -f .fixture-extra-output ]; then
  mkdir -p target/runs/not-a-verdict
fi
if [ "${STARGATE_FIXTURE_EXPECT_PRIOR:-}" = 1 ]; then
  grep -q 'OWN-GLM-PRIOR' "$prompt"
  grep -q 'OWN-ASTRA-PRIOR' "$prompt" || exit 65
fi
{
  echo "VERDICT: ${STARGATE_FIXTURE_VERDICT:-APPROVE}"
  for field in REVIEWER TOOL MODEL EFFORT SNAPSHOT ROUND; do grep -m1 "^$field:" "$prompt"; done
  echo 'SUMMARY: fixture single-gate approval'
  if [ "${STARGATE_FIXTURE_VERDICT:-APPROVE}" = REWORK ]; then
    echo "FINDINGS: OWN-GLM-PRIOR closure probe"
  else
    echo 'FINDINGS: none'
  fi
} > "$output"
EOF
cat > "$ACTUAL/fake-bin/codex" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
model=""
args="$*"
[[ " $* " = *" -s danger-full-access "* && " $* " = *" --ephemeral "* ]] || exit 64
[[ " $* " = *'model_reasoning_effort="high"'* ]] || exit 64
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -C) cd "$2"; shift 2 ;;
    -m) model="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ "$model" = gpt-6-astra ] || exit 64
[[ "$output" = */candidate/target/runs/T900.review-astra.verdict ]] || exit 64
[[ "$PWD" = */astra/candidate ]] || exit 64
[ ! -e target/runs/T900.review-glm.verdict ] || exit 64
if [ -n "${STARGATE_FIXTURE_CALL_LOG:-}" ]; then
  printf '%s\n' "$$" >> "$STARGATE_FIXTURE_CALL_LOG"
fi
if [ -n "${STARGATE_FIXTURE_BARRIER:-}" ]; then
  while [ ! -e "$STARGATE_FIXTURE_BARRIER/release" ]; do sleep 0.05; done
fi
prompt="$(mktemp)"
cat > "$prompt"
effort="$(sed -n 's/^EFFORT: //p' "$prompt" | head -1)"
[[ "$args" = *"model_reasoning_effort=\"$effort\""* ]] || exit 64
if [ "${STARGATE_FIXTURE_EXPECT_PRIOR:-}" = 1 ]; then
  grep -q 'OWN-ASTRA-PRIOR' "$prompt"
  grep -q 'OWN-GLM-PRIOR' "$prompt" || exit 65
fi
{
  echo "VERDICT: ${STARGATE_FIXTURE_VERDICT:-APPROVE}"
  for field in REVIEWER TOOL MODEL EFFORT SNAPSHOT ROUND; do grep -m1 "^$field:" "$prompt"; done
  echo 'SUMMARY: fixture single-gate approval'
  if [ "${STARGATE_FIXTURE_VERDICT:-APPROVE}" = REWORK ]; then
    echo "FINDINGS: OWN-ASTRA-PRIOR closure probe"
  else
    echo 'FINDINGS: none'
  fi
} > "$output"
EOF
chmod +x "$ACTUAL/fake-bin/opencode" "$ACTUAL/fake-bin/codex"
actual_text="$(
(
  cd "$ACTUAL" || exit 1
  git init -q -b main
  git config user.email fixture@example.invalid
  git config user.name 'T142 fixture'
  git config commit.gpgsign false
  printf 'before\n' > candidate.txt
  git add -A
  git commit -qm fixture
  start_sha="$(git rev-parse HEAD)"
  printf 'after\n' > candidate.txt
  git add candidate.txt
  mkdir -p target/runs
  printf '%s\n' "$start_sha" > target/runs/T900.start-sha
  bash scripts/run-task.sh T900 >/dev/null
  PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
    bash scripts/review-task.sh T900
) 2>&1
)"
actual_rc=$?
[ "$actual_rc" -eq 0 ] || bail "production launcher path failed with local CLI stand-ins: $actual_text"
for verdict in T900.review-glm.verdict T900.review-astra.verdict; do
  [ -s "$ACTUAL/target/runs/$verdict" ] || bail "production path did not import $verdict"
done
[ -s "$ACTUAL/target/runs/T900.review-set" ] || bail "production path omitted manifest-last marker"
grep -q '^GATE: review$' "$ACTUAL/target/runs/T900.review-set" || bail "manifest is not the single gate"
[ "$(cat "$ACTUAL/candidate.txt")" = "after" ] || bail "production path modified the live candidate"

cp -a "$ACTUAL" "$SANDBOX/gate-approved"

# Each private output directory is a constrained import channel: an unexpected
# directory or symlink must reject the whole set, not be ignored because it is
# not a regular file.
extra_text="$({
  cd "$ACTUAL" || exit 1
  rm -f target/runs/T900.review-glm.verdict target/runs/T900.review-astra.verdict \
    target/runs/T900.review-set
  printf 'trigger\n' > .fixture-extra-output
  git add .fixture-extra-output
  bash scripts/run-task.sh T900 >/dev/null
  PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
    bash scripts/review-task.sh T900
} 2>&1)"
extra_rc=$?
[ "$extra_rc" -ne 0 ] || bail "unexpected reviewer output entry did not fail the set"
[ ! -e "$ACTUAL/target/runs/T900.review-set" ] ||
  bail "rejected output set still received a live manifest: $extra_text"
for verdict in T900.review-glm.verdict T900.review-astra.verdict; do
  [ ! -e "$ACTUAL/target/runs/$verdict" ] || bail "rejected output set imported $verdict"
done

# Failures and source changes invalidate the entire set, even when its peer
# wrote an otherwise valid approval. The live tree must retain its bytes.
for mode in fail mutate; do
  result="$({
    cd "$ACTUAL" || exit 1
    git rm -q -f --ignore-unmatch .fixture-extra-output .fixture-fail .fixture-mutate
    printf 'trigger\n' > ".fixture-$mode"
    git add ".fixture-$mode"
    bash scripts/run-task.sh T900 >/dev/null
    PATH="$ACTUAL/fake-bin:$PATH" bash scripts/review-task.sh T900
  } 2>&1)"
  rc=$?
  [ "$rc" -ne 0 ] || bail "$mode did not reject the review set: $result"
  if [ "$mode" = mutate ]; then
    [[ "$result" = *'reviewer changed its source copy'* ]] || bail "mutation was not the rejection cause: $result"
  fi
  [ ! -e "$ACTUAL/target/runs/T900.review-set" ] || bail "$mode imported a manifest"
  [ "$(cat "$ACTUAL/candidate.txt")" = after ] || bail "$mode changed the live source"
done

# A replacement attempt invalidates prior approvals even if source is unchanged.
case_dir="$SANDBOX/retry"
cp -a "$SANDBOX/gate-approved" "$case_dir"
before="$(git -C "$case_dir" rev-parse HEAD)"
result="$({
  cd "$case_dir" || exit 1
  git rm -q -f --ignore-unmatch .fixture-mutate
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_FAIL=1 bash scripts/review-task.sh T900
} 2>&1)"
[ "$?" -ne 0 ] || bail "failed replacement succeeded"
[ ! -e "$case_dir/target/runs/T900.review-set" ] || bail "gate retained old approval manifest"
(cd "$case_dir" && bash scripts/run-task.sh T900 >/dev/null 2>&1)
[ "$(git -C "$case_dir" rev-parse HEAD)" = "$before" ] || bail "gate committed after failed replacement"

# B and C must both refuse while A holds the gate lock.
case_dir="$SANDBOX/concurrent"
cp -a "$SANDBOX/gate-approved" "$case_dir"
mkdir "$SANDBOX/barrier"
call_log="$SANDBOX/barrier/calls"
(
  cd "$case_dir" || exit 1
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_BARRIER="$SANDBOX/barrier" \
    STARGATE_FIXTURE_CALL_LOG="$call_log" bash scripts/review-task.sh T900
) > "$SANDBOX/concurrent.log" 2>&1 &
launch_a=$!
for ((attempt=0; attempt<200; attempt++)); do
  [ -f "$call_log" ] && [ "$(wc -l < "$call_log")" -eq 2 ] && break
  sleep 0.05
done
[ -f "$call_log" ] && [ "$(wc -l < "$call_log")" -eq 2 ] || bail "concurrency positive control did not start both reviewers"
for other in B C; do
  result="$({
    cd "$case_dir" || exit 1
    PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_CALL_LOG="$call_log" \
      timeout 10 bash scripts/review-task.sh T900
  } 2>&1)"
  [ "$?" -ne 0 ] || bail "concurrent launch $other was accepted"
  [ -d "$case_dir/target/runs/T900.review.lock" ] || bail "launch $other removed A's lock"
done
touch "$SANDBOX/barrier/release"
wait "$launch_a" || bail "owner launch failed"
[ "$(wc -l < "$call_log")" -eq 2 ] || bail "more than the owner's two reviewers started"

# Prove actual model arguments, not just prompt/model labels, are checked.
for mutation in missing-glm wrong-glm missing-astra wrong-astra missing-role wrong-role; do
  case_dir="$SANDBOX/$mutation"
  cp -a "$SANDBOX/gate-approved" "$case_dir"
  case "$mutation" in
    missing-glm) sed -i 's/--model "$model" //' "$case_dir/scripts/review-task.sh" ;;
    wrong-glm) sed -i 's/--model "$model"/--model wrong-model/' "$case_dir/scripts/review-task.sh" ;;
    missing-astra) sed -i 's/-m "$model" //' "$case_dir/scripts/review-task.sh" ;;
    wrong-astra) sed -i 's/-m "$model"/-m wrong-model/' "$case_dir/scripts/review-task.sh" ;;
    missing-role) sed -i 's/--agent "$role" //' "$case_dir/scripts/review-task.sh" ;;
    wrong-role) sed -i 's/--agent "$role"/--agent build/' "$case_dir/scripts/review-task.sh" ;;
  esac
  result="$({
    cd "$case_dir" || exit 1
    git add scripts/review-task.sh
    bash scripts/run-task.sh T900 >/dev/null 2>&1 || true
    bash scripts/run-task.sh T900 >/dev/null
    PATH="$ACTUAL/fake-bin:$PATH" bash scripts/review-task.sh T900
  } 2>&1)"
  [ "$?" -ne 0 ] && [[ "$result" = *'failed (rc=64)'* ]] || bail "model mutation $mutation escaped argument check: $result"
done

# A REWORK gate must survive the driver round transition as private own-item
# evidence for BOTH reviewers of the next round, and the round after the fix
# commits privacy-critical work on the single gate alone.
case_dir="$SANDBOX/prior"
cp -a "$SANDBOX/gate-approved" "$case_dir"
result="$({
  cd "$case_dir" || exit 1
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_VERDICT=REWORK bash scripts/review-task.sh T900
  bash scripts/run-task.sh T900 >/dev/null
  touch target/runs/T900.verified
  bash scripts/run-task.sh T900 >/dev/null
  bash scripts/run-task.sh T900 >/dev/null
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_EXPECT_PRIOR=1 bash scripts/review-task.sh T900
  bash scripts/run-task.sh T900 >/dev/null
} 2>&1)"
[ "$?" -eq 0 ] || bail "repeat review lost or leaked prior findings: $result"
grep -q '^status: done' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" ||
  bail "single gate did not carry the privacy-critical ticket to done"

# The driver retains the gate lock through trailer capture and git commit.
# A git shim pauses the driver exactly at `git commit`; while it is held
# there a REAL launcher invocation (fake CLIs) must refuse, and the commit
# that lands afterwards carries exactly the authorizing set's trailers.
commit_boundary_case() {
  local tag="$1" driver="$2" launcher_rc
  local case_dir="$SANDBOX/$tag"
  cp -a "$SANDBOX/gate-approved" "$case_dir"
  # The shim lives OUTSIDE the repo: an in-repo shim would be untracked
  # source the driver's inventory check correctly refuses.
  mkdir -p "$SANDBOX/$tag-gitshim"
  cat > "$SANDBOX/$tag-gitshim/git" <<'SHIM'
#!/usr/bin/env bash
if [ "${1:-}" = commit ]; then
  mkdir -p target
  : > target/committing
  while [ ! -e target/release-commit ]; do sleep 0.05; done
  if [ -e target/abort-commit ]; then exit 130; fi
fi
exec /usr/bin/git "$@"
SHIM
  chmod +x "$SANDBOX/$tag-gitshim/git"
  rm -f "$case_dir/target/committing" "$case_dir/target/release-commit" "$case_dir/target/abort-commit"
  if [ "$driver" = mutated ]; then
    python3 - "$case_dir/scripts/run-task.sh" <<'MUT'
import sys
p = sys.argv[1]
t = open(p).read()
anchor = '      REVIEW_LINE="$(review_trailers'
assert anchor in t
# Early-unlock mutation: release right after the in-lock validation, before
# trailer capture — exactly the critical-section-lifetime defect round 3
# flagged S12 for not catching.
open(p, 'w').write(t.replace(
    anchor,
    '      rmdir "$RUN_DIR/$TICKET_ID.review.lock" 2>/dev/null || true\n' + anchor, 1))
MUT
    # The mutation must be part of the reviewed candidate, or the driver's
    # snapshot guard refuses the mutated tree before the boundary.
    (cd "$case_dir" && git add scripts/run-task.sh &&
     bash scripts/run-task.sh T900 >/dev/null 2>&1 || true &&
     bash scripts/run-task.sh T900 >/dev/null 2>&1 &&
     PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
       bash scripts/review-task.sh T900 >/dev/null 2>&1) || bail "$tag: mutant re-approval failed"
  fi
  (
    cd "$case_dir" || exit 1
    PATH="$SANDBOX/$tag-gitshim:$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
      timeout 60 bash scripts/run-task.sh T900
  ) > "$SANDBOX/$tag-driver.log" 2>&1 &
  local drv=$!
  local i
  for i in $(seq 1 300); do [ -f "$case_dir/target/committing" ] && break; sleep 0.05; done
  [ -f "$case_dir/target/committing" ] || { bail "$tag: driver never reached the commit boundary: $(tail -3 "$SANDBOX/$tag-driver.log" 2>/dev/null)"; kill "$drv" 2>/dev/null; return; }
  local result rc
  result="$(
    cd "$case_dir" || exit 1
    PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
      STARGATE_FIXTURE_VERDICT=REWORK timeout 30 bash scripts/review-task.sh T900 2>&1
  )"
  rc=$?
  if [ "$driver" = mutated ]; then
    # Non-vacuity control: with the early unlock, the boundary launcher is
    # ADMITTED — proving the unmutated assertion below is load-bearing.
    [ "$rc" -eq 0 ] || bail "$tag: mutant unexpectedly refused ($rc): $result"
  else
    [ "$rc" -ne 0 ] || bail "$tag: launcher started while the driver held the gate lock"
    [[ "$result" = *'already running'* ]] || bail "$tag: refusal was not the held lock: $result"
    [ -d "$case_dir/target/runs/T900.review.lock" ] || bail "$tag: driver's lock vanished at the commit boundary"
  fi
  : > "$case_dir/target/release-commit"
  wait "$drv" || bail "$tag: driver failed after the boundary release: $(cat "$SANDBOX/$tag-driver.log")"
  if [ "$driver" != mutated ]; then
    grep -q '^status: done' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" ||
      bail "$tag: driver did not complete after release"
    git -C "$case_dir" log -1 --format=%B > "$SANDBOX/$tag-msg"
    grep -q 'Reviewed-by: stargate-review (glm; opencode; model zai-coding-plan/glm-5.3-flash; effort xhigh; VERDICT: APPROVE' "$SANDBOX/$tag-msg" ||
      bail "$tag: commit trailers do not match the authorizing APPROVE set (glm)"
    grep -q 'Reviewed-by: stargate-review (astra; codex; model gpt-6-astra; effort high; VERDICT: APPROVE' "$SANDBOX/$tag-msg" ||
      bail "$tag: commit trailers do not match the authorizing APPROVE set (astra)"
  fi
}
commit_boundary_case s13-hold normal
commit_boundary_case s13-early-unlock-mutant mutated

# Catchable termination inside the approval critical section must release the
# gate lock (owner-tracked cleanup) and leave the candidate uncommitted, the
# ticket in review, and the gate immediately usable again.
s14_case() {
  local case_dir="$SANDBOX/s14-sigterm" drv i s14_before s14_rc result
  cp -a "$SANDBOX/gate-approved" "$case_dir"
  cp -a "$SANDBOX/s13-hold-gitshim" "$SANDBOX/s14-gitshim"
  rm -f "$case_dir/target/committing" "$case_dir/target/release-commit" "$case_dir/target/abort-commit"
  (
    cd "$case_dir" || exit 1
    PATH="$SANDBOX/s14-gitshim:$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
      bash scripts/run-task.sh T900
  ) > "$SANDBOX/s14-driver.log" 2>&1 &
  drv=$!
  for i in $(seq 1 200); do [ -f "$case_dir/target/committing" ] && break; sleep 0.05; done
  if [ ! -f "$case_dir/target/committing" ]; then
    bail "s14: driver never reached the commit boundary"
    kill "$drv" 2>/dev/null
    wait "$drv" 2>/dev/null
    return
  fi
  s14_before="$(git -C "$case_dir" rev-parse HEAD)"
  kill -TERM "$drv"
  : > "$case_dir/target/abort-commit"
  : > "$case_dir/target/release-commit"
  wait "$drv"; s14_rc=$?
  [ "$s14_rc" -ne 0 ] || bail "s14: terminated driver reported success"
  [ ! -d "$case_dir/target/runs/T900.review.lock" ] || bail "s14: SIGTERM inside the critical section stranded the gate lock"
  [ "$(git -C "$case_dir" rev-parse HEAD)" = "$s14_before" ] || bail "s14: terminated driver still committed"
  grep -q '^status: in-review' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" || bail "s14: ticket left review state on termination"
  # The gate must be immediately usable after the cleanup: a real launcher run
  # acquires the lock and completes.
  result="$(
    cd "$case_dir" || exit 1
    PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
      bash scripts/review-task.sh T900 2>&1
  )"
  [ "$?" -eq 0 ] || bail "s14: gate lock was not reusable after SIGTERM cleanup: $result"
}
s14_case

if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T142 single-gate review boundary (${#errs[@]} finding(s)):" >&2
  printf '  - %s\n' "${errs[@]}" >&2
  exit 1
fi

echo "PASS: T142 single-gate review boundary"
