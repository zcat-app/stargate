#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# review-task.sh — launch the complete single-gate reviewer set against one
# candidate. ONE invocation runs every configured reviewer in parallel as a
# native CLI child process with a fresh context; correctness and adversarial
# security review happen in the same pass (no split phases). Separate source
# copies prevent accidental interference, not hostile same-user access.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
REPO_ROOT="$(pwd)"
MATRIX="$REPO_ROOT/scripts/review-matrix.json"
RUN_DIR="$REPO_ROOT/target/runs"
TICKET_ID=""

usage() {
  echo "usage: scripts/review-task.sh <T-NNN>" >&2
}

  [ "$#" -eq 1 ] || { usage; exit 2; }
  TICKET_ID="$1"
  [[ "$TICKET_ID" =~ ^T[0-9]+[a-z]?$ ]] || { echo "review-task: invalid ticket id" >&2; exit 2; }

[ -f "$MATRIX" ] || { echo "review-task: missing $MATRIX" >&2; exit 1; }
mkdir -p "$RUN_DIR"

ROOT_TMP="$(mktemp -d -t stargate-review-XXXXXX)"
LOCK_DIR=""
declare -a REVIEWER_IDS=()
declare -a REVIEWER_TOOLS=()
declare -a REVIEWER_ROLES=()
declare -a REVIEWER_MODELS=()
declare -a REVIEWER_EFFORTS=()
declare -a REVIEWER_OUTPUTS=()
declare -a REVIEWER_DIRS=()
declare -a REVIEWER_PIDS=()

cleanup() {
  local pid
  for pid in "${REVIEWER_PIDS[@]:-}"; do
    [ -z "$pid" ] || kill -- "-$pid" 2>/dev/null || true
  done
  for pid in "${REVIEWER_PIDS[@]:-}"; do
    [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
  done
  if [ -n "$LOCK_DIR" ]; then rmdir "$LOCK_DIR" >/dev/null 2>&1 || true; fi
  rm -rf "$ROOT_TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

load_matrix() {
  local ticket="$1"
  while IFS=$'\t' read -r id tool role model effort output; do
    REVIEWER_IDS+=("$id")
    REVIEWER_TOOLS+=("$tool")
    REVIEWER_ROLES+=("$role")
    REVIEWER_MODELS+=("$model")
    REVIEWER_EFFORTS+=("$effort")
    REVIEWER_OUTPUTS+=("$output")
  done < <(python3 - "$MATRIX" "$ticket" <<'PY'
import json, re, sys

matrix = json.load(open(sys.argv[1]))
if matrix.get("version") != 1:
    raise SystemExit("review-task: unsupported review matrix version")
rows = matrix.get("reviewers")
if not isinstance(rows, list) or len(rows) != 2:
    raise SystemExit("review-task: the single gate requires exactly two reviewers")
seen_ids, seen_tools = set(), set()
for row in rows:
    values = [row.get(k, "") for k in ("id", "tool", "role", "model", "effort", "output")]
    if any(not isinstance(v, str) or not v or "\t" in v or "\n" in v for v in values):
        raise SystemExit("review-task: malformed review matrix row")
    if values[0] in seen_ids or values[1] in seen_tools or values[1] not in ("opencode", "codex"):
        raise SystemExit("review-task: duplicate reviewer, duplicate tool or unknown tool")
    seen_ids.add(values[0])
    seen_tools.add(values[1])
    output = values[5].replace("{ticket}", sys.argv[2])
    if not re.fullmatch(r"T[0-9]+[a-z]?(?:\.[a-z0-9-]+)*\.verdict", output):
        raise SystemExit("review-task: unsafe verdict filename")
    print("\t".join([*values[:5], output]))
PY
  )
  [ "${#REVIEWER_IDS[@]}" -eq 2 ] || { echo "review-task: invalid reviewer matrix" >&2; exit 1; }
}

snapshot() {
  python3 - "$RUN_DIR/$TICKET_ID.start-sha" "$RUN_DIR/$TICKET_ID.round" <<'PY'
import hashlib, os, pathlib, subprocess, sys

def git(*args):
    return subprocess.check_output(['git', *args])

base_file, round_file = sys.argv[1:]
base_path = pathlib.Path(base_file)
base = base_path.read_text().strip() if base_path.exists() else git('rev-parse', 'HEAD').decode().strip()
parts = [base.encode(), pathlib.Path(round_file).read_bytes().strip(), git('rev-parse', 'HEAD'),
         git('diff', '--no-ext-diff', '--binary', base, '--'),
         git('diff', '--no-ext-diff', '--binary', '--cached', base, '--')]
for name in sorted(filter(None, git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0'))):
    path = pathlib.Path(os.fsdecode(name))
    parts.extend([name, str(path.lstat().st_mode).encode(),
                  os.fsencode(path.readlink()) if path.is_symlink() else path.read_bytes()])
digest = hashlib.sha256()
for part in parts:
    digest.update(len(part).to_bytes(8, 'big'))
    digest.update(part)
print(digest.hexdigest())
PY
}

materialize_candidate() {
  local destination="$1" staged_patch="$2" unstaged_patch="$3" head_sha="$4"
  git clone -q --no-local --no-hardlinks "$REPO_ROOT" "$destination"
  git -C "$destination" checkout -q --detach "$head_sha"
  if [ -s "$staged_patch" ]; then
    git -C "$destination" apply --index --binary "$staged_patch"
  fi
  if [ -s "$unstaged_patch" ]; then
    git -C "$destination" apply --binary "$unstaged_patch"
  fi
  mkdir -p "$destination/target/runs"
}

build_prompt() {
  local destination="$1" id="$2" tool="$3" role="$4" model="$5" effort="$6" output="$7" expected="$8" round="$9"
  local role_file="$REPO_ROOT/.claude/agents/$role.md"
  [ -f "$role_file" ] || { echo "review-task: missing role file $role_file" >&2; return 1; }
  {
    echo "# Isolated single-gate reviewer runtime"
    echo
    echo "You are the already-spawned $role reviewer with identity $id. Your gate covers correctness AND adversarial security/privacy in this one pass. Review directly; do not delegate or invoke another model CLI."
    echo "Your candidate is a separate local copy. Inspect only this copy; do not seek the live checkout or peer sessions. This is context separation, not an OS security boundary."
    echo "Your verdict output path is target/runs/$output in your private candidate."
    echo "Copy these identity fields exactly once into the verdict:"
    echo "REVIEWER: $id"
    echo "TOOL: $tool"
    echo "MODEL: $model"
    echo "EFFORT: $effort"
    echo "SNAPSHOT: $expected"
    echo "ROUND: $round"
    echo
    echo "# Canonical role instructions"
    cat "$role_file"
    echo
    echo "# Driver handoff"
    cat "$RUN_DIR/$TICKET_ID.prompt"
    echo
    echo "# Runtime binding (takes precedence for transport only)"
    echo "This process itself satisfies the handoff's request to run the reviewer set. Do not spawn another."
    if [ "$tool" = codex ]; then
      echo "You run natively without an OS sandbox. Inspection is read-only by instruction; return the full structured verdict as your final response."
      echo "The Codex CLI captures those exact bytes to target/runs/$output; do not attempt a file write."
    else
      echo "Write the full verdict to target/runs/$output. Do not write any other path."
    fi
    echo "Do not edit source or run builds. Use supplied verification evidence and read-only inspection. Report capability limits honestly."
  } > "$destination"
}

validate_verdict() {
  local file="$1" id="$2" tool="$3" model="$4" effort="$5" expected="$6" round="$7"
  python3 - "$file" "$id" "$tool" "$model" "$effort" "$expected" "$round" <<'PY'
import re, sys

path, reviewer, tool, model, effort, snapshot, round_number = sys.argv[1:]
text = open(path).read()
def field(name):
    values = re.findall(r"^" + re.escape(name) + r":[ \t]*(.*)$", text, re.MULTILINE)
    if len(values) != 1:
        raise ValueError(name)
    return values[0].strip()
try:
    verdict = field("VERDICT")
    if verdict not in ("APPROVE", "APPROVE-WITH-FIXES", "REWORK", "ESCALATE"):
        raise ValueError("verdict")
    expected = {"REVIEWER": reviewer, "TOOL": tool, "MODEL": model, "EFFORT": effort,
                "SNAPSHOT": snapshot, "ROUND": round_number}
    if any(field(key) != value for key, value in expected.items()):
        raise ValueError("identity")
    # Every single-gate reviewer is also the security review: the
    # summary/findings discipline applies to both, not to one phase.
    if not field("SUMMARY") or field("FINDINGS") is None:
        raise ValueError("gate fields")
except ValueError as exc:
    raise SystemExit(f"review-task: invalid verdict {path}: {exc}")
PY
}

run_actual() {
  load_matrix "$TICKET_ID"
  # Lock ownership: LOCK_DIR is assigned ONLY after this process creates the
  # lock, so a refused concurrent launch's cleanup cannot rmdir the holder's
  # (empty) lock directory and let a third launch through.
  mkdir "$RUN_DIR/$TICKET_ID.review.lock" 2>/dev/null || { echo "review-task: a review set is already running for $TICKET_ID" >&2; exit 1; }
  LOCK_DIR="$RUN_DIR/$TICKET_ID.review.lock"
  local prompt="$RUN_DIR/$TICKET_ID.prompt" snapshot_file manifest
  [ -f "$prompt" ] || { echo "review-task: missing driver handoff $prompt" >&2; exit 1; }
  grep -q '(REVIEW,' "$prompt" || { echo "review-task: handoff is not REVIEW" >&2; exit 1; }
  snapshot_file="$RUN_DIR/$TICKET_ID.review-snapshot"
  [ -s "$snapshot_file" ] || { echo "review-task: missing driver snapshot" >&2; exit 1; }
  local expected round head_sha before after staged_patch unstaged_patch
  expected="$(cat "$snapshot_file")"
  round="$(cat "$RUN_DIR/$TICKET_ID.round")"
  head_sha="$(git rev-parse HEAD)"
  before="$(snapshot)"
  [ "$before" = "$expected" ] || { echo "review-task: stale handoff; live candidate does not match $expected" >&2; exit 1; }
  if git ls-files --others --exclude-standard | grep -q .; then
    echo "review-task: untracked source present; refusing incomplete candidate" >&2
    exit 1
  fi

  # A new launch retires any previous approval set first: a failed rerun must
  # never leave stale verdicts + manifest standing for an unchanged tree the
  # driver could still commit on.
  rm -f "$RUN_DIR/$TICKET_ID.review-set"
  for output in "${REVIEWER_OUTPUTS[@]}"; do rm -f "$RUN_DIR/$output"; done

  staged_patch="$ROOT_TMP/staged.patch"
  unstaged_patch="$ROOT_TMP/unstaged.patch"
  git diff --binary --cached HEAD -- > "$staged_patch"
  git diff --binary -- > "$unstaged_patch"
  local i id tool role model effort output dir candidate candidate_seal out input binary
  for i in "${!REVIEWER_IDS[@]}"; do
    id="${REVIEWER_IDS[$i]}"; tool="${REVIEWER_TOOLS[$i]}"; role="${REVIEWER_ROLES[$i]}"
    model="${REVIEWER_MODELS[$i]}"; effort="${REVIEWER_EFFORTS[$i]}"; output="${REVIEWER_OUTPUTS[$i]}"
    dir="$ROOT_TMP/$id"; candidate="$dir/candidate"; input="$dir/input"
    mkdir -p "$input"
    materialize_candidate "$candidate" "$staged_patch" "$unstaged_patch" "$head_sha"
    out="$candidate/target/runs"
    candidate_seal="$(cd "$candidate" && snapshot)"
    [ "$candidate_seal" = "$expected" ] || {
      echo "review-task: materialized candidate for $id does not match handoff seal" >&2
      exit 1
    }
    build_prompt "$input/prompt.md" "$id" "$tool" "$role" "$model" "$effort" "$output" "$expected" "$round"
    binary="$(command -v "$tool" || true)"
    [ -n "$binary" ] || { echo "review-task: $tool executable unavailable" >&2; exit 1; }
    # Each invocation starts a new session: never resume/fork the implementer.
    if [ "$tool" = opencode ]; then
      # OpenCode run rejects subagent-only roles and silently selects build.
      # Make the gate role CLI-selectable for this invocation; keep its denies.
      OPENCODE_CONFIG_CONTENT='{"agent":{"stargate-review":{"mode":"all"}},"provider":{"zai-coding-plan":{"models":{"glm-5.3":{"variants":{"xhigh":{"reasoningEffort":"max"}}}}}},"permission":{"external_directory":"deny","task":"deny"}}' \
        TMPDIR="$dir" setsid "$binary" run "Perform the attached isolated ticket review directly." \
          --auto --pure --dir "$candidate" --agent "$role" --model "$model" --variant "$effort" \
          --file "$input/prompt.md" > "$dir/reviewer.log" 2>&1 &
    else
      TMPDIR="$dir" setsid "$binary" exec -C "$candidate" -s danger-full-access -m "$model" \
        -c "model_reasoning_effort=\"$effort\"" \
        -c shell_environment_policy.inherit=none --ephemeral --ignore-user-config \
        -o "$out/$output" - < "$input/prompt.md" > "$dir/reviewer.log" 2>&1 &
    fi
    REVIEWER_PIDS+=("$!")
    REVIEWER_DIRS+=("$dir")
  done

  local failed=0 pid rc
  for i in "${!REVIEWER_IDS[@]}"; do
    pid="${REVIEWER_PIDS[$i]}"
    if wait "$pid"; then rc=0; else rc=$?; failed=1; fi
    if [ "$rc" -ne 0 ]; then
      echo "review-task: ${REVIEWER_IDS[$i]} failed (rc=$rc)" >&2
      tail -n 40 "${REVIEWER_DIRS[$i]}/reviewer.log" >&2 || true
    fi
  done
  if [ "$failed" -ne 0 ]; then
    echo "review-task: reviewer set failed; no verdicts imported" >&2
    exit 1
  fi

  after="$(snapshot)"
  [ "$after" = "$expected" ] || { echo "review-task: candidate changed during review; discarding verdict set" >&2; exit 1; }
  for i in "${!REVIEWER_IDS[@]}"; do
    dir="${REVIEWER_DIRS[$i]}"; output="${REVIEWER_OUTPUTS[$i]}"
    if [ ! -s "$dir/candidate/target/runs/$output" ] || [ ! -f "$dir/candidate/target/runs/$output" ] || [ -L "$dir/candidate/target/runs/$output" ]; then
      echo "review-task: ${REVIEWER_IDS[$i]} wrote no regular private verdict" >&2
      exit 1
    fi
    if find "$dir/candidate/target/runs" -mindepth 1 -maxdepth 1 ! -name "$output" -print -quit | grep -q .; then
      echo "review-task: ${REVIEWER_IDS[$i]} wrote outside its verdict channel" >&2
      exit 1
    fi
    candidate_seal="$(cd "$dir/candidate" && snapshot)"
    [ "$candidate_seal" = "$expected" ] || {
      echo "review-task: reviewer changed its source copy; rejecting set" >&2
      exit 1
    }
    validate_verdict "$dir/candidate/target/runs/$output" "${REVIEWER_IDS[$i]}" \
      "${REVIEWER_TOOLS[$i]}" "${REVIEWER_MODELS[$i]}" "${REVIEWER_EFFORTS[$i]}" "$expected" "$round"
    cp "$dir/candidate/target/runs/$output" "$ROOT_TMP/$output"
  done

  manifest="$RUN_DIR/$TICKET_ID.review-set"
  rm -f "$manifest"
  for output in "${REVIEWER_OUTPUTS[@]}"; do rm -f "$RUN_DIR/$output"; done
  for output in "${REVIEWER_OUTPUTS[@]}"; do mv "$ROOT_TMP/$output" "$RUN_DIR/$output"; done
  {
    printf 'SNAPSHOT: %s\nROUND: %s\nGATE: review\n' "$expected" "$round"
    for output in "${REVIEWER_OUTPUTS[@]}"; do
      sha256sum "$RUN_DIR/$output" | sed "s#  $RUN_DIR/#  #"
    done
  } > "$ROOT_TMP/review-set"
  mv "$ROOT_TMP/review-set" "$manifest"
  echo "review-task: imported two isolated single-gate verdicts for $TICKET_ID"
}

run_actual
