#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# run-task.sh — the loop driver. Drives one ticket through the workflow
# defined in docs/process/workflow.md, doing the deterministic phases
# directly and emitting structured handoff prompts at the non-deterministic
# phases (which a human or external agent driver then picks up and feeds
# back in).
#
# Why a shell script, not a skill: skills are tool-specific (Claude Code,
# opencode each have their own). The procedure they wrap is universal.
# This script IS that procedure, tool-agnostic. A skill (future /run)
# becomes a thin wrapper: "run scripts/run-task.sh <id> and follow the
# handoff prompts". The infochat/zecsite run.md is the precedent.
#
# State machine (status: → action):
#   pending        → START: emit grounding + clarity prompt; transition to
#                    in-progress on next invocation once the caller confirms.
#   in-progress    → IMPLEMENT (the agent writes code); then VERIFY (run
#                    scripts/verify.sh directly); then transition to
#                    in-review.
#   in-review      → emit single-gate REVIEW handoff prompt; on next
#                    invocation, validate the isolated two-reviewer verdict
#                    set (one pass covers correctness AND security) and act.
#   done           → emit merge handoff (or perform merge directly if
#                    --merge is given).
#   escalated      → REFUSE; surface the menu, stop.
#   deferred       → REFUSE; point at manual reopen.
#
# Round state lives at target/runs/<id>.round (transient, gitignored). The
# ticket file's `status:` field is the source of truth for the phase; the
# round counter is per-cycle, not durable.
#
# Bright-line stops (workflow.md §"Autonomous runs"):
#   - verify.sh not green after a rework round, or not fresh-green at APPROVE
#   - review round cap hit (default 2; 3 if round_cap: 3)
#   - any single-gate reviewer verdict ESCALATE, or REWORK at the shared cap
#     (the gate covers both correctness and security for every ticket);
#     milestone sweeps remain additional checks.
#
# The script NEVER pushes. The script NEVER spawns a developer-subagent
# (there is no portable way to do that from shell; the caller does it).
# Status transitions happen ONLY here.
#
# Branch model (T096 / sol-review M6): direct commits on the feature
# integration branch ($FEATURE_BRANCH, from .specify/feature.json). The
# feature branch squash-merges to main at milestone close (--merge). main has
# no scripts/ mid-feature, so per-ticket branches off main are unbuildable;
# the prior per-ticket commits on the feature branch are grandfathered.
#
# Usage:
#   scripts/run-task.sh T015              # drive ticket T015 one phase forward
#   scripts/run-task.sh --next            # pick lowest runnable id, drive it
#   scripts/run-task.sh T015 --merge      # in done: perform the squash-merge
#   scripts/run-task.sh T015 --reset      # caution: reset round counter

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# --- arg parsing -----------------------------------------------------------
TICKET_ID=""
PICK_NEXT=0
DO_MERGE=0
RESET_ROUND=0
for arg in "$@"; do
  case "$arg" in
    --next)   PICK_NEXT=1 ;;
    --merge)  DO_MERGE=1 ;;
    --reset)  RESET_ROUND=1 ;;
    --*) echo "run-task: unknown flag: $arg" >&2; exit 2 ;;
    # if/then/else (not A && B || C): a second positional is a hard error,
    # not a masked assignment failure (T103 A4 / SC2015).
    *) if [ -z "$TICKET_ID" ]; then TICKET_ID="$arg"
       else echo "run-task: unexpected arg: $arg" >&2; exit 2; fi ;;
  esac
done

if [ "$PICK_NEXT" = "1" ] && [ -z "$TICKET_ID" ]; then
  # Use next-task.sh to pick the lowest-id runnable ticket.
  PICKED="$(bash scripts/next-task.sh --json --count 1 \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['id']) if d else sys.exit(1)" 2>/dev/null || true)"
  if [ -z "$PICKED" ]; then
    echo "run-task: no runnable ticket found." >&2
    exit 1
  fi
  TICKET_ID="$PICKED"
  echo "run-task: --next picked $TICKET_ID"
fi

[ -n "$TICKET_ID" ] || { echo "usage: run-task.sh <T-NNN | --next> [--merge|--reset]" >&2; exit 2; }

# --- locate ticket + feature dir ------------------------------------------
FEATURE_DIR="$(python3 -c '
import json
try:
    cfg = json.load(open(".specify/feature.json"))
    print(cfg.get("feature_directory", "specs/001-tor-route"))
except Exception:
    print("specs/001-tor-route")
' 2>/dev/null || echo "specs/001-tor-route")"

# Canonical branch model (T096 / sol-review M6): direct commits on the
# feature integration branch; the feature branch squash-merges to main at
# milestone close. The feature integration branch name is derived from the
# feature directory basename (specs/001-tor-route -> 001-tor-route). main has
# no scripts/ dir mid-feature, so per-ticket branches off main are unbuildable;
# the 87 prior commits on the feature branch are grandfathered.
FEATURE_BRANCH="$(python3 -c '
import json, os
try:
    cfg = json.load(open(".specify/feature.json"))
    fd = cfg.get("feature_directory", "specs/001-tor-route")
except Exception:
    fd = "specs/001-tor-route"
print(os.path.basename(fd.rstrip("/")))
' 2>/dev/null || echo "001-tor-route")"

# Refuse ambiguous/multiple ticket matches (T096 §Acceptance #2). A bare
# `ls | head -1` silently picks one, which mismatches the canonical "one ticket
# file per id" invariant and can drive the wrong ticket.
shopt -s nullglob
TICKET_MATCHES=( "$FEATURE_DIR/tickets/$TICKET_ID"-*.md )
shopt -u nullglob
case "${#TICKET_MATCHES[@]}" in
  0) echo "run-task: ticket $TICKET_ID not found under $FEATURE_DIR/tickets/" >&2; exit 2 ;;
  1) TICKET_PATH="${TICKET_MATCHES[0]}" ;;
  *) echo "run-task: ambiguous: $TICKET_ID matches ${#TICKET_MATCHES[@]} files:" >&2
     printf '  %s\n' "${TICKET_MATCHES[@]}" >&2
     echo "  rename so '$TICKET_ID' matches exactly one filename." >&2
     exit 2 ;;
esac

# --- frontmatter field extraction (same python helper as the other scripts) -
extract_fm() {
  local key="$1"
  python3 - "$TICKET_PATH" "$key" <<'PY'
import re, sys
path, key = sys.argv[1], sys.argv[2]
txt = open(path).read()
m = re.match(r'^---\n(.*?)\n---\n', txt, re.DOTALL)
fm = m.group(1) if m else ''
for line in fm.splitlines():
    mm = re.match(rf'^{re.escape(key)}:\s*(.*)$', line)
    if mm:
        v = re.sub(r'\s+#.*$', '', mm.group(1)).rstrip().strip("'\"")
        print(v)
        break
PY
}

STATUS="$(extract_fm status)"
PRIVACY="$(extract_fm privacy_critical)"
ROUND_CAP="$(extract_fm round_cap)"
[ -z "$ROUND_CAP" ] && ROUND_CAP=2

# --- round state file -------------------------------------------------------
RUN_DIR="target/runs"
mkdir -p "$RUN_DIR"
REVIEW_MATRIX="scripts/review-matrix.json"
[ -f "$REVIEW_MATRIX" ] || { echo "run-task: missing $REVIEW_MATRIX" >&2; exit 1; }
ROUND_FILE="$RUN_DIR/$TICKET_ID.round"
mapfile -t REVIEW_VERDICT_FILES < <(python3 - "$REVIEW_MATRIX" "$TICKET_ID" "$RUN_DIR" <<'PY'
import json, os, sys
for row in json.load(open(sys.argv[1]))['reviewers']:
    print(os.path.join(sys.argv[3], row['output'].replace('{ticket}', sys.argv[2])))
PY
)
if [ "${#REVIEW_VERDICT_FILES[@]}" -ne 2 ]; then
  echo "run-task: review matrix must define exactly two single-gate reviewers" >&2
  exit 1
fi
REVIEW_SET="$RUN_DIR/$TICKET_ID.review-set"
REVIEW_SNAPSHOT="$RUN_DIR/$TICKET_ID.review-snapshot"
AWF_FILE="$RUN_DIR/$TICKET_ID.awf-applied"      # sentinel: APPROVE-WITH-FIXES items applied (reviewer-prompt.md)
PROMPT_FILE="$RUN_DIR/$TICKET_ID.prompt"

if [ "$RESET_ROUND" = "1" ]; then
  rm -f "$ROUND_FILE" "$REVIEW_SNAPSHOT" "$AWF_FILE" \
    "$REVIEW_SET" "${REVIEW_VERDICT_FILES[@]}"
  # Reset is the documented manual-recovery entry: clear a gate lock stranded
  # by an uncatchable kill. A launcher running right now loses its exclusion —
  # that is the operator's explicit choice, matching the flag's "caution".
  rm -rf "$RUN_DIR/$TICKET_ID.review.lock"
  echo "run-task: reset round state for $TICKET_ID"
  exit 0
fi

# Initialise round counter on first contact.
if [ ! -f "$ROUND_FILE" ]; then
  echo 1 > "$ROUND_FILE"
fi
ROUND="$(cat "$ROUND_FILE")"

# Gate-lock ownership (T142): when THIS process creates the review lock, the
# EXIT/INT/TERM cleanup releases it, so catchable termination inside the
# approval critical section cannot strand the gate for every later launcher
# and driver invocation. A process that failed to acquire the lock never
# owned it and never removes another process's lock.
GATE_LOCK_OWNED=0
gate_lock_cleanup() {
  if [ "$GATE_LOCK_OWNED" = 1 ]; then
    rmdir "$RUN_DIR/$TICKET_ID.review.lock" 2>/dev/null || true
    GATE_LOCK_OWNED=0
  fi
}
trap gate_lock_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- helpers ----------------------------------------------------------------
emit_prompt() {
  # Write a structured handoff prompt to $PROMPT_FILE and to stdout. The
  # caller (a human reading the terminal, or an external agent driver) reads
  # this prompt, does the non-deterministic work, then re-invokes run-task.sh
  # which picks up the result.
  local kind="$1"; shift
  {
    echo "# run-task handoff — $TICKET_ID ($kind, round $ROUND)"
    echo
    cat
    echo
    echo "---"
    echo "_Generated by scripts/run-task.sh. When the work above is done,"
    echo "re-run \`scripts/run-task.sh $TICKET_ID\` to advance to the next phase._"
  } > "$PROMPT_FILE"
  cat "$PROMPT_FILE"
}

# ensure_feature_branch: land the caller on $FEATURE_BRANCH (T096 §Acceptance
# #2). Creates it from main if absent; checks it out if the caller is elsewhere.
# Refuses a dirty working tree (would carry unrelated changes across the
# checkout). The branch name is derived from the feature directory basename,
# reconciling the docs' per-ticket-branch wording to the direct-commits model
# the 87 prior commits already follow.
ensure_feature_branch() {
  if [ -n "$(git status --porcelain)" ]; then
    echo "run-task: working tree dirty. Commit or stash before starting $TICKET_ID." >&2
    exit 1
  fi
  if ! git show-ref --verify --quiet "refs/heads/$FEATURE_BRANCH"; then
    # Feature branch doesn't exist — create it from main. This is the
    # milestone-squash source; per-ticket work commits here directly.
    if ! git show-ref --verify --quiet "refs/heads/main"; then
      echo "run-task: neither '$FEATURE_BRANCH' nor 'main' exists; nothing to branch from." >&2
      exit 1
    fi
    git checkout -b "$FEATURE_BRANCH" main
    echo "run-task: created + checked out feature branch '$FEATURE_BRANCH' from main."
  elif [ "$(git rev-parse --abbrev-ref HEAD)" != "$FEATURE_BRANCH" ]; then
    git checkout "$FEATURE_BRANCH"
    echo "run-task: checked out feature branch '$FEATURE_BRANCH'."
  fi
}

# make_focused_commit: create the one-ticket commit on the feature branch with
# the required Reviewed-by trailer (T096 §Acceptance #3). Commits ONLY paths the
# caller already staged (`git add <paths>` during IMPLEMENT) — never `git add -A`
# and never `-a`, so unrelated edits stay out of the focused commit. Refuses if
# nothing is staged. The message is constructed from the ticket's id/title and
# the §Context body so the invariant holds by construction, not caller discipline.
make_focused_commit() {
  local verdict_line="$1" title ctx
  if [ -z "$(git diff --cached --name-only)" ]; then
    return 1
  fi
  title="$(extract_fm title)"
  ctx="$(python3 - "$TICKET_PATH" <<'PY'
import re, sys
txt = open(sys.argv[1]).read()
m = re.search(r'^## Context\s*\n(.*?)(?=^## |\Z)', txt, re.MULTILINE | re.DOTALL)
body = m.group(1).strip() if m else ''
# Collapse to a flat paragraph for the commit body; drop the leading
# blockquote line-by-line noise bootstrap may have emitted.
lines = [ln.rstrip() for ln in body.splitlines() if ln.strip()]
print('\n'.join(lines) if lines else '(no Context section)')
PY
)"
  git commit -m "Implement ${FEATURE_BRANCH}: ${TICKET_ID} ${title}" \
            -m "${ctx}" \
            -m "${verdict_line}" \
            -m "Marks ${TICKET_ID} [X]."
}

update_ticket_status() {
  # Rewrite the `status:` line in the ticket file. Idempotent. Targeted edit
  # — does NOT regenerate the file or touch the body.
  local new_status="$1"
  python3 - "$TICKET_PATH" "$new_status" <<'PY'
import datetime, re, sys
path, new_status = sys.argv[1], sys.argv[2]
txt = open(path).read()
today = datetime.date.today().isoformat()
# Update status: line.
txt = re.sub(r'^(status:\s*).*$',
             lambda m: m.group(1) + new_status,
             txt, count=1, flags=re.MULTILINE)
# Update last_updated: line.
txt = re.sub(r'^(last_updated:\s*).*$',
             lambda m: m.group(1) + today,
             txt, count=1, flags=re.MULTILINE)
open(path, 'w').write(txt)
PY
  echo "run-task: $TICKET_ID status → $new_status"
  # Regenerate STATUS.md so it stays in sync with the frontmatter we just
  # changed. Best-effort: a regen failure does not block the transition
  # (the next transition or a manual `scripts/regen-status.sh` catches up).
  # This closes the "forgot to regen STATUS.md" drift the CI ticket-state
  # job was catching after the fact.
  bash "$(git rev-parse --show-toplevel)/scripts/regen-status.sh" "$FEATURE_DIR" >/dev/null 2>&1 \
    || echo "run-task: WARNING — regen-status.sh failed; STATUS.md may be stale" >&2
}

# T133/T139: bind approval to the worktree, index, source inventory,
# baseline and HEAD. Both diffs prevent a staged version different from the
# reviewed working copy from borrowing approval.
review_snapshot() {
  python3 - "$RUN_DIR/$TICKET_ID.start-sha" "$ROUND" <<'SNAPSHOT'
import hashlib, os, pathlib, subprocess, sys

def git(*args):
    return subprocess.check_output(['git', *args])

base_file = pathlib.Path(sys.argv[1])
base = base_file.read_text().strip() if base_file.exists() else git('rev-parse', 'HEAD').decode().strip()
parts = [base.encode(), sys.argv[2].encode(), git('rev-parse', 'HEAD'),
         git('diff', '--no-ext-diff', '--binary', base, '--'),
         git('diff', '--no-ext-diff', '--binary', '--cached', base, '--')]
# Ignored build products are outside the candidate; all other new paths are
# source until explicitly staged. NUL delimiting handles unusual filenames.
for name in sorted(filter(None, git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0'))):
    path = pathlib.Path(os.fsdecode(name))
    parts.extend([name, str(path.lstat().st_mode).encode(),
                  os.fsencode(path.readlink()) if path.is_symlink() else path.read_bytes()])
digest = hashlib.sha256()
for part in parts:
    digest.update(len(part).to_bytes(8, 'big'))
    digest.update(part)
print(digest.hexdigest())
SNAPSHOT
}

invalidate_reviews() {
  rm -f "$REVIEW_SET" "$REVIEW_SNAPSHOT" "$AWF_FILE" "$PROMPT_FILE" "${REVIEW_VERDICT_FILES[@]}"
  echo "run-task: reviewed snapshot changed; a fresh single-gate review set is required." >&2
}

any_file_exists() {
  local path
  for path in "$@"; do [ -e "$path" ] && return 0; done
  return 1
}

# Validate the manifest-last import and every reviewer identity independently.
# The strongest verdict wins: ESCALATE > REWORK > APPROVE-WITH-FIXES > APPROVE.
validate_review_set() {
  local manifest="$1" expected="$2"
  shift 2
  python3 - "$REVIEW_MATRIX" "$TICKET_ID" "$manifest" "$expected" "$ROUND" "$@" <<'PY'
import hashlib, json, pathlib, re, sys

matrix_path, ticket, manifest_path, snapshot, round_number, *files = sys.argv[1:]
rows = json.load(open(matrix_path))['reviewers']
expected_names = [r['output'].replace('{ticket}', ticket) for r in rows]
if [pathlib.Path(f).name for f in files] != expected_names:
    raise SystemExit('run-task: reviewer file set does not match review matrix')

manifest = pathlib.Path(manifest_path).read_text()
def one(text, name):
    values = re.findall(r'^' + re.escape(name) + r':[ \t]*(.*)$', text, re.MULTILINE)
    if len(values) != 1:
        raise ValueError(name)
    return values[0].strip()
try:
    if one(manifest, 'SNAPSHOT') != snapshot or one(manifest, 'ROUND') != round_number or one(manifest, 'GATE') != 'review':
        raise ValueError('manifest identity')
except ValueError as exc:
    raise SystemExit(f'run-task: malformed review-set manifest: {exc}')

hash_lines = re.findall(r'^([0-9a-f]{64})  ([^/\n]+)$', manifest, re.MULTILINE)
if [name for _, name in hash_lines] != expected_names:
    raise SystemExit('run-task: review-set manifest has missing, duplicate or unknown files')

priority = {'APPROVE': 0, 'APPROVE-WITH-FIXES': 1, 'REWORK': 2, 'ESCALATE': 3}
verdicts = []
for row, path, (recorded_hash, _) in zip(rows, files, hash_lines):
    data = pathlib.Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != recorded_hash:
        raise SystemExit(f'run-task: review-set hash mismatch: {path}')
    text = data.decode()
    try:
        verdict = one(text, 'VERDICT')
        identities = {'REVIEWER': row['id'], 'TOOL': row['tool'], 'MODEL': row['model'],
                      'EFFORT': row['effort'], 'SNAPSHOT': snapshot, 'ROUND': round_number}
        if verdict not in priority or any(one(text, key) != value for key, value in identities.items()):
            raise ValueError('verdict identity')
        # Single gate: every reviewer is also the security review, so the
        # summary/findings discipline applies to both verdicts.
        if not one(text, 'SUMMARY') or one(text, 'FINDINGS') is None:
            raise ValueError('gate fields')
    except (UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(f'run-task: malformed or mismatched gate verdict {path}: {exc}')
    verdicts.append(verdict)
print(max(verdicts, key=priority.__getitem__))
PY
}

combined_verdicts() {
  local path
  for path in "$@"; do
    printf '%s\n' "--- reviewer verdict: $(basename "$path")"
    cat "$path"
  done
}

review_trailers() {
  python3 - "$REVIEW_MATRIX" "$ROUND" "$@" <<'PY'
import json, re, sys
matrix, round_number, *files = sys.argv[1:]
rows = json.load(open(matrix))['reviewers']
for row, path in zip(rows, files):
    verdicts = re.findall(r'^VERDICT:[ \t]*(.*)$', open(path).read(), re.MULTILINE)
    if len(verdicts) != 1:
        raise SystemExit(f'run-task: cannot record reviewer verdict from {path}')
    print('Reviewed-by: {role} ({id}; {tool}; model {model}; effort {effort}; VERDICT: {verdict}; round {round})'.format(
        role=row['role'], id=row['id'], tool=row['tool'], model=row['model'], effort=row['effort'],
        verdict=verdicts[0].strip(), round=round_number))
PY
}

# Constitution VII/VIII: the review diff must include every intended new
# source, and the budget includes the union of working and staged paths.
# Ignored artifacts stay outside this inventory; intended ignored source must
# be explicitly force-added before review, as documented in workflow.md.
check_inventory() {
  local base
  base="$(cat "$RUN_DIR/$TICKET_ID.start-sha" 2>/dev/null || git rev-parse HEAD)"
  if ! python3 - "$base" "$(extract_fm files_budget)" <<'INVENTORY'
import os, subprocess, sys

def paths(*args):
    return set(filter(None, subprocess.check_output(['git', *args]).split(b'\0')))

untracked = paths('ls-files', '--others', '--exclude-standard', '-z')
changed = (paths('diff', '--name-only', '--no-renames', '-z', sys.argv[1], '--') |
           paths('diff', '--cached', '--name-only', '--no-renames', '-z', sys.argv[1], '--') |
           untracked)
if untracked:
    print('run-task: unstaged new source blocks review/commit; stage intended paths explicitly:', file=sys.stderr)
    for name in sorted(untracked):
        print('  ' + repr(os.fsdecode(name)), file=sys.stderr)
try:
    budget = int(sys.argv[2])
    if budget < 1:
        raise ValueError()
except ValueError:
    sys.exit('run-task: missing or invalid files_budget')
if len(changed) > budget:
    print(f'run-task: {len(changed)} changed paths exceed files_budget={budget}; STOP', file=sys.stderr)
sys.exit(1 if untracked or len(changed) > budget else 0)
INVENTORY
  then
    invalidate_reviews
    return 1
  fi
}

# Principle VII: only privacy-critical implementation tickets need a new
# red/green record. A declared test_for ticket is independently deliverable
# test work; its implementation ticket carries the later failing probe.
check_test_first_evidence() {
  [ "$PRIVACY" = true ] || return 0
  local test_for
  test_for="$(extract_fm test_for)"
  if [ -n "$test_for" ] && [ "$test_for" != '[]' ]; then return 0; fi
  python3 scripts/test-first-evidence.py check "$TICKET_ID"
}

# --- dispatch on status -----------------------------------------------------
case "$STATUS" in

  pending)
    # Phase: START. Ground + clarity pre-flight. The agent should:
    #   1. Read the full ticket file.
    #   2. Read every cited spec_refs / decision_refs / constitution_refs anchor.
    #   3. Verify any module/path the acceptance names resolves on disk.
    #   4. (privacy_critical OR complexity:high) Build the analyze property map.
    #   5. (complexity:high) Spawn plan-writer for an outline sidecar.
    #   6. Run scripts/lint-ticket.py as the mechanical clarity pre-flight.
    # When the caller confirms grounding is done, they re-invoke run-task.sh;
    # we transition to in-progress on that next invocation by checking for a
    # sentinel file (so the human / agent driver controls the actual start).

    # Gather cited refs ahead of the heredoc so we interpolate them in one shot.
    REFS_BLOCK=""
    for ref_kind in spec_refs decision_refs constitution_refs; do
      refs="$(python3 - "$TICKET_PATH" "$ref_kind" <<'PY'
import re, sys
path, key = sys.argv[1], sys.argv[2]
txt = open(path).read()
m = re.match(r'^---\n(.*?)\n---\n', txt, re.DOTALL)
fm = m.group(1) if m else ''
lines = fm.splitlines()
i = 0
while i < len(lines):
    mm = re.match(rf'^{re.escape(key)}:\s*(.*)$', lines[i])
    if mm:
        rest = re.sub(r'\s+#.*$', '', mm.group(1)).strip()
        if rest.startswith('['):
            inner = rest.strip('[]').strip()
            if inner:
                for v in inner.split(','):
                    print('   - ' + v.strip().strip("'\""))
        elif rest == '':
            j = i + 1
            while j < len(lines) and re.match(r'^\s+-\s+', lines[j]):
                print('   - ' + re.sub(r'^\s+-\s+', '', lines[j]).strip().strip("'\""))
                j += 1
        else:
            print('   - ' + rest.strip("'\""))
        break
    i += 1
PY
)"
      [ -n "$refs" ] && REFS_BLOCK="${REFS_BLOCK}${refs}
"
    done
    [ -z "$REFS_BLOCK" ] && REFS_BLOCK="   (no spec_refs / decision_refs / constitution_refs cited — fill these in if the ticket names anchors.)"

    cat <<EOF | emit_prompt START
Ground on $TICKET_ID BEFORE any code change (workflow.md §"The flow" step 1):

1. Read the full ticket: \`$TICKET_PATH\`
2. Read every cited anchor:
${REFS_BLOCK}
3. Verify any module/path the acceptance names resolves on disk (Glob / ls).
4. Analyze gate (docs/process/analysis.md, planned):
$([ "$PRIVACY" = "true" ] && echo "   - REQUIRED (\`privacy_critical: true\`): build the property map (must-hold / gated / residue)." || echo "   - Quick pass; omit unless complexity: high.")
5. Mechanical clarity pre-flight: \`python3 scripts/lint-ticket.py $TICKET_PATH\`
6. When grounding is complete and clarity is PASS/WARN, signal ready:
   touch target/runs/$TICKET_ID.grounded

EOF
    if [ ! -f "target/runs/$TICKET_ID.grounded" ]; then
      echo "run-task: $TICKET_ID emitted START handoff. Ground, then re-invoke."
      exit 0
    fi
    # Caller signalled ready — land on the feature integration branch
    # (creating it from main if absent) BEFORE flipping status, so an
    # in-progress ticket always has its commit target ready (T096 §Acceptance
    # #2). Dirty tree refusal happens inside ensure_feature_branch.
    ensure_feature_branch
    rm -f "target/runs/$TICKET_ID.grounded"
    # Pin the review baseline: everything this ticket changes (mid-ticket
    # grounding commits included) diffs against this SHA, and the REVIEW
    # mechanical report derives its counts from it.
    git rev-parse HEAD > "$RUN_DIR/$TICKET_ID.start-sha" 2>/dev/null || true
    update_ticket_status "in-progress"
    echo "run-task: $TICKET_ID ready to implement on '$FEATURE_BRANCH'. Re-invoke to advance."
    exit 0
    ;;

  in-progress)
    # Phase: IMPLEMENT → VERIFY.
    # If verify.sh is already green (target/verify.log fresh since last
    # edit) we transition to in-review. Otherwise we emit an implement
    # handoff and ask the caller to write code + run verify.sh.
    cat <<EOF | emit_prompt IMPLEMENT
Implement $TICKET_ID (workflow.md §"The flow" steps 2–3):

1. Read the ticket's §Acceptance — this is the only section that pins behavior.
2. For privacy_critical=$PRIVACY tasks, tests MUST be written first
   (Constitution Principle VII, no AI exception): the test must exist and be
   failing before the implementation lands.
3. Surgical changes only, within files_budget=$(extract_fm files_budget).
   Stay outside out_of_scope.
   Privacy-critical implementation: after the spec-derived test fails, run
   \`python3 scripts/test-first-evidence.py red $TICKET_ID -- <test command>\`.
   After the fix passes, run the same tool with \`green\` before staging its
   evidence JSON. Inspect the recorded output for secrets before staging.
4. When the diff is ready, run from repo root:
   bash scripts/verify.sh
5. Verify must be GREEN. Fix the code, never the test, unless the ticket's
   §Out-of-scope authorized that test change.
6. **Stage the ticket's changed paths** (explicit paths only — never \`git add -A\`;
   the driver commits ONLY what you stage, at APPROVE):
   git add <path1> <path2> ... $TICKET_PATH
7. When verify is green and the paths are staged, signal ready:
   touch target/runs/$TICKET_ID.verified

EOF
    if [ ! -f "target/runs/$TICKET_ID.verified" ]; then
      echo "run-task: $TICKET_ID emitted IMPLEMENT handoff. Code + verify, then re-invoke."
      exit 0
    fi
    rm -f "target/runs/$TICKET_ID.verified"
    check_inventory || exit 1
    check_test_first_evidence || exit 1

    # Also run verify.sh directly as the safety re-check (workflow.md step 3).
    echo "run-task: re-running scripts/verify.sh as the pre-review gate…"
    if bash scripts/verify.sh >> target/verify.log 2>&1; then
      check_inventory || exit 1
      echo "run-task: GREEN. Transitioning $TICKET_ID to in-review."
      update_ticket_status "in-review"
    else
      echo "run-task: verify.sh NOT GREEN after the caller signalled verified." >&2
      echo "  The tree changed between the caller's verify and this one. Re-implement." >&2
      exit 1
    fi
    exit 0
    ;;

  in-review)
    check_inventory || exit 1
    check_test_first_evidence || exit 1
    # Phase: emit the single-gate REVIEW handoff OR act on the manifest-complete
    # reviewer set. One pass covers correctness AND adversarial security review.
    if [ ! -f "$REVIEW_SET" ]; then
      if any_file_exists "${REVIEW_VERDICT_FILES[@]}"; then
        echo "run-task: incomplete review set; a legacy or partial verdict cannot advance $TICKET_ID" >&2
        invalidate_reviews
        exit 1
      fi
      # Mechanical report (reviewer-prompt.md §Inputs): script-computed facts
      # the reviewer must trust over its own counting. Contents are data, not
      # templates — interpolating them is safe; nothing here is re-evaluated.
      BASE_SHA="$(cat "$RUN_DIR/$TICKET_ID.start-sha" 2>/dev/null || git rev-parse HEAD)"
      # Every probe below is best-effort: under `set -euo pipefail` a failing
      # command substitution would abort the whole driver silently, so each
      # pipeline ends in an explicit fallback.
      STAT_LINE="$( (git diff "$BASE_SHA" --stat 2>/dev/null | tail -1) || echo 'unknown')"
      FILES_TOUCHED="$(python3 - "$BASE_SHA" <<'COUNT'
import subprocess, sys
def paths(*args):
    return set(filter(None, subprocess.check_output(['git', *args]).split(b'\0')))
print(len(paths('diff', '--name-only', '--no-renames', '-z', sys.argv[1], '--') |
          paths('diff', '--cached', '--name-only', '--no-renames', '-z', sys.argv[1], '--')))
COUNT
)"
      BUDGET="$(extract_fm files_budget)"
      BUDGET_VERDICT="within budget"
      if [ -n "$FILES_TOUCHED" ] && [ -n "$BUDGET" ] && [ "$FILES_TOUCHED" -gt "$BUDGET" ]; then
        BUDGET_VERDICT="OVER BUDGET (bright-line: STOP)"
      fi
      VERIFY_FRESH="$( (stat -c '%y' target/verify.log 2>/dev/null | cut -d. -f1) || true)"
      VERIFY_RESULT="$( (grep '^RESULT:' target/verify.log 2>/dev/null | tail -1) || true)"
      OOS_BLOCK="$( (sed -n '/^## Out-of-scope/,/^## /p' "$TICKET_PATH" | sed '1d;$d' | sed '/^$/d' | head -12) || true)"
      PRIOR_BLOCK=""
      if [ "$ROUND" -ge 2 ] && [ -f "$RUN_DIR/$TICKET_ID-r$((ROUND-1)).verdict" ]; then
        PRIOR_BLOCK="$(cat "$RUN_DIR/$TICKET_ID-r$((ROUND-1)).verdict"
printf '%s\n' "--- end of prior verdict — you MUST run the round-disposition protocol over every item above")"
      fi
      REPORT_BLOCK="diff base:     $BASE_SHA   (git diff <base> is the review scope)
diffstat:      ${STAT_LINE:-unknown}
files touched: ${FILES_TOUCHED:-unknown} of files_budget=${BUDGET:-?} → $BUDGET_VERDICT
verify.log:    last written ${VERIFY_FRESH:-unknown} — ${VERIFY_RESULT:-no RESULT line yet}
out-of-scope (ticket §Out-of-scope, abridged):
$(printf '%s' "$OOS_BLOCK" | sed 's/^/  /')"
      [ -n "$PRIOR_BLOCK" ] && REPORT_BLOCK="$REPORT_BLOCK
prior round verdict (items + EVALUATED-AS probes):
$(printf '%s' "$PRIOR_BLOCK" | sed 's/^/  /')"
      review_snapshot > "$REVIEW_SNAPSHOT"
      cat <<EOF | emit_prompt REVIEW
Run the single-gate reviewer set against $TICKET_ID (workflow.md §"The flow" step 4):

  scripts/review-task.sh $TICKET_ID

ONE invocation, ONE pass: the launcher creates two separate fresh-context
native CLI sessions (one OpenCode GLM 5.3 and one Codex Astra), each blind to
your rationale and peer verdicts, each covering correctness AND adversarial
security/privacy in the same pass. It gives each:
  - The diff:    \`git diff $BASE_SHA\`
  - Staged commit content: \`git diff --cached $BASE_SHA\`
  - The ticket:  \`$TICKET_PATH\`

MECHANICAL REPORT (script-computed — the reviewer trusts these numbers over
its own counting and flags any mismatch as suspect input, not a finding):
$REPORT_BLOCK
Source snapshot: $(cat "$REVIEW_SNAPSHOT")

Each reviewer writes only its own private verdict channel. The launcher
validates and imports both with a manifest written last. Every verdict
includes these fields exactly once, copying this handoff's identity:
  VERDICT: APPROVE | APPROVE-WITH-FIXES | REWORK | ESCALATE
  REVIEWER: <matrix id>
  TOOL: <matrix tool>
  MODEL: <matrix model>
  EFFORT: <matrix effort>
  SNAPSHOT: $(cat "$REVIEW_SNAPSHOT")
  ROUND: $ROUND
  SUMMARY: <one line>
  FINDINGS: <severity, file:line, attack path, falsification attempt, fix probe>
Do not launch either CLI manually and do not transcribe a verdict. The
launcher fails closed instead of falling back to the live checkout. After it
reports both imports, re-invoke: scripts/run-task.sh $TICKET_ID

EOF
      echo "run-task: $TICKET_ID emitted REVIEW handoff. Run the single-gate reviewer set, then re-invoke."
      exit 0
    fi

    if [ ! -f "$REVIEW_SNAPSHOT" ] || [ "$(review_snapshot)" != "$(cat "$REVIEW_SNAPSHOT")" ]; then
      invalidate_reviews
      exit 1
    fi

    # A delayed reviewer can finish after a newer handoff was emitted. Bind
    # the manifest and all responses to source, round and configured identity.
    if ! GATE_VERDICT="$(validate_review_set "$REVIEW_SET" \
      "$(cat "$REVIEW_SNAPSHOT")" "${REVIEW_VERDICT_FILES[@]}")"; then
      invalidate_reviews
      exit 1
    fi
    VERDICT_BODY="$(combined_verdicts "${REVIEW_VERDICT_FILES[@]}")"
    # Archive per round: the NEXT round's reviewer needs this round's
    # FINDINGS + EVALUATED-AS probes to run the disposition protocol
    # (reviewer-prompt.md §"Round disposition"). Diffstats alone can't
    # carry rework items.
    printf '%s\n' "$VERDICT_BODY" > "$RUN_DIR/$TICKET_ID-r${ROUND}.verdict"
    # APPROVE-WITH-FIXES (reviewer-prompt.md §Verdict): comment/doc-only FIX
    # ITEMS applied without burning a review round. Fail-closed via sentinel:
    # first sight emits APPLY-FIXES; only after the caller applies exactly the
    # listed items, re-verifies GREEN, and touches $AWF_FILE does this fall
    # through to the normal APPROVE path below if the snapshot is unchanged.
    # Actual source corrections invalidate it above and require refreshed
    # review in the same round (Constitution VIII / workflow.md).
    if [ "$GATE_VERDICT" = APPROVE-WITH-FIXES ]; then
      if [ ! -f "$AWF_FILE" ]; then
        cat <<EOF | emit_prompt APPLY-FIXES
$TICKET_ID verdict set is APPROVE-WITH-FIXES. Apply ONLY the FIX ITEMS listed
in these reviewer-written files — verbatim, nothing else:
$(printf '  %s\n' "${REVIEW_VERDICT_FILES[@]}")
  - Comment/doc lines only, inside files already changed by this ticket's diff.
  - Zero executable-line changes. An item that needs one was mis-tiered by the
    reviewer: STOP and surface; do not apply it and do not edit the verdict.
Then:
  bash scripts/verify.sh                    # must be GREEN
  touch target/runs/$TICKET_ID.awf-applied  # signal fixes applied
  scripts/run-task.sh $TICKET_ID            # changed snapshot requests fresh review in this round

EOF
        echo "run-task: $TICKET_ID emitted APPLY-FIXES handoff. Apply fix items, re-invoke."
        exit 0
      fi
    fi
    if [ "$GATE_VERDICT" = APPROVE ] || [ "$GATE_VERDICT" = APPROVE-WITH-FIXES ]; then
      # --- T096 §Acceptance #3: APPROVE is fail-closed. The driver may not
      # flip `done` until (a) verify is fresh-green, (b) the complete gate
      # verdict set approves (the files we're holding), and (c) a focused
      # commit with the required Reviewed-by trailers exists. The driver
      # creates the commit itself so the invariant holds by construction.
      echo "run-task: APPROVE received. Re-running verify.sh as the freshness gate…"
      if ! bash scripts/verify.sh >> target/verify.log 2>&1; then
        echo "run-task: verify.sh NOT GREEN at APPROVE. Tree changed post-review. Re-implement." >&2
        invalidate_reviews
        exit 1
      fi
      check_inventory || exit 1
      check_test_first_evidence || exit 1
      if [ "$(review_snapshot)" != "$(cat "$REVIEW_SNAPSHOT")" ]; then
        invalidate_reviews
        exit 1
      fi
      # Serialize approval consumption with the launcher through the same gate
      # lock review-task.sh uses: whoever holds <id>.review.lock owns the
      # review-set state. A launcher that finished before this point is what
      # the final validation below reads; a launcher still running (or
      # starting now) fails closed on the other side of the mkdir. Without
      # this critical section, set retirement could land between validation
      # and git commit (Constitution VIII).
      if ! mkdir "$RUN_DIR/$TICKET_ID.review.lock" 2>/dev/null; then
        echo "run-task: a review set is being (re)launched for $TICKET_ID; refusing to consume approval concurrently. Re-invoke after it finishes." >&2
        exit 1
      fi
      GATE_LOCK_OWNED=1
      # A concurrent review-task.sh may have retired or replaced the approved
      # set while verification ran (target/ is gitignored, so the snapshot
      # above cannot see it). The commit consumes the set that exists under
      # the lock, never the verdict cached before it.
      if ! GATE_FINAL="$(validate_review_set "$REVIEW_SET" \
        "$(cat "$REVIEW_SNAPSHOT")" "${REVIEW_VERDICT_FILES[@]}")"; then
        echo "run-task: approved review set was replaced during final verification; refusing commit." >&2
        invalidate_reviews
        exit 1
      fi
      if [ "$GATE_FINAL" != "$GATE_VERDICT" ]; then
        echo "run-task: review set changed during final verification ($GATE_VERDICT -> $GATE_FINAL); refusing commit." >&2
        invalidate_reviews
        exit 1
      fi

      # Create the focused commit on the feature branch with the required
      # Reviewed-by trailer. The caller staged paths during IMPLEMENT; we
      # commit only those. If nothing is staged, surface a COMMIT handoff
      # rather than flipping done (the commit invariant is the gate).
      REVIEW_LINE="$(review_trailers "${REVIEW_VERDICT_FILES[@]}")"
      if ! make_focused_commit "$REVIEW_LINE"; then
        cat <<EOF | emit_prompt COMMIT
$TICKET_ID was APPROVED but no changes are staged for the focused commit
(T096 §Acceptance #3 — done requires a focused commit with the Reviewed-by
trailer). Stage the ticket's paths explicitly (never \`git add -A\`):

  git add <path1> <path2> ... $TICKET_PATH

Then re-invoke: scripts/run-task.sh $TICKET_ID
The driver will create the commit and flip \`done\`.

EOF
        echo "run-task: $TICKET_ID emitted COMMIT handoff. Stage paths, re-invoke."
        # Keep the review set so re-invocation proceeds straight to commit;
        # the EXIT trap releases the gate lock so a launch is not blocked.
        exit 0
      fi

      # Stash the verdict into the ticket's reviews: field (latest only).
      python3 - "$TICKET_PATH" "$ROUND" "$VERDICT_BODY" <<'PY'
import datetime, re, sys
path, round, verdict = sys.argv[1], sys.argv[2], sys.argv[3]
today = datetime.date.today().isoformat()
txt = open(path).read()
# Replace the reviews: {...} block with the latest entry.
new = f"reviews: {{ round: {round}, date: {today}, verdict: APPROVE }}"
txt = re.sub(r'^reviews:\s*\{[^}]*\}\s*$', new, txt, count=1, flags=re.MULTILINE)
open(path, 'w').write(txt)
PY
      update_ticket_status "done"
      rm -f "$REVIEW_SET" "$REVIEW_SNAPSHOT" "$AWF_FILE" "${REVIEW_VERDICT_FILES[@]}"
      echo "run-task: $TICKET_ID done (committed on '$FEATURE_BRANCH')."
      echo "  Push is your call: git push origin $FEATURE_BRANCH"
      echo "  Milestone squash-merge to main: scripts/run-task.sh $TICKET_ID --merge"
      exit 0
    fi

    if [ "$GATE_VERDICT" = ESCALATE ]; then
      echo "run-task: ESCALATE on $TICKET_ID (round $ROUND). Surfacing menu." >&2
      update_ticket_status "escalated"
      cat >&2 <<EOF

$VERDICT_BODY

---

Escalation menu (workflow.md §"Escalation menu"). The user decides; the
agent never picks. Reply with one of:

  1. refine     — acceptance was ambiguous; rewrite the ticket, restart from pending
  2. override   — reviewer was too strict; record why and approve
  3. decompose  — split into smaller tickets; defer this one
  4. defer      — blocked on new work; file the blocker, pause this one
  5. amend      — the spec or Constitution itself is wrong (amend-spec / amend-constitution)

To resume after a refine/override, edit the ticket file accordingly, run
\`scripts/run-task.sh $TICKET_ID --reset\`, then re-invoke.
EOF
      exit 1
    fi

    # REWORK.
    if [ "$ROUND" -ge "$ROUND_CAP" ]; then
      echo "run-task: REWORK round $ROUND = cap ($ROUND_CAP) on $TICKET_ID. Escalating." >&2
      update_ticket_status "escalated"
      # Preserve the reviewer reports and manifest for the human decision.
      exit 1
    fi

    # Bump round counter, transition back to in-progress for the rework.
    # Clear the consumed set silently — invalidate_reviews' "snapshot changed"
    # message would misreport this deliberate round transition.
    ROUND=$((ROUND + 1))
    echo "$ROUND" > "$ROUND_FILE"
    rm -f "$REVIEW_SET" "$REVIEW_SNAPSHOT" "$AWF_FILE" "$PROMPT_FILE" "${REVIEW_VERDICT_FILES[@]}"
    update_ticket_status "in-progress"
    cat <<EOF

run-task: REWORK round $ROUND for $TICKET_ID. Address ONLY the named items
in the verdict below; do not re-architect. Re-run scripts/verify.sh, then
re-invoke this script.

$VERDICT_BODY

EOF
    exit 0
    ;;

  done)
    if [ "$DO_MERGE" = "1" ]; then
      # T096 §Acceptance #4: milestone squash-merge of the recorded feature
      # branch into main. Targets $FEATURE_BRANCH by NAME (never guesses from
      # the caller's current branch), refuses a dirty tree, refuses an absent
      # feature branch, and never pushes. Per-ticket work already committed on
      # the feature branch at APPROVE; this is the milestone-end step.
      if [ -n "$(git status --porcelain)" ]; then
        echo "run-task: working tree dirty. Commit or stash before --merge." >&2
        exit 1
      fi
      if ! git show-ref --verify --quiet "refs/heads/$FEATURE_BRANCH"; then
        echo "run-task: feature branch '$FEATURE_BRANCH' does not exist. Nothing to merge." >&2
        exit 1
      fi
      if ! git show-ref --verify --quiet "refs/heads/main"; then
        echo "run-task: 'main' does not exist. Create it before the milestone merge." >&2
        exit 1
      fi
      # Count commits being folded in (for the milestone message).
      NCOMMITS="$(git rev-list --count main.."${FEATURE_BRANCH}" 2>/dev/null || echo 0)"
      if [ "${NCOMMITS:-0}" -eq 0 ]; then
        echo "run-task: '$FEATURE_BRANCH' has no commits ahead of main. Nothing to merge." >&2
        exit 0
      fi
      echo "run-task: milestone squash-merge of '$FEATURE_BRANCH' (${NCOMMITS} commits) into main…"
      git checkout main
      if git merge --squash "$FEATURE_BRANCH"; then
        # T105: capture the milestone commit's rc and confirm main actually
        # advanced. The `&& _crc=0 || _crc=$?` form tests the exit so the
        # script's `set -e` does not abort before we can fail-closed. Without
        # this, a failed/hollow `git commit` (hook rejection, nothing staged,
        # transient fs failure under load) would fall through to the "merge
        # complete" echo and exit 0 with NO commit on main — a silent fail-open
        # in the milestone gate. Stay on main + keep staged changes on failure
        # so the operator can inspect/resolve; never claim success unearned.
        _pre="$(git rev-parse main)"
        git commit -m "Merge ${FEATURE_BRANCH}: milestone squash (${NCOMMITS} ticket commits)" \
                   -m "Squash-merges ${NCOMMITS} reviewed per-ticket commits from ${FEATURE_BRANCH}." \
                   -m "Generated by scripts/run-task.sh ${TICKET_ID} --merge at milestone close." \
                   && _crc=0 || _crc=$?
        _post="$(git rev-parse main)"
        if [ "${_crc:-1}" -ne 0 ] || [ "$_pre" = "$_post" ]; then
          echo "run-task: milestone squash commit did not land on main (commit rc=${_crc}, pre=${_pre} post=${_post}). Staged changes left on main for manual resolution; you are on main." >&2
          exit 1
        fi
        # The feature branch is NOT deleted: under the direct-commits model it
        # remains the active integration branch; deletion is the user's call.
        git checkout "$FEATURE_BRANCH" 2>/dev/null || true
        echo "run-task: milestone merge complete. main now carries ${FEATURE_BRANCH}."
        echo "  Push is your call (never auto-push): git push origin main"
      else
        echo "run-task: squash-merge conflicted. Resolve, or rebase $FEATURE_BRANCH onto main and retry." >&2
        git merge --abort 2>/dev/null || true
        git checkout "$FEATURE_BRANCH" 2>/dev/null || true
        exit 1
      fi
      exit 0
    fi

    cat <<EOF | emit_prompt MERGE
$TICKET_ID is done — its focused commit landed on '$FEATURE_BRANCH' at APPROVE
(T096 §Acceptance #3). Next steps:

  - Push the ticket commit (your call — the script never pushes):
      git push origin $FEATURE_BRANCH
  - Milestone squash-merge of the whole feature branch into main (run once,
    at milestone close):
      scripts/run-task.sh $TICKET_ID --merge

The milestone merge targets '$FEATURE_BRANCH' by name (never guesses from your
current branch), refuses a dirty tree, reuses a generated milestone message,
and never pushes.

EOF
    exit 0
    ;;

  escalated)
    echo "run-task: $TICKET_ID is escalated. The escalation menu is open." >&2
    echo "  Resolve via the five-way menu (workflow.md §\"Escalation menu\")," >&2
    echo "  edit the ticket file accordingly, then:" >&2
    echo "    scripts/run-task.sh $TICKET_ID --reset" >&2
    echo "    scripts/run-task.sh $TICKET_ID" >&2
    exit 1
    ;;

  deferred)
    echo "run-task: $TICKET_ID is deferred. Reopen manually once the blocker resolves:" >&2
    echo "  - flip status: deferred → pending in $TICKET_PATH" >&2
    echo "  - clear deferred_on: / deferred_reason: if applicable" >&2
    echo "  - scripts/run-task.sh $TICKET_ID --reset && scripts/run-task.sh $TICKET_ID" >&2
    exit 1
    ;;

  *)
    echo "run-task: unknown status '$STATUS' for $TICKET_ID." >&2
    exit 2
    ;;

esac
