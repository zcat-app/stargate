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
#   in-review      → emit codereview handoff prompt; on next invocation,
#                    parse the verdict the caller wrote to
#                    target/runs/<id>.verdict and act on it.
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
#   - codereview verdict ESCALATE
#   - independent redteam REWORK at the shared cap, or ESCALATE
#     (privacy-critical tickets); milestone sweeps remain additional checks.
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
ROUND_FILE="$RUN_DIR/$TICKET_ID.round"
DIFFSTAT_FILE="$RUN_DIR/$TICKET_ID-r$([ -f "$ROUND_FILE" ] && cat "$ROUND_FILE" || echo 1).diffstat"
VERDICT_FILE="$RUN_DIR/$TICKET_ID.verdict"      # codereview verdict (APPROVE|APPROVE-WITH-FIXES|REWORK|ESCALATE)
REDTEAM_FILE="$RUN_DIR/$TICKET_ID.redteam.verdict"
REDTEAM_SNAPSHOT="$RUN_DIR/$TICKET_ID.redteam-snapshot"
CODE_SNAPSHOT="$RUN_DIR/$TICKET_ID.code-snapshot"
AWF_FILE="$RUN_DIR/$TICKET_ID.awf-applied"      # sentinel: APPROVE-WITH-FIXES items applied (reviewer-prompt.md)
PROMPT_FILE="$RUN_DIR/$TICKET_ID.prompt"

if [ "$RESET_ROUND" = "1" ]; then
  rm -f "$ROUND_FILE" "$VERDICT_FILE" "$DIFFSTAT_FILE" "$REDTEAM_FILE" "$REDTEAM_SNAPSHOT" "$CODE_SNAPSHOT" "$AWF_FILE"
  echo "run-task: reset round state for $TICKET_ID"
  exit 0
fi

# Initialise round counter on first contact.
if [ ! -f "$ROUND_FILE" ]; then
  echo 1 > "$ROUND_FILE"
fi
ROUND="$(cat "$ROUND_FILE")"

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
# baseline, HEAD and (for redteam) codereview output. Both diffs prevent a staged
# version different from the reviewed working copy from borrowing approval.
review_snapshot() {
  python3 - "$RUN_DIR/$TICKET_ID.start-sha" "$ROUND" "${1:-$VERDICT_FILE}" <<'SNAPSHOT'
import hashlib, os, pathlib, subprocess, sys

def git(*args):
    return subprocess.check_output(['git', *args])

base_file = pathlib.Path(sys.argv[1])
base = base_file.read_text().strip() if base_file.exists() else git('rev-parse', 'HEAD').decode().strip()
parts = [base.encode(), sys.argv[2].encode(), git('rev-parse', 'HEAD'),
         git('diff', '--no-ext-diff', '--binary', base, '--'),
         git('diff', '--no-ext-diff', '--binary', '--cached', base, '--')]
if sys.argv[3] != 'source-only':
    parts.append(pathlib.Path(sys.argv[3]).read_bytes())
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
  rm -f "$VERDICT_FILE" "$REDTEAM_FILE" "$REDTEAM_SNAPSHOT" "$CODE_SNAPSHOT" "$AWF_FILE" "$PROMPT_FILE"
  echo "run-task: reviewed snapshot changed; fresh codereview and redteam required." >&2
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
4. When the diff is ready, run from repo root:
   bash scripts/verify.sh
5. Verify must be GREEN. Fix the code, never the test, unless the ticket's
   §Out-of-scope authorized that test change.
6. **Stage the ticket's changed paths** (explicit paths only — never \`git add -A\`;
   the driver commits ONLY what you stage, at APPROVE):
   git add <path1> <path2> ... $TICKET_PATH
7. When verify is green and the paths are staged, signal ready:
   touch target/runs/$TICKET_ID.verified

Diff stats will be captured on transition to in-review for the must-shrink
check on round ≥2.

EOF
    if [ ! -f "target/runs/$TICKET_ID.verified" ]; then
      echo "run-task: $TICKET_ID emitted IMPLEMENT handoff. Code + verify, then re-invoke."
      exit 0
    fi
    rm -f "target/runs/$TICKET_ID.verified"
    check_inventory || exit 1

    # Capture diff stat for must-shrink on later rounds. Scoped to the
    # ticket's base SHA (branch-wide `git diff main` would count every
    # sibling ticket's work too).
    BASE_SHA="$(cat "$RUN_DIR/$TICKET_ID.start-sha" 2>/dev/null || true)"
    [ -n "$BASE_SHA" ] || BASE_SHA="$(git rev-parse HEAD)"
    git diff "$BASE_SHA" --stat > "$DIFFSTAT_FILE" 2>/dev/null || true
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
    # Phase: emit codereview handoff OR act on the verdict the caller wrote.
    if [ ! -f "$VERDICT_FILE" ]; then
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
      review_snapshot source-only > "$CODE_SNAPSHOT"
      cat <<EOF | emit_prompt REVIEW
Spawn \`stargate-codereview\` against $TICKET_ID (workflow.md §"The flow" step 4).

The reviewer runs FRESH CONTEXT, blind to your rationale. Hand it ONLY:
  - The diff:    \`git diff $BASE_SHA\`
  - Staged commit content: \`git diff --cached $BASE_SHA\`
  - The ticket:  \`$TICKET_PATH\`

MECHANICAL REPORT (script-computed — the reviewer trusts these numbers over
its own counting and flags any mismatch as suspect input, not a finding):
$REPORT_BLOCK
Source snapshot: $(cat "$CODE_SNAPSHOT")

The reviewer WRITES ITS OWN VERDICT (Write tool) to:
  $VERDICT_FILE
Include each of these fields exactly once, copying this handoff's identity:
  VERDICT: APPROVE | APPROVE-WITH-FIXES | REWORK | ESCALATE
  SNAPSHOT: $(cat "$CODE_SNAPSHOT")
  ROUND: $ROUND
…BEFORE its reply; its chat reply is only a short stub (verdict + finding
count). You do NOT transcribe, edit, or reformat the verdict. When the file
exists, just re-invoke: scripts/run-task.sh $TICKET_ID
If the reviewer finished without writing the file, that is a failed review —
re-spawn it; do not write the verdict yourself.
$([ "$PRIVACY" = "true" ] && printf '%s\n' "" "NOTE: privacy_critical=true — after codereview approval the root caller dispatches independent redteam; both approvals are required before commit." )

EOF
      echo "run-task: $TICKET_ID emitted REVIEW handoff. Spawn codereview, write verdict, re-invoke."
      exit 0
    fi

    if [ ! -f "$CODE_SNAPSHOT" ] || [ "$(review_snapshot source-only)" != "$(cat "$CODE_SNAPSHOT")" ]; then
      invalidate_reviews
      exit 1
    fi

    if [ -f "$REDTEAM_SNAPSHOT" ] && [ "$(review_snapshot)" != "$(cat "$REDTEAM_SNAPSHOT")" ]; then
      invalidate_reviews
      exit 1
    fi

    # Verdict is in — act on it.
    VERDICT_BODY="$(cat "$VERDICT_FILE")"
    # A delayed reviewer can finish after a newer handoff was emitted. Bind
    # the response itself, not only the stored request, to source and round.
    if ! CODE_VERDICT="$(python3 - "$VERDICT_FILE" "$(cat "$CODE_SNAPSHOT")" "$ROUND" <<'VERDICT'
import re, sys
text = open(sys.argv[1]).read()
def field(name):
    values = re.findall(r'^' + name + r':[ \t]*(.*)$', text, re.MULTILINE)
    if len(values) != 1:
        raise ValueError(name)
    return values[0].strip()
try:
    verdict = field('VERDICT')
    if (verdict not in ('APPROVE', 'APPROVE-WITH-FIXES', 'REWORK', 'ESCALATE')
            or field('SNAPSHOT') != sys.argv[2] or field('ROUND') != sys.argv[3]):
        raise ValueError('invalid verdict identity')
except ValueError:
    sys.exit('run-task: malformed or mismatched codereview verdict; fresh review required')
print(verdict)
VERDICT
)"; then
      invalidate_reviews
      exit 1
    fi
    # Archive per round: the NEXT round's reviewer needs this round's
    # FINDINGS + EVALUATED-AS probes to run the disposition protocol
    # (reviewer-prompt.md §"Round disposition"). Diffstats alone can't
    # carry rework items.
    cp "$VERDICT_FILE" "$RUN_DIR/$TICKET_ID-r${ROUND}.verdict" 2>/dev/null || true
    # APPROVE-WITH-FIXES (reviewer-prompt.md §Verdict): comment/doc-only FIX
    # ITEMS applied without burning a review round. Fail-closed via sentinel:
    # first sight emits APPLY-FIXES; only after the caller applies exactly the
    # listed items, re-verifies GREEN, and touches $AWF_FILE does this fall
    # through to the normal APPROVE path below if the snapshot is unchanged.
    # Actual source corrections invalidate it above and require refreshed
    # review in the same round (Constitution VIII / workflow.md).
    if [ "$CODE_VERDICT" = APPROVE-WITH-FIXES ]; then
      if [ ! -f "$AWF_FILE" ]; then
        cat <<EOF | emit_prompt APPLY-FIXES
$TICKET_ID verdict is APPROVE-WITH-FIXES. Apply ONLY the FIX ITEMS listed in
$VERDICT_FILE — verbatim, nothing else:
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
    REDTEAM_APPROVED=0
    if [ "$PRIVACY" = true ] && { [ "$CODE_VERDICT" = APPROVE ] || [ "$CODE_VERDICT" = APPROVE-WITH-FIXES ]; }; then
      CURRENT_SNAPSHOT="$(review_snapshot)"
      if [ -f "$REDTEAM_SNAPSHOT" ] && [ "$(cat "$REDTEAM_SNAPSHOT")" != "$CURRENT_SNAPSHOT" ]; then
        invalidate_reviews
        exit 1
      fi
      if [ ! -f "$REDTEAM_SNAPSHOT" ]; then
        # Old or unsolicited verdicts cannot satisfy a newly issued request.
        rm -f "$REDTEAM_FILE"
        printf '%s\n' "$CURRENT_SNAPSHOT" > "$REDTEAM_SNAPSHOT"
      fi
      if [ ! -f "$REDTEAM_FILE" ]; then
        BASE_SHA="$(cat "$RUN_DIR/$TICKET_ID.start-sha" 2>/dev/null || git rev-parse HEAD)"
        cat <<EOF | emit_prompt REDTEAM
The ROOT caller must spawn stargate-redteam in a fresh context for $TICKET_ID.
Use its ticket-review mode. No reviewer may spawn another reviewer.
Provide ONLY this handoff, both diffs (git diff $BASE_SHA and
git diff --cached $BASE_SHA), the ticket's cited spec/contract anchors,
the Constitution and THREAT-MODEL.md. Inspect staged content as the commit
candidate as well as the working copy exercised by verification. Do not supply
implementation rationale or the current codereview findings. Read affected
callers and configuration to establish reachability across the diff boundary.

Review round: $ROUND (shared cap $ROUND_CAP)
Snapshot: $CURRENT_SNAPSHOT
The reviewer writes its own verdict to $REDTEAM_FILE, then replies with a stub.
Required fields, each exactly once:
VERDICT: APPROVE | REWORK | ESCALATE
SNAPSHOT: $CURRENT_SNAPSHOT
ROUND: $ROUND
SUMMARY: <one line>
FINDINGS: <severity, file:line, attack path, falsification attempt, fix probe>

APPROVE requires zero unresolved Blocker/Major findings. Minor findings may
accompany approval. REWORK uses the shared round budget; ESCALATE stops for
human resolution. A prior accepted risk requires human reconciliation, never
an automatic override. For repeat review, inspect your prior redteam verdict
at $RUN_DIR/$TICKET_ID-r$((ROUND-1)).redteam.verdict if it exists.
Do not edit code, the ticket, or any other reviewer's verdict. Re-invoke
scripts/run-task.sh $TICKET_ID after the reviewer has written the file.
EOF
        exit 0
      fi
      # Verdict files are an IPC boundary: reject missing, duplicate, unknown,
      # wrong-round or stale fields rather than accepting an APPROVE prefix.
      if ! REDTEAM_KIND="$(python3 - "$REDTEAM_FILE" "$CURRENT_SNAPSHOT" "$ROUND" <<'CHECK'
import re, sys
text = open(sys.argv[1]).read()
def field(name):
    values = re.findall(r'^' + name + r':[ \t]*(.*)$', text, re.MULTILINE)
    if len(values) != 1:
        raise ValueError(name)
    return values[0].strip()
try:
    verdict = field('VERDICT')
    if not field('SUMMARY'):
        raise ValueError('empty summary')
    field('FINDINGS')
    if verdict not in ('APPROVE', 'REWORK', 'ESCALATE') or field('SNAPSHOT') != sys.argv[2] or field('ROUND') != sys.argv[3]:
        raise ValueError('invalid verdict')
except ValueError:
    sys.exit('run-task: malformed or mismatched redteam verdict; reviewer must correct it')
print(verdict)
CHECK
)"; then
        exit 1
      fi
      cp "$REDTEAM_FILE" "$RUN_DIR/$TICKET_ID-r${ROUND}.redteam.verdict"
      if [ "$REDTEAM_KIND" = APPROVE ]; then
        REDTEAM_APPROVED=1
      else
        # Reuse the established rework/escalation path and round budget.
        VERDICT_BODY="$(cat "$REDTEAM_FILE")"
        cp "$REDTEAM_FILE" "$RUN_DIR/$TICKET_ID-r${ROUND}.verdict"
        rm -f "$VERDICT_FILE" "$REDTEAM_FILE" "$REDTEAM_SNAPSHOT" "$AWF_FILE"
      fi
    fi
    if echo "$VERDICT_BODY" | grep -qE '^VERDICT:\s*APPROVE'; then
      # --- T096 §Acceptance #3: APPROVE is fail-closed. The driver may not
      # flip `done` until (a) verify is fresh-green, (b) codereview APPROVE is
      # present (the file we're holding), and (c) a focused commit with the
      # required Reviewed-by trailer exists. The driver creates the commit
      # itself so the invariant holds by construction. Privacy-critical
      # tickets additionally require independent redteam approval (T133).
      echo "run-task: APPROVE received. Re-running verify.sh as the freshness gate…"
      if ! bash scripts/verify.sh >> target/verify.log 2>&1; then
        echo "run-task: verify.sh NOT GREEN at APPROVE. Tree changed post-review. Re-implement." >&2
        invalidate_reviews
        exit 1
      fi
      check_inventory || exit 1
      if [ "$(review_snapshot source-only)" != "$(cat "$CODE_SNAPSHOT")" ]; then
        invalidate_reviews
        exit 1
      fi
      if [ "$REDTEAM_APPROVED" = 1 ] && [ "$(review_snapshot)" != "$(cat "$REDTEAM_SNAPSHOT")" ]; then
        invalidate_reviews
        exit 1
      fi

      # Create the focused commit on the feature branch with the required
      # Reviewed-by trailer. The caller staged paths during IMPLEMENT; we
      # commit only those. If nothing is staged, surface a COMMIT handoff
      # rather than flipping done (the commit invariant is the gate).
      VERDICT_KIND="$(printf '%s\n' "$VERDICT_BODY" | grep -m1 '^VERDICT:' | sed 's/^VERDICT:[[:space:]]*//' | cut -c1-40)"
      REVIEW_LINE="Reviewed-by: stargate-codereview (VERDICT: $VERDICT_KIND; round $ROUND)"
      if [ "$REDTEAM_APPROVED" = 1 ]; then
        REVIEW_LINE="$REVIEW_LINE
Reviewed-by: stargate-redteam (VERDICT: APPROVE; round $ROUND; snapshot $CURRENT_SNAPSHOT)"
      fi
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
        # Keep verdict + redteam so re-invocation proceeds straight to commit.
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
      rm -f "$VERDICT_FILE" "$REDTEAM_FILE" "$REDTEAM_SNAPSHOT" "$CODE_SNAPSHOT" "$AWF_FILE"
      echo "run-task: $TICKET_ID done (committed on '$FEATURE_BRANCH')."
      echo "  Push is your call: git push origin $FEATURE_BRANCH"
      echo "  Milestone squash-merge to main: scripts/run-task.sh $TICKET_ID --merge"
      exit 0
    fi

    if echo "$VERDICT_BODY" | grep -qE '^VERDICT:\s*ESCALATE'; then
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
      rm -f "$VERDICT_FILE"
      exit 1
    fi

    # Must-shrink check on round ≥2: compare this round's diffstat to prior.
    if [ "$ROUND" -ge 2 ] && [ -f "$RUN_DIR/$TICKET_ID-r$((ROUND-1)).diffstat" ]; then
      PRIOR="$RUN_DIR/$TICKET_ID-r$((ROUND-1)).diffstat"
      CURRENT="$DIFFSTAT_FILE"
      NONCONVERGING="$(python3 - "$PRIOR" "$CURRENT" <<'PY'
import re, sys
def parse(p):
    files, added, removed = 0, 0, 0
    for line in open(p):
        m = re.match(r'^\s*(\d+) files? changed, (\d+) insertions?\(\+\), (\d+) deletions?\(-\)\s*$', line)
        if m:
            files, added, removed = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return files, added, removed
pf, pa, pr = parse(sys.argv[1])
cf, ca, cr = parse(sys.argv[2])
# Non-converging = grew on all three dimensions.
if cf > pf and ca > pa and cr > pr:
    print(f"NON-CONVERGING: round {2} grew files ({pf}→{cf}), added ({pa}→{ca}), removed ({pr}→{cr}) simultaneously")
PY
)"
      if [ -n "$NONCONVERGING" ]; then
        echo "run-task: $NONCONVERGING. Escalating (scope creep in fix's clothes)." >&2
        update_ticket_status "escalated"
        rm -f "$VERDICT_FILE"
        exit 1
      fi
    fi

    # Bump round counter, transition back to in-progress for the rework.
    ROUND=$((ROUND + 1))
    echo "$ROUND" > "$ROUND_FILE"
    rm -f "$VERDICT_FILE"
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
