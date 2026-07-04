#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# handoff.sh — write a structured session handoff so a fresh session (after a
# context reset, a crash, a long pause, or a tool switch) can resume without
# re-deriving everything.
#
# Handoffs are LOCAL WORKING NOTES. They live under specs/<feature>/.handoffs/
# which is gitignored — never committed, never referenced from a tracked doc.
# The Constitution, the spec, the ticket file, and git log are the durable
# sources of truth; a handoff is a snapshot of "now" that the next session
# re-verifies before relying on.
#
# Precedent: zecsite's /ticket handoff subcommand. Adapted to stargate with:
#   - feature-scoped path (one .handoffs/ per feature)
#   - explicit grounding step (verify branch / status / verify log before
#     writing — a stale handoff is worse than none)
#   - Constitution-aware "don't-rediscover" section (privacy-critical gotchas
#     that bit this session)
#
# Usage:
#   scripts/handoff.sh                   # in-flight ticket in current feature
#   scripts/handoff.sh T015              # specific ticket
#   scripts/handoff.sh --session         # no-ticket session handoff (date-named)
#   scripts/handoff.sh T015 --round 2    # annotate with rework round context

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TICKET_ID=""
SESSION=0
ROUND=""
for arg in "$@"; do
  case "$arg" in
    --session) SESSION=1 ;;
    --round)   shift_if_value=1 ;;
    --round=*) ROUND="${arg#--round=}" ;;
    --*) echo "handoff: unknown flag: $arg" >&2; exit 2 ;;
    *) [ -z "$TICKET_ID" ] && [ "$SESSION" = "0" ] && TICKET_ID="$arg" || true ;;
  esac
done

# Determine feature directory.
FEATURE_DIR="$(python3 -c '
import json
try:
    cfg = json.load(open(".specify/feature.json"))
    print(cfg.get("feature_directory", "specs/001-tor-route"))
except Exception:
    print("specs/001-tor-route")
' 2>/dev/null || echo "specs/001-tor-route")"

HANDOFF_DIR="$FEATURE_DIR/.handoffs"
mkdir -p "$HANDOFF_DIR"

# --- GROUND TRUTH (verify before writing — zecsite's load-bearing rule) ----
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '(detached)')"
HEAD_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo '(no-git)')"
TREE_STATE="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
[ "$TREE_STATE" = "0" ] && TREE_DESC="clean" || TREE_DESC="dirty ($TREE_STATE untracked/modified)"
TODAY="$(date +%Y-%m-%d)"
NOW="$(date '+%H:%M %Z')"

# Find ticket file if id given; derive title + status.
TICKET_PATH=""
TICKET_TITLE=""
TICKET_STATUS=""
TICKET_PHASE=""
if [ -n "$TICKET_ID" ] && [ "$SESSION" = "0" ]; then
  TICKET_PATH="$(ls "$FEATURE_DIR/tickets/$TICKET_ID"-*.md 2>/dev/null | head -1 || true)"
  if [ -z "$TICKET_PATH" ]; then
    echo "handoff: ticket $TICKET_ID not found under $FEATURE_DIR/tickets/" >&2
    exit 2
  fi
  # Extract title + status + phase (one per line; bash reads them into an array).
  mapfile -t TICKET_META < <(python3 -c "
import re
txt = open('$TICKET_PATH').read()
m = re.match(r'^---\n(.*?)\n---\n', txt, re.DOTALL)
fm = m.group(1) if m else ''
def get(k):
    m2 = re.search(rf'^{k}:\s*(.*)\$', fm, re.MULTILINE)
    if not m2: return ''
    v = re.sub(r'\s+#.*\$', '', m2.group(1)).strip().strip('\\'\"')
    return v
print(get('title')[:80])
print(get('status'))
print(get('phase'))
")
  TICKET_TITLE="${TICKET_META[0]:-}"
  TICKET_STATUS="${TICKET_META[1]:-}"
  TICKET_PHASE="${TICKET_META[2]:-}"
fi

# Verify log freshness (if one exists).
VERIFY_LOG="target/verify.log"
VERIFY_FRESHNESS="(no verify log yet)"
if [ -f "$VERIFY_LOG" ]; then
  LOG_MTIME="$(stat -c %Y "$VERIFY_LOG" 2>/dev/null || stat -f %m "$VERIFY_LOG" 2>/dev/null || echo 0)"
  NOW_EPOCH="$(date +%s)"
  AGE_SEC=$((NOW_EPOCH - LOG_MTIME))
  if [ "$AGE_SEC" -lt 300 ]; then
    VERIFY_FRESHNESS="fresh (<5min old)"
  elif [ "$AGE_SEC" -lt 3600 ]; then
    VERIFY_FRESHNESS="~$((AGE_SEC / 60))min old"
  else
    VERIFY_FRESHNESS="~$((AGE_SEC / 3600))h old (stale — re-run scripts/verify.sh before relying on it)"
  fi
fi

# --- decide path -----------------------------------------------------------
if [ "$SESSION" = "1" ]; then
  OUT_PATH="$HANDOFF_DIR/SESSION-${TODAY}-HANDOFF.md"
  LABEL="Session ${TODAY}"
else
  OUT_PATH="$HANDOFF_DIR/${TICKET_ID}-HANDOFF.md"
  LABEL="$TICKET_ID"
fi

# --- write -----------------------------------------------------------------
{
  echo "# Handoff — $LABEL ($TODAY $NOW)"
  echo
  echo "> **Local working note.** Gitignored. Re-verify any assertion about"
  echo "> files or build state before relying on it — a handoff reflects"
  echo "> what was true when written, not what's true now. The Constitution,"
  echo "> the spec, the ticket file, and git log are the durable sources of truth."
  echo
  echo "## State now"
  echo
  echo "- **Branch:** \`$BRANCH\`"
  echo "- **HEAD:** \`$HEAD_SHA\`"
  echo "- **Working tree:** $TREE_DESC"
  echo "- **Last \`scripts/verify.sh\` log:** $VERIFY_FRESHNESS"

  if [ -n "$TICKET_ID" ] && [ "$SESSION" = "0" ]; then
    echo "- **Ticket:** \`$TICKET_ID\` — $TICKET_TITLE"
    echo "- **Status:** \`$TICKET_STATUS\`"
    echo "- **Phase:** $TICKET_PHASE"
    [ -n "$ROUND" ] && echo "- **Round:** $ROUND (rework)"
  fi
  echo
  echo "## What happened this session"
  echo
  echo "<!-- One paragraph or a short bullet list. Decisions made and WHY"
  echo "     (link ADR / spec § / Constitution principle). NOT a keystroke"
  echo "     log. \"Resolved on the fly\" recaps belong here per the"
  echo "     stargate collaboration cadence. -->"
  echo
  echo "- (fill in)"
  echo
  echo "## Next steps (in order)"
  echo
  echo "<!-- The exact next command(s) and any manual step before them. The"
  echo "     resume session should be able to read this section and start"
  echo "     without re-deriving context. -->"
  echo
  if [ "$SESSION" = "0" ] && [ -n "$TICKET_ID" ]; then
    echo "- Resume $TICKET_ID: \`scripts/run-task.sh $TICKET_ID\`"
  else
    echo "- Pick the next ticket: \`scripts/next-task.sh --count 1\`"
  fi
  echo "- (add specific next actions)"
  echo
  echo "## Don't-rediscover gotchas"
  echo
  echo "<!-- Expensive-to-relearn facts: build flags, version pins, traps,"
  echo "     environment specifics. Each with the reason it bites. If the"
  echo "     gotcha is privacy-critical, name the Constitution principle. -->"
  echo
  echo "- (fill in, or delete this section if empty)"
  echo
  echo "## Open questions"
  echo
  echo "<!-- Anything unresolved that the next session must decide. If a"
  echo "     question has a proposed answer, state it and what would falsify"
  echo "     it (Constitution's falsify-before-publishing doctrine). -->"
  echo
  echo "- (fill in, or delete this section if empty)"
  echo
  echo "## References"
  echo
  echo "- Workflow: \`docs/process/workflow.md\`"
  echo "- Ticket template: \`docs/process/ticket-template.md\`"
  echo "- Review loop: \`.specify/memory/review-loop.md\`"
  echo "- Constitution: \`.specify/memory/constitution.md\`"
  echo
  echo "---"
  echo
  echo "_Handoff written by \`scripts/handoff.sh\` on $TODAY $NOW._"
} > "$OUT_PATH"

# Confirm gitignored (the absence from git IS the point).
GITIGNORED="$(git check-ignore -q "$OUT_PATH" 2>/dev/null && echo yes || echo no)"

echo "handoff: wrote $OUT_PATH ($([ "$GITIGNORED" = yes ] && echo "gitignored ✓" || echo "WARNING: NOT gitignored — check .gitignore"))"
echo "handoff: branch=$BRANCH head=$HEAD_SHA tree=$TREE_DESC"
