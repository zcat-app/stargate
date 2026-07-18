#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# next-task.sh — resolve the set of runnable tickets for a feature.
#
# A ticket is runnable when:
#   - status is `pending`
#   - every id in `blocked_by:` has `status: done` in its own ticket file
#
# Default output: human-readable table (lowest id first). With --json: a
# stable JSON array each entry carrying the load-bearing fields, so a future
# `/run` autopilot or an external cloud agent can consume it without grep.
#
# Usage:
#   scripts/next-task.sh [specs/NNN-feature]            # table
#   scripts/next-task.sh specs/NNN-feature --json       # JSON
#   scripts/next-task.sh specs/NNN-feature --count 1    # only the lowest-id runnable
#
# Defaults to specs/001-tor-route (the current active feature per .specify/feature.json).
#
# Why this exists: autonomy requires a machine-readable "what should I do next?"
# Without it, an agent falls back to grep over tasks.md (fragile) or asks the
# human (defeats the point). This script is the single source of truth for
# "runnable" — every driver (an agent, a CI runner, a cron loop) reads it.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Default to the active feature from .specify/feature.json if no path given.
# Only treat $1 as FEATURE_DIR if it doesn't look like a flag.
FEATURE_DIR=""
if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
  FEATURE_DIR="$1"; shift
fi
if [ -z "$FEATURE_DIR" ]; then
  FEATURE_DIR="$(python3 -c '
import json, sys
try:
    cfg = json.load(open(".specify/feature.json"))
    print(cfg.get("feature_directory", "specs/001-tor-route"))
except Exception:
    print("specs/001-tor-route")
' 2>/dev/null || echo "specs/001-tor-route")"
fi

OUTPUT="table"
COUNT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --json)    OUTPUT="json"; shift ;;
    --count)   COUNT="${2:?--count requires a value}"; shift 2 ;;
    --count=*) COUNT="${1#--count=}"; shift ;;
    *) echo "next-task: unknown flag: $1" >&2; exit 2 ;;
  esac
done

TICKETS_DIR="$FEATURE_DIR/tickets"
[ -d "$TICKETS_DIR" ] || { echo "next-task: $TICKETS_DIR not found (run scripts/bootstrap-tickets.sh $FEATURE_DIR first)" >&2; exit 2; }

# Extract a single YAML frontmatter field from a ticket file. Targeted
# extraction (not a general YAML parser) — mirrors infochat's regen-status.py
# approach: read only what we need, no pyyaml dependency, no CVE surface.
# Field shapes supported:
#   - scalar:        key: value
#   - quoted scalar: key: "value with spaces"
#   - inline list:   key: [A, B]   or   key: []
#   - block list:    key:\n  - A\n  - B
get_field() {
  local file="$1" key="$2"
  python3 - "$file" "$key" <<'PY'
import re, sys
path, key = sys.argv[1], sys.argv[2]
text = open(path).read()
# Frontmatter is the YAML between the first two '---' lines.
m = re.match(r'^---\n(.*?)\n---\n', text, re.DOTALL)
if not m: sys.exit(0)
fm = m.group(1)
lines = fm.splitlines()
i = 0
while i < len(lines):
    line = lines[i]
    mm = re.match(rf'^{re.escape(key)}:\s*(.*)$', line)
    if not mm:
        i += 1; continue
    # Strip a trailing YAML comment. A '#' preceded by whitespace starts a
    # comment unless inside quotes. Our extracted fields don't contain '#'
    # inside quotes, so a simple split is safe here.
    rest = re.sub(r'\s+#.*$', '', mm.group(1)).rstrip()
    # inline list:  key: [A, B, C]   or   key: []
    if rest.startswith('['):
        inner = rest.strip('[]').strip()
        if not inner: print(''); sys.exit(0)
        vals = [v.strip().strip('\'"') for v in inner.split(',')]
        for v in vals: print(v)
        sys.exit(0)
    # empty value → maybe block list follows
    if rest == '' or rest == '[]':
        if rest == '[]': print(''); sys.exit(0)
        # block list: collect subsequent '  - X' lines
        vals = []
        j = i + 1
        while j < len(lines) and re.match(r'^\s+-\s+', lines[j]):
            vals.append(re.sub(r'^\s+-\s+', '', lines[j]).strip().strip('\'"'))
            j += 1
        if vals:
            for v in vals: print(v)
            sys.exit(0)
        print(''); sys.exit(0)
    # scalar (strip surrounding quotes)
    print(rest.strip('\'"'))
    sys.exit(0)
sys.exit(0)
PY
}

# Collect status by id (so we can resolve blocked_by lookups).
declare -A STATUS TITLE PRIVACY CRITICAL PARALLEL STORY PHASE
for f in "$TICKETS_DIR"/*.md; do
  [ -f "$f" ] || continue
  id="$(get_field "$f" id)"
  [ -z "$id" ] && continue
  STATUS[$id]="$(get_field "$f" status)"
  TITLE[$id]="$(get_field "$f" title)"
  PRIVACY[$id]="$(get_field "$f" privacy_critical)"
  PARALLEL[$id]="$(get_field "$f" parallel)"
  STORY[$id]="$(get_field "$f" story)"
  PHASE[$id]="$(get_field "$f" phase)"
done

# Resolve runnable tickets.
runnable=()
for id in "${!STATUS[@]}"; do
  [ "${STATUS[$id]}" = "pending" ] || continue
  # Find this ticket's blocked_by. Re-read the file (cheap; ~100 files).
  # find(1) instead of ls: stable parsing + unusual-filename safe (T103 A4 / SC2012).
  f="$(find "$TICKETS_DIR" -maxdepth 1 -name "${id}-*.md" 2>/dev/null | head -1)"
  [ -z "$f" ] && continue
  deps="$(get_field "$f" blocked_by)"
  all_done=1
  if [ -n "$deps" ]; then
    while IFS= read -r dep; do
      [ -z "$dep" ] && continue
      if [ "${STATUS[$dep]:-missing}" != "done" ]; then all_done=0; break; fi
    done <<< "$deps"
  fi
  [ "$all_done" = "1" ] && runnable+=("$id")
done

# Sort by numeric portion of the id (T015 → 15, T012a → 12.1).
sort_key() {
  local id="$1"
  # Extract digits and optional trailing letter.
  if [[ "$id" =~ ^T0*([0-9]+)([a-z]?)$ ]]; then
    # Strip leading zeros (bash's printf %d otherwise parses "069" as octal).
    num="$((10#${BASH_REMATCH[1]}))"
    letter="${BASH_REMATCH[2]}"
    # Letter sorts after the bare number: T012a → 12.01, T012 → 12.00
    local letter_val=0
    [ -n "$letter" ] && letter_val=$((10#$(printf '%d' "'$letter")))
    printf '%05d.%03d' "$num" "$letter_val"
  else
    printf '%s' "$id"
  fi
}

# Sort runnable ids.
if [ ${#runnable[@]} -eq 0 ]; then
  if [ "$OUTPUT" = "json" ]; then
    echo "[]"
  else
    echo "next-task: no runnable tickets in $FEATURE_DIR."
    echo "  (pending tickets exist but all have unsatisfied blocked_by, or"
    echo "   no tickets are pending. Check with: ls $TICKETS_DIR/)"
  fi
  exit 0
fi

IFS=$'\n' sorted_ids=($(for id in "${runnable[@]}"; do echo "$(sort_key "$id") $id"; done | sort | awk '{print $2}')); unset IFS

# Apply --count.
if [ "$COUNT" != "0" ] && [ "$COUNT" -lt "${#sorted_ids[@]}" ]; then
  sorted_ids=("${sorted_ids[@]:0:$COUNT}")
fi

if [ "$OUTPUT" = "json" ]; then
  TICKETS_DIR="$TICKETS_DIR" python3 - "${sorted_ids[@]}" <<'PY'
import json, sys
ids = sys.argv[1:]
# Re-read the per-id metadata we already gathered in bash by re-parsing — but
# the bash associative arrays aren't visible here. For JSON output we re-derive
# from disk so the contract is "this script reads files", not "this script
# holds state". Cheap for ~100 files.
import os, re, glob
tickets_dir = os.environ.get('TICKETS_DIR', '')
def frontmatter(path):
    txt = open(path).read()
    m = re.match(r'^---\n(.*?)\n---\n', txt, re.DOTALL)
    if not m: return {}
    out = {}
    for line in m.group(1).splitlines():
        mm = re.match(r'^([a-z_]+):\s*(.*)$', line)
        if not mm: continue
        # Strip trailing YAML comments (our fields don't contain '#' in quotes).
        val = re.sub(r'\s+#.*$', '', mm.group(2)).strip().strip('\'"')
        out[mm.group(1)] = val
    return out
result = []
for id in ids:
    matches = glob.glob(f'{tickets_dir}/{id}-*.md')
    if not matches: continue
    fm = frontmatter(matches[0])
    result.append({
        'id': id,
        'title': fm.get('title', ''),
        'phase': fm.get('phase', ''),
        'story': fm.get('story', '-'),
        'parallel': fm.get('parallel', 'false') == 'true',
        'privacy_critical': fm.get('privacy_critical', 'false') == 'true',
        'complexity': fm.get('complexity', 'low'),
        'risk': fm.get('risk', 'low'),
        'files_budget': int(fm.get('files_budget', '0') or '0'),
        'ticket_file': os.path.relpath(matches[0]),
    })
print(json.dumps(result, indent=2))
PY
  exit 0
fi

# Table output.
printf '%-8s  %-9s  %-7s  %-10s  %-10s  %s\n' "ID" "STORY" "PARALLEL" "PRIVACY" "COMPLEXITY" "TITLE"
printf '%-8s  %-9s  %-7s  %-10s  %-10s  %s\n' "----" "-----" "--------" "-------" "----------" "-----"
for id in "${sorted_ids[@]}"; do
  printf '%-8s  %-9s  %-7s  %-10s  %-10s  %s\n' \
    "$id" \
    "${STORY[$id]:--}" \
    "${PARALLEL[$id]:-false}" \
    "${PRIVACY[$id]:-false}" \
    "$(get_field "$TICKETS_DIR/$id-"*.md complexity | head -1)" \
    "${TITLE[$id]:-}"
done
echo
echo "Runnable: ${#sorted_ids[@]} ticket(s). Pick one and start it (future /run skill or scripts/run-task.sh)."
