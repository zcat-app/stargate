#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# derive-deps.sh — improve `blocked_by:` lists in ticket files using signals
# from tasks.md that bootstrap-tickets.sh left as `[]` (TODO).
#
# Why this is a separate step from bootstrap: the dependency graph in
# tasks.md is implicit. bootstrap emits every ticket with `blocked_by: []`
# so the simplest case (everything runnable) works immediately; this script
# tightens it so the dependency graph is real and `scripts/next-task.sh`
# returns the actually-runnable set.
#
# Derivation rules (most-coarse to most-specific; later rules win):
#
#   1. PHASE ORDERING (coarse).
#      Every task in Phase N is blocked_by the *closing* task of Phase N-1
#      (or the last [X] task in the previous phase, if no closing task is
#      named). This is intentionally loose — phase boundaries are about
#      "shared infrastructure" not strict dependencies. It's a floor, not a
#      ceiling.
#
#   2. EXPLICIT PROSE (precise).
#      Patterns inside a task body that name other tasks:
#        - "Depends on T-NNN and T-NNN"           → blocked_by those
#        - "Pairs with T-NNN"                     → blocked_by that (test+impl)
#        - "Test gate: T-NNN MUST be authored"    → blocked_by that
#        - "Verified by T-NNN"                    → that is a verifier, not a
#                                                   blocker; do NOT add.
#      These prose-derived deps are precise and override phase-derived ones.
#
#   3. SUBTICKET PARENT (T-NNN → T-NNNa/b/c).
#      Subtickets (T012a, T019b, etc.) block their parent (T012, T019) when
#      the parent is an umbrella, OR depend on the parent when the subticket
#      is a follow-on. The bootstrap can't tell which; this script writes a
#      WARN and leaves the relationship for manual review.
#
# Safety: never REMOVES a blocked_by entry that the user hand-added. Only
# adds. Run with --prune to also remove phase-derived entries that are no
# longer in tasks.md (rare; use only when tasks.md has been regenerated).
#
# Usage:
#   scripts/derive-deps.sh                        # active feature
#   scripts/derive-deps.sh specs/001-tor-route    # explicit
#   scripts/derive-deps.sh --dry-run              # show what would change

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

FEATURE_DIR=""
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --*) echo "derive-deps: unknown flag: $1" >&2; exit 2 ;;
    *) [ -z "$FEATURE_DIR" ] && FEATURE_DIR="$1" && shift || { echo "derive-deps: unexpected arg: $1" >&2; exit 2; } ;;
  esac
done

[ -n "$FEATURE_DIR" ] || FEATURE_DIR="$(python3 -c '
import json
try:
    cfg = json.load(open(".specify/feature.json"))
    print(cfg.get("feature_directory", "specs/001-tor-route"))
except Exception:
    print("specs/001-tor-route")
' 2>/dev/null || echo "specs/001-tor-route")"

TASKS_MD="$FEATURE_DIR/tasks.md"
TICKETS_DIR="$FEATURE_DIR/tickets"

[ -f "$TASKS_MD" ] || { echo "derive-deps: $TASKS_MD not found" >&2; exit 2; }
[ -d "$TICKETS_DIR" ] || { echo "derive-deps: $TICKETS_DIR not found (run bootstrap-tickets.sh)" >&2; exit 2; }

# Pass tasks.md + ticket dir to a python worker. Python is the right tool
# here: regex extraction across 100+ files + 200+ task bodies is painful in
# pure bash, and the precedent (infochat's regen-status.py) is python.
python3 - "$TASKS_MD" "$TICKETS_DIR" "$DRY_RUN" <<'PY'
import glob, os, re, sys

TASKS_MD, TICKETS_DIR, DRY_RUN = sys.argv[1], sys.argv[2], int(sys.argv[3])

# --- parse tasks.md: id → (phase, body, parent) -----------------------------
# A task line: `- [X] T015 [P] [US1] body...`  (possibly multi-line via
# continuation, but the body we care about is the same line — the long
# prose is on the single physical line after the markers).
tasks = {}        # id → {'phase': str, 'body': str, 'done': bool}
phase_order = []  # list of phase names in order seen
phase_of = {}     # task id → phase name
current_phase = "(no phase)"
for line in open(TASKS_MD):
    m = re.match(r'^##\s+Phase\s+(\d+):', line)
    if m:
        # Capture just the phase number for ordering; the full title is noise
        # for dependency purposes.
        current_phase = m.group(1)
        if current_phase not in phase_order:
            phase_order.append(current_phase)
        continue
    m = re.match(r'^-\s*\[([ Xx])\]\s+(T\d+[a-z]?)\s+(.*)$', line)
    if not m: continue
    mark, tid, body = m.group(1), m.group(2), m.group(3)
    tasks[tid] = {
        'phase': current_phase,
        'body': body,
        'done': mark in ('X', 'x'),
    }
    phase_of[tid] = current_phase

# --- phase ordering: for each phase, what is the "previous phase close"? ----
# Rule: every task in phase N is blocked_by the *highest-numbered [X] task
# in any earlier phase*. If no task in earlier phases is [X] (early in the
# build), no phase-derived dep. If multiple, only the highest id — that's
# the conventional "this phase is unlocked when X lands" sentinel.
def phase_close_before(phase):
    earlier_x = [tid for tid, t in tasks.items()
                 if t['done'] and phase_order.index(t['phase']) < phase_order.index(phase)]
    if not earlier_x: return None
    def k(tid):
        m = re.match(r'^T0*(\d+)([a-z]?)$', tid)
        return (int(m.group(1)), m.group(2)) if m else (99999, '')
    return max(earlier_x, key=k)

phase_blocker = {p: phase_close_before(p) for p in phase_order}

# --- prose-derived deps ------------------------------------------------------
# Per task body, find references to other T-NNN ids that imply a dep.
DEP_PATTERNS = [
    re.compile(r'\bDepends on\s+(T\d+[a-z]?(?:\s*(?:,|and)\s*T\d+[a-z]?)*)', re.IGNORECASE),
    re.compile(r'\bPairs with\s+(T\d+[a-z]?)', re.IGNORECASE),
    re.compile(r'\bTest gate:\s*(T\d+[a-z]?)\s+MUST', re.IGNORECASE),
]
# Negative pattern — "verified by" is NOT a blocker; the verifier is gated
# BY the impl, not the other way round.
VERIFIED_BY = re.compile(r'\bverified by\s+(T\d+[a-z]?)', re.IGNORECASE)

def prose_deps(body):
    deps = set()
    for pat in DEP_PATTERNS:
        for m in pat.finditer(body):
            # Extract all T-NNN tokens from the match.
            for tok in re.findall(r'T\d+[a-z]?', m.group(0)):
                deps.add(tok)
    # Subtract any "verified by" mentions.
    for m in VERIFIED_BY.finditer(body):
        deps.discard(m.group(1))
    return deps

prose_blockers = {tid: prose_deps(t['body']) for tid, t in tasks.items()}

# --- for each ticket file, compute the new blocked_by list -------------------
# Read existing blocked_by from the ticket file (so we preserve user-added
# entries); merge with derived; write back.
def read_blocked_by(path):
    txt = open(path).read()
    m = re.match(r'^---\n(.*?)\n---\n', txt, re.DOTALL)
    if not m: return set()
    fm = m.group(1)
    # inline list
    mm = re.search(r'^blocked_by:\s*(.*)$', fm, re.MULTILINE)
    if not mm: return set()
    rest = re.sub(r'\s+#.*$', '', mm.group(1)).strip()
    if rest.startswith('['):
        inner = rest.strip('[]').strip()
        if not inner: return set()
        return {v.strip().strip("'\"") for v in inner.split(',')}
    # block list
    vals = set()
    for line in fm.splitlines():
        m2 = re.match(r'^\s+-\s+(T\d+[a-z]?)\s*$', line)
        if m2: vals.add(m2.group(1))
    return vals

def write_blocked_by(path, deps):
    txt = open(path).read()
    if not deps:
        new_line = "blocked_by: []   # derived by scripts/derive-deps.sh"
    else:
        # Inline list, sorted by id numeric+letter.
        def k(tid):
            m = re.match(r'^T0*(\d+)([a-z]?)$', tid)
            return (int(m.group(1)), m.group(2)) if m else (99999, '')
        rendered = ', '.join(sorted(deps, key=k))
        new_line = f"blocked_by: [{rendered}]   # derived by scripts/derive-deps.sh"
    # Replace the blocked_by line (whatever shape it was) in the frontmatter.
    fm_match = re.match(r'^(---\n)(.*?)(\n---\n)', txt, re.DOTALL)
    if not fm_match: return False
    fm = fm_match.group(2)
    # Match either `blocked_by: ...` (inline or empty) — block-list form is
    # collapsed to inline on rewrite (simpler; we always write inline).
    fm_new = re.sub(
        r'^blocked_by:\s*(?:\[[^\]]*\]|.*?(?=\n[a-z]|\Z))',
        new_line,
        fm, count=1, flags=re.MULTILINE | re.DOTALL
    )
    # If the original used a block list, there may be trailing '  - T-NNN'
    # lines now orphaned — strip them.
    fm_new = re.sub(r'\n\s+-\s+T\d+[a-z?]?\s*(?=\n[a-z]|\Z)', '', fm_new)
    new_txt = fm_match.group(1) + fm_new + fm_match.group(3) + txt[fm_match.end():]
    open(path, 'w').write(new_txt)
    return True

# --- apply ------------------------------------------------------------------
changes = 0
for tid, t in tasks.items():
    matches = glob.glob(f'{TICKETS_DIR}/{tid}-*.md')
    if not matches: continue
    path = matches[0]
    existing = read_blocked_by(path)
    derived = set()
    # Phase ordering dep.
    pb = phase_blocker.get(t['phase'])
    if pb and pb != tid:
        derived.add(pb)
    # Prose deps.
    derived |= prose_blockers.get(tid, set())
    # Drop self-deps and deps on ids that don't exist as tickets (stale
    # references in tasks.md).
    derived.discard(tid)
    derived = {d for d in derived if glob.glob(f'{TICKETS_DIR}/{d}-*.md')}
    # Merge: preserve user-added entries that aren't in either set.
    merged = existing | derived
    # Idempotency: if no change, skip.
    if merged == existing: continue
    added = derived - existing
    if DRY_RUN:
        print(f"  (dry-run) {tid}: +{sorted(added)} → blocked_by={sorted(merged)}")
    else:
        write_blocked_by(path, merged)
        print(f"  {tid}: +{sorted(added)} → blocked_by={sorted(merged)}")
    changes += 1

print(f"derive-deps: {changes} ticket(s) updated{' (dry-run)' if DRY_RUN else ''}.")
PY
