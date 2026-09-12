#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# sync-agents.sh — regenerate .opencode/agent/*.md from .claude/agents/*.md.
#
# Why: stargate is tool-agnostic. Agent definitions live once under
# .claude/agents/ (the canonical source) and are mirrored into .opencode/agent/
# so opencode sees the same reviewers. The two tools' frontmatter shapes
# differ; this script does the mechanical transform so they cannot drift.
#
# Mapping:
#   Claude frontmatter                 → opencode frontmatter
#   ---------------------------------------------------------------
#   name: <X>                          → (filename = <X>.md)
#   description: <...>                 → description: <...>
#   model: opus | sonnet               → (dropped; opencode picks per agent
#                                         via opencode.json or its default)
#   tools: Read, Grep, Glob, Bash[, Write]
#                                      → permission rules ONLY. Do NOT emit
#                                         an opencode `tools:` frontmatter map:
#                                         it is not in the documented agent
#                                         frontmatter schema, and unknown
#                                         keys are passed through as provider
#                                         model options — the 2026-09-06 T053
#                                         round-1 review spawns lost bash
#                                         entirely with it present. Tools
#                                         follow from permission: an allow
#                                         somewhere provisions the tool.
#
#   Permission-map ordering is load-bearing: opencode takes the LAST
#   matching rule (docs: "put the * wildcard first and specific rules
#   after"). So a scoped writer emits `"*": deny` FIRST and the narrow
#   allow AFTER it; the reverse order denies everything, the exact
#   signature of the first T053 spawn (verdict file unwritable, git diff
#   blocked). Unmatched bash commands fall through to the global
#   opencode.json policy (ask; --auto approves) — reviewers' real guards
#   are their agent-definition mandate and the driver's staged-paths-only
#   commit, same as the Claude Code path.
#
# Body is copied verbatim — the prompt is shared. Re-run after any edit to a
# .claude/agents/*.md file.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

SRC_DIR=".claude/agents"
DST_DIR=".opencode/agent"

if [ ! -d "$SRC_DIR" ]; then
  echo "sync-agents: $SRC_DIR not found — nothing to sync." >&2
  exit 0
fi

mkdir -p "$DST_DIR"

# Transform Claude "tools:" list into an opencode permission map.
# Read-only reviewers (no Edit/Write) get edit: deny. Verdict-writing
# reviewers get edit allowed ONLY on target/runs/*.verdict: the wildcard
# deny MUST come first because opencode takes the last matching rule
# (docs §Agents — "put the * wildcard first and specific rules after").
# Never "ask": it hangs silently inside a non-interactive subagent
# (2026-07-16 review-freeze root cause) — under --auto, ask would also
# auto-approve, so deny is the honest block.
emit_permission() {
  local tools="$1" name="$2"
  echo "permission:"
  # Default: read-only. If Edit or Write appears in the list, the agent is a
  # writer and gets a narrow verdict-path allow instead of deny.
  if echo "$tools" | grep -Eq '\b(Edit|Write)\b'; then
    echo "  edit:"
    echo "    \"*\": deny"
    if [ "$name" = stargate-redteam ]; then
      echo "    target/runs/*.redteam.verdict: allow"
    else
      echo "    target/runs/*.verdict: allow"
    fi
  else
    echo "  edit: deny"
  fi
  # Read-side tools are always allowed for stargate reviewers.
  echo "  read: allow"
  echo "  glob: allow"
  echo "  grep: allow"
  # Bash: allow the read-only git inspection commands reviewers need.
  # Deliberately NO trailing wildcard deny — with last-match-wins it
  # would silence every allow above it, and unmatched commands belong to
  # the global opencode.json policy, not a per-agent block.
  if echo "$tools" | grep -Eq '\bBash\b'; then
    echo "  bash:"
    echo "    git diff*: allow"
    echo "    git log*: allow"
    echo "    git show*: allow"
    echo "    git status*: allow"
    echo "    git rev-parse*: allow"
  fi
}

count=0
for src in "$SRC_DIR"/*.md; do
  [ -f "$src" ] || continue
  name="$(basename "$src" .md)"
  dst="$DST_DIR/$name.md"

  # Split frontmatter from body. The frontmatter is the YAML between the
  # opening and closing '---' lines; the body is everything after.
  body_file="$(mktemp)"
  front_file="$(mktemp)"
  awk '
    BEGIN { state="pre"; fm_n=0 }
    state=="pre" && /^---[[:space:]]*$/ { state="fm"; next }
    state=="fm"  && /^---[[:space:]]*$/ { state="body"; next }
    state=="fm"  { print >("'"$front_file"'"); next }
    state=="body" { print >("'"$body_file"'"); next }
  ' "$src"

  # Extract fields we care about.
  description="$(grep -E '^description:' "$front_file" | head -1 | sed -E 's/^description:[[:space:]]*//')"
  tools="$(grep -E '^tools:' "$front_file" | head -1 | sed -E 's/^tools:[[:space:]]*//')"

  : > "$dst"
  {
    echo "---"
    printf 'description: %s\n' "$description"
    echo "mode: subagent"
    emit_permission "$tools" "$name"
    echo "---"
    echo
    cat "$body_file"
  } >> "$dst"

  rm -f "$body_file" "$front_file"
  count=$((count + 1))
  echo "sync-agents: $src → $dst"
done

echo "sync-agents: $count agent(s) mirrored. Restart opencode to load them."
