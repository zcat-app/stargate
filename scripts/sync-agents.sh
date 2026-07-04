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
#   tools: Read, Grep, Glob, Bash      → permission rules (read-only = deny
#                                         edit; allow the listed tools)
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
# Read-only reviewers (no Edit/Write) get edit: deny; everything else gets
# ask. Tools that have a per-pattern form (bash) get an explicit narrow allow.
emit_permission() {
  local tools="$1"
  echo "permission:"
  # Default: read-only. If Edit or Write appears in the list, the agent is a
  # writer and gets edit: ask instead of deny.
  if echo "$tools" | grep -Eq '\b(Edit|Write)\b'; then
    echo "  edit: ask"
  else
    echo "  edit: deny"
  fi
  # Read-side tools are always allowed for stargate reviewers.
  echo "  read: allow"
  echo "  glob: allow"
  echo "  grep: allow"
  # Bash: allow only the read-only git inspection commands reviewers need.
  if echo "$tools" | grep -Eq '\bBash\b'; then
    echo "  bash:"
    echo "    git diff*: allow"
    echo "    git log*: allow"
    echo "    git show*: allow"
    echo "    git status*: allow"
    echo "    git rev-parse*: allow"
    echo "    \"*: deny\""
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
    emit_permission "$tools"
    echo "---"
    echo
    cat "$body_file"
  } >> "$dst"

  rm -f "$body_file" "$front_file"
  count=$((count + 1))
  echo "sync-agents: $src → $dst"
done

echo "sync-agents: $count agent(s) mirrored. Restart opencode to load them."
