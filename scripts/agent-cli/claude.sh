#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Claude Code adapter for scripts/agent-cli.sh. Sourced, not executed; the
# shebang documents the shell dialect for editors and ShellCheck (T103 A4).
#
# Status: STUB. opencode is stargate's primary agent CLI; this adapter
# exists so the dispatcher's swappability is real and tested, not as a
# maintained parity target. If you switch to Claude Code as primary, fill
# in the verified invocation and remove this notice.
#
# Best-known invocation (verify against current Claude Code docs before
# relying on it): `claude -p` for non-interactive mode, with the prompt
# as the argument or piped via stdin. Auth via ANTHROPIC_API_KEY env var.
#
# What needs verification on first real use:
#   - exact flag names (Claude Code's CLI changes more often than opencode's)
#   - the equivalent of --auto for permission auto-approval
#   - whether --dir or a `cd` is needed for working-directory control
#   - output capture semantics (does claude -p emit just the final text,
#     or interleaved tool calls + reasoning?)

run_agent() {
  local prompt
  prompt="$(cat "$PROMPT_FILE")"

  # Best-guess invocation. Replace with verified flags when this adapter
  # becomes the primary.
  if [ -n "$OUTPUT_FILE" ]; then
    echo "$prompt" | claude -p > "$OUTPUT_FILE" 2>&1
  else
    echo "$prompt" | claude -p
  fi
}
