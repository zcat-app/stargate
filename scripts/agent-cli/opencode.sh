# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# opencode adapter for scripts/agent-cli.sh. Sourced, not executed.
#
# Invocation: `opencode run` (non-interactive). Per opencode CLI docs:
#   opencode run [message..]
#     --agent <name>      use a specific agent from .opencode/agent/*.md
#     --model <p/m>       provider/model override (e.g. anthropic/claude-...)
#     --dir <dir>         working directory
#     --auto              auto-approve permissions not explicitly denied
#     --file <path>       attach a file to the message
#     --format <fmt>      default (formatted) or json (raw events)
#
# Auth: opencode reads API keys from env (ANTHROPIC_API_KEY etc.) or
# ~/.local/share/opencode/auth.json. For CI, set ANTHROPIC_API_KEY (or
# whatever provider key matches --model) as a GitHub secret; the workflow
# exposes it as an env var that opencode picks up automatically.
#
# Permission model: with --auto, opencode auto-approves everything not
# explicitly DENIED in opencode.json's permission rules. The stargate
# opencode.json denies edit/bash on sensitive paths; --auto cannot override
# deny rules. CI safety therefore comes from (a) the workflow's collaborator
# check (only write-access users can trigger), and (b) opencode.json's deny
# rules. Local users drop --no-auto to get per-action prompts.
#
# This adapter is the canonical opencode invocation. If you want to tweak
# flags (add --thinking, switch format, attach a different file), edit HERE
# — do not fork the dispatcher.

run_agent() {
  local prompt
  prompt="$(cat "$PROMPT_FILE")"

  # Build the argv. --auto and --dir are unconditional; --agent and --model
  # only when explicitly requested (the adapter does NOT pick a default
  # agent/model — that's the dispatcher caller's decision, leaving the
  # adapter a pure translator).
  local argv=(opencode run --auto --dir "$WORKDIR")
  [ -n "$AGENT_NAME" ] && argv+=(--agent "$AGENT_NAME")
  [ -n "$MODEL" ]      && argv+=(--model "$MODEL")

  # Capture output if requested. opencode's stdout is the agent's final text
  # (or raw JSON events with --format json; we keep default formatted text).
  if [ -n "$OUTPUT_FILE" ]; then
    "${argv[@]}" "$prompt" > "$OUTPUT_FILE" 2>&1
  else
    "${argv[@]}" "$prompt"
  fi
}
