#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# opencode adapter for scripts/agent-cli.sh. Sourced, not executed; the
# shebang documents the shell dialect for editors and ShellCheck (T103 A4).
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
# Permission model: the adapter passes --auto exactly when AUTO_APPROVE=true,
# the dispatcher's default (CI). `scripts/agent-cli.sh --no-auto` sets it
# false, and opencode then asks before each `ask` permission (T191 item 6:
# the hint was previously inert because --auto was unconditional). With
# --auto, opencode approves every permission that is not explicitly denied,
# so each `ask` in opencode.json becomes a yes. opencode
# applies the LAST bash rule whose wildcard matches each command of a
# pipeline or list, so opencode.json ends its bash map with deny rules for
# `git push*` and the usual exfiltration commands (curl, wget, nc, ncat,
# socat, ssh, scp, env, printenv); --auto cannot override a deny
# (T191 item 6; ci_inputs_test.sh checks the last-match result).
#
# Those rules match command TEXT. They are a tool control, not a sandbox: an
# allowed interpreter (`bash -c`, `python3`, `go run`) reaches the same
# capability. What CI safety actually rests on:
#   (a) the workflow's collaborator check (only write-access users trigger);
#   (b) credentials: the agent job holds a read-only token that is never
#       persisted to .git/config, so the agent cannot push anything; only a
#       separate publish job pushes agent/$TICKET (.github/workflows/
#       agent-task.yml). The provider API key IS in the agent's environment
#       and an auto-approved agent can read it; the collaborator check is the
#       only control on who can start such a run.
# For per-action prompts locally, pass --no-auto to scripts/agent-cli.sh.
#
# This adapter is the canonical opencode invocation. If you want to tweak
# flags (add --thinking, switch format, attach a different file), edit HERE
# — do not fork the dispatcher.

run_agent() {
  local prompt
  prompt="$(cat "$PROMPT_FILE")"

  # Build the argv. --dir is unconditional; --auto follows AUTO_APPROVE
  # (dispatcher contract); --agent and --model only when explicitly requested
  # (the adapter does NOT pick a default agent/model — that's the dispatcher
  # caller's decision, leaving the adapter a pure translator).
  local argv=(opencode run)
  [ "$AUTO_APPROVE" = "true" ] && argv+=(--auto)
  argv+=(--dir "$WORKDIR")
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
