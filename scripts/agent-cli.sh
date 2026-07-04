#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# agent-cli.sh — pluggable dispatcher that runs an LLM agent against a
# prompt file, used by .github/workflows/agent-task.yml to drive
# scripts/run-task.sh's emitted handoff prompts from CI.
#
# Why a dispatcher, not a hardcoded `opencode run`:
#   stargate's primary agent CLI is opencode. But "primary" is not "only" —
#   experimentation wants Claude Code (`claude -p`), maybe Cursor, maybe a
#   custom internal runner. Hardcoding any one of these couples the CI
#   workflow to a single tool's CLI quirks (auth flags, output formats,
#   working-directory handling). The dispatcher isolates those quirks in
#   per-tool adapter files under scripts/agent-cli/<tool>.sh; the workflow
#   and any other caller goes through this single entry point.
#
# Contract (what every adapter must implement):
#   scripts/agent-cli/<tool>.sh must define a `run_agent()` shell function
#   that reads the following env vars (set by this dispatcher before
#   sourcing the adapter):
#     PROMPT_FILE   — absolute path to a file containing the prompt text
#     WORKDIR       — absolute path; the agent's working directory
#     MODEL         — empty (use default) OR a tool-specific model id
#     AGENT_NAME    — empty OR a tool-specific agent/subagent name
#                     (opencode: an agent defined in .opencode/agent/*.md)
#     AUTO_APPROVE  — "true" or "false"; CI sets true (workflow already
#                     authorized via collaborator check); local sets false
#     OUTPUT_FILE   — empty OR a path to capture the agent's final text
#   The function must:
#     - exit 0 on success
#     - exit non-zero on failure (timeout, auth error, agent-CLI bug)
#     - NOT itself call exit on a bright-line stop — that's run-task.sh's
#       job; an agent that stopped at a bright line still exited cleanly
#
# Usage:
#   scripts/agent-cli.sh --prompt <file> [--workdir <dir>] [--model <m>]
#                        [--agent <name>] [--output <file>] [--no-auto]
#                        [--dry-run]
#   AGENT_CLI env var selects the adapter (default: opencode):
#     AGENT_CLI=opencode scripts/agent-cli.sh ...
#     AGENT_CLI=claude   scripts/agent-cli.sh ...
#     AGENT_CLI=mycustom scripts/agent-cli.sh ...   # uses scripts/agent-cli/mycustom.sh
#
# Exit codes: 0 = agent ran successfully; 1 = agent failed; 2 = usage /
# adapter-not-found / contract violation.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# --- defaults + arg parsing -------------------------------------------------
AGENT_CLI="${AGENT_CLI:-opencode}"
PROMPT_FILE=""
WORKDIR="$(pwd)"
MODEL=""
AGENT_NAME=""
OUTPUT_FILE=""
AUTO_APPROVE="true"   # CI default; override with --no-auto for local use
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prompt)  PROMPT_FILE="$(readlink -f "$2")"; shift 2 ;;
    --workdir) WORKDIR="$(readlink -f "$2")"; shift 2 ;;
    --model)   MODEL="$2"; shift 2 ;;
    --agent)   AGENT_NAME="$2"; shift 2 ;;
    --output)  OUTPUT_FILE="$(readlink -f "$2")"; shift 2 ;;
    --no-auto) AUTO_APPROVE="false"; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '3,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "agent-cli: unknown flag: $1" >&2; exit 2 ;;
  esac
done

[ -n "$PROMPT_FILE" ] || { echo "agent-cli: --prompt is required" >&2; exit 2; }
[ -f "$PROMPT_FILE" ] || { echo "agent-cli: prompt file not found: $PROMPT_FILE" >&2; exit 2; }

ADAPTER="scripts/agent-cli/${AGENT_CLI}.sh"
[ -f "$ADAPTER" ] || {
  echo "agent-cli: adapter not found for AGENT_CLI=$AGENT_CLI" >&2
  echo "  looked at: $ADAPTER" >&2
  echo "  available adapters:" >&2
  ls scripts/agent-cli/*.sh 2>/dev/null | sed 's/^/    /' >&2
  exit 2
}

# Export the contract env vars the adapter reads.
export PROMPT_FILE WORKDIR MODEL AGENT_NAME AUTO_APPROVE OUTPUT_FILE

if [ "$DRY_RUN" = "1" ]; then
  echo "agent-cli (dry-run): would source $ADAPTER and call run_agent"
  echo "  PROMPT_FILE:   $PROMPT_FILE ($(wc -c < "$PROMPT_FILE") bytes)"
  echo "  WORKDIR:       $WORKDIR"
  echo "  MODEL:         ${MODEL:-(adapter default)}"
  echo "  AGENT_NAME:    ${AGENT_NAME:-(adapter default)}"
  echo "  AUTO_APPROVE:  $AUTO_APPROVE"
  echo "  OUTPUT_FILE:   ${OUTPUT_FILE:-(none)}"
  exit 0
fi

# --- source adapter + invoke ------------------------------------------------
# Adapter defines run_agent(); we call it. The adapter's exit code IS our
# exit code — no swallowing.
source "$ADAPTER"
run_agent
