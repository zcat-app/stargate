# Agent CLI adapters

This directory holds the per-tool adapters that `scripts/agent-cli.sh`
dispatches to. The dispatcher isolates the workflow (`agent-task.yml`) and
any other caller from the quirks of each LLM CLI; the adapters are the only
place that knows how to invoke a specific tool.

## The contract (what every adapter must implement)

Each `scripts/agent-cli/<tool>.sh` defines a single shell function,
`run_agent()`, that:

- Reads these env vars (set by the dispatcher before sourcing the adapter):
  - `PROMPT_FILE` — absolute path to a file containing the prompt text.
  - `WORKDIR` — absolute path; the agent's working directory.
  - `MODEL` — empty (use the tool's default) OR a tool-specific model id.
  - `AGENT_NAME` — empty OR a tool-specific agent/subagent name (e.g. an
    opencode agent under `.opencode/agent/*.md`).
  - `AUTO_APPROVE` — `"true"` or `"false"`. CI sets true (the workflow's
    collaborator check already authorized the run); local users drop to
    false for per-action prompts.
  - `OUTPUT_FILE` — empty OR a path to capture the agent's final text.
- Exits 0 on success, non-zero on failure.
- Does NOT itself exit on a bright-line stop. Bright-line stops are
  `scripts/run-task.sh`'s job; an agent that stopped at a bright line
  still exited cleanly from the CLI's perspective.

## Selecting an adapter

```bash
# Default (opencode):
scripts/agent-cli.sh --prompt handoff.txt

# Override via env var:
AGENT_CLI=claude scripts/agent-cli.sh --prompt handoff.txt

# Add your own: drop scripts/agent-cli/mytool.sh defining run_agent(),
# then AGENT_CLI=mytool scripts/agent-cli.sh ...
```

The `agent-task.yml` CI workflow takes a `agent_cli` input (default:
`opencode`) so a run can override per-invocation.

## Current adapters

| File | Tool | Status |
|---|---|---|
| `opencode.sh` | opencode (`opencode run --auto ...`) | **Primary.** Verified against opencode CLI docs. |
| `claude.sh` | Claude Code (`claude -p`) | Stub. Best-guess invocation; verify before relying on it. |

## Auth

Each adapter handles its own auth, almost always via an environment variable
the agent CLI reads natively:

- opencode reads `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / etc. from env or
  `~/.local/share/opencode/auth.json`. CI sets the relevant key as a secret;
  the dispatcher does not manage auth.
- Claude Code reads `ANTHROPIC_API_KEY` from env.

The CI workflow exposes the secret as an env var in the runner; the adapter
does nothing special — the agent CLI picks it up.

## Why this design (and not just hardcode `opencode run`)

stargate's primary agent CLI is opencode, but "primary" is not "only".
Experimentation wants to try Claude Code, maybe Cursor, maybe a custom
internal runner. Hardcoding any one of these couples the workflow to a
single tool's CLI quirks (flag names change, auth models differ, output
formats drift). The dispatcher isolates those quirks here.

The contract is intentionally tiny — one shell function, six env vars,
two exit codes — so adding an adapter is a 20-line file. The dispatcher
itself never needs to change when an adapter is added or removed.
