# Stargate — Agent Context (tool-agnostic)

> **This file is the canonical entry-point for any coding agent** — opencode,
> zcode, Claude Code, or any other. Tool-specific shims (`CLAUDE.md`,
> `.github/copilot-instructions.md`) point here; they do not duplicate it.
> **If anything in this file conflicts with the authoritative sources below,
> those win — flag the drift and stop the affected implementation. A user-authorized
> reconciliation/amendment may proceed under Governance; do not treat drift as permission to ship it.**

## What Stargate is

An open-source, multi-protocol **privacy-routing proxy**. A browser extension
picks the route per request (Tor, I2P, Nym mixnet, Direct); the proxy forwards
bytes to the appropriate sidecar. Family-shareable, Docker-deployed,
privacy-first. License: Apache 2.0.

## Authoritative sources (read before any non-trivial change)

| Source | Authority |
|---|---|
| `.specify/memory/constitution.md` | **Binding.** 8 principles; fix conflicting code/specs first; policy changes require governed amendment. |
| `THREAT-MODEL.md` | Per-deployment-mode and per-route threat models. A change touching threat-model surfaces updates this **in the same PR**. |
| `CONTRIBUTING.md` | Workflow, code style per plane, PR norms, AI-assisted-workflow doctrine. |
| `.specify/memory/review-loop.md` | Per-task review loop: round cap, escalation menu, must-shrink. |
| `docs/process/workflow.md` | The lifecycle + procedure every ticket follows (skills are procedure-only thin wrappers around this). |
| `docs/process/ticket-template.md` | The YAML frontmatter schema for executable work units. |
| `specs/NNN-feature/` | Feature specs, plans, contracts, and tickets. |
| `SECURITY-DECISIONS.md` | Append-only log of accepted-finding rationales (append when a Blocker/Major finding is accepted). |

## Architecture at a glance

Two processes, distinct lifecycles, gRPC over Unix socket between them:

| Plane | Language | Responsibility |
|---|---|---|
| **Data plane** | Go (`data-plane/`) | Network transport, sidecar coordination, per-port routing. Privacy-critical hot path. |
| **Control plane** | Quarkus 3.33 LTS on JDK 25 LTS (`control-plane/`) | Admin UI, settings, sidecar lifecycle commands, audit. SQLite for state. |
| **Extension** | JS/TS (`extension/`) | Per-request route selection. First-class target: Mullvad Browser. |

The **data plane is a dumb router** (Constitution Principle I): no payload
inspection, no termination of tunneled application TLS, no destination DNS, no application
header inspection, no per-request logs, no cover traffic. Narrow proxy negotiation and
authenticated management TLS follow Principles I/II; they do not authorize payload inspection. It **must keep routing if the control
plane is unreachable** (Principle II).

Deployment: Docker Compose, three profiles — `local` (loopback-only),
`lan` (WireGuard sidecar), `vps` (WireGuard/Tailscale tunnel). The proxy
binds route/admin listeners only to loopback (local) or the actual tunnel interface
in the listener namespace (LAN/VPS). Container flags and a tunnel elsewhere in the
stack cannot bypass refusal; tunnel loss must not expose a fallback listener.

## How work happens (the short version)

Every non-trivial change is **spec-driven** and **ticket-driven**:

1. **Spec**: `/speckit-specify` → `specs/NNN-feature/spec.md`.
2. **Plan**: `/speckit-plan` → `plan.md` (must include a Constitution Check).
3. **Tasks**: `/speckit-tasks` → `tasks.md` (the spec-kit plan; regenerated).
4. **Tickets**: `scripts/bootstrap-tickets.sh` → `specs/NNN-feature/tickets/T-NNN-*.md`
   (executable work units with lifecycle state; **not** overwritten by `/speckit-tasks`).
5. **Pick + drive**: `scripts/next-task.sh` resolves the runnable set;
   `scripts/run-task.sh <id>` is the loop driver — does the deterministic
   phases directly (verify, status transitions, squash-merge), emits
   structured handoff prompts at the non-deterministic phases (ground,
   implement, codereview). Resume-aware: enters at the right phase based on
   ticket `status:`. `scripts/handoff.sh <id>` writes a session handoff
   (gitignored, under `specs/<feature>/.handoffs/`) for cross-session resume.
   `scripts/regen-status.sh` regenerates the STATUS board from frontmatter.
   The future `/run` autopilot wraps `run-task.sh` and feeds the handoff
   prompts back to itself unattended, stopping only on bright-line conditions.

Full procedure: `docs/process/workflow.md`. Round cap, must-shrink, escalation
menu: `.specify/memory/review-loop.md`.

## Working doctrine (from CONTRIBUTING.md — applies to every change)

- **Constitution is authoritative.** Re-read it before privacy-critical work.
- **Tests-first for privacy-critical paths** (DNS, routing, headers, auth,
  sidecar contracts) — Constitution Principle VII, **no AI exception**. Tests
  are derived from the spec, then implementation is driven to satisfy them.
- **Falsify before publishing.** Every claim is a hypothesis. Name what would
  make it false and check *that* — re-confirming supporting evidence is
  confirmation, not verification.
- **Surgical changes only.** Every changed line traces to an acceptance
  criterion, the explicit request, or an orphan your own change created. No
  drive-by edits. Spotted a real bug mid-task? File a follow-up — don't expand
  scope.
- **Ground before acting.** Read the whole task and verify state on disk
  *before* batching edits or running a build that depends on it.
- **No defensive code inside trust boundaries.** Validate at system edges
  (external input, config parsing, deserialization, IPC, file I/O); inside
  those boundaries, internal-to-internal calls are trusted.
- **Comment the *why*** of non-obvious decisions; link the principle / spec /
  threat-model entry. Skip "what" comments for self-explanatory code.
- **Enforce Constitution III's actor/traffic matrix.** DP/CP have no independent
  public-network egress. Sidecar-native maintenance and explicitly invoked isolated
  update retrieval do not authorize proxy probes, polling, telemetry or remote notifications.
- **No secrets in prompts.** No bearer tokens, no admin enrollment codes, no
  private keys, no production DB dumps.
- **Cite the principle when constraining an agent.** "Principle I says the
  data plane must not parse payloads — rewrite without the header inspection"
  is precise; "make it more private" is not.

## Verification — the single green gate

`scripts/verify.sh` is the deterministic answer to "is the tree green?" It is
**phase-aware**: each gate self-detects whether it has anything to run and
reports SKIP when code does not exist yet. A green run is valid only while the
tree is unchanged. Run it from the repo root before any review/commit.

Companion: `scripts/ground-check.sh` (external-pin grounding, offline by
default). Hooks: `.githooks/pre-commit` (secret scanner),
`.githooks/pre-push` (main guard).

## Tool-specific notes

| Tool | Reads | Writes / drives |
|---|---|---|
| **opencode** | `AGENTS.md` (this file), `opencode.json`, `.opencode/agent/*.md`, `.opencode/skills/*/SKILL.md` | Subagents via `Task` tool. Permission rules in `opencode.json`. |
| **Claude Code** | `CLAUDE.md` (thin pointer to this file), `.claude/agents/*.md`, `.claude/skills/*/SKILL.md`, `.claude/settings.local.json` | Slash commands, subagents via `Task` tool. |
| **zcode / others** | `AGENTS.md` + the authoritative sources above | Use `scripts/*` directly; the workflow is shell-backed and tool-agnostic. |

To keep agents in sync across tools: `.claude/agents/` is the canonical source;
`scripts/sync-agents.sh` regenerates `.opencode/agent/` mirrors. Run it after
editing any `.claude/agents/*.md`.

## Suggested model usage

- **Long-context / planning / threat-modelling / adversarial review**:
  Opus-class (the `stargate-redteam` and `stargate-perf` subagents default here).
- **Routine implementation / refactoring / test-writing** (once the spec is
  stable): Sonnet-class.
- **Per-task code review** (`stargate-codereview`): Opus-class, fresh context,
  blind to the implementer's rationale.

> **Known drift (2026-07-16).** The Opus-class guidance above is aspirational:
> no Opus-capable provider is configured in opencode (the only provider is
> `zai-coding-plan`, serving `glm-*`). The opencode review agents are now
> explicitly pinned to `zai-coding-plan/glm-5.2` in `opencode.json` so their
> model is deterministic rather than inherited — still not Opus-class. The
> Claude Code path is unaffected and already correct: `.claude/agents/*.md`
> pin `model: opus` (codereview, redteam) and `model: sonnet` (perf), which
> Claude Code resolves natively. To fully close this on the opencode side: add
> an Opus-class provider and repoint the three `model` fields.

The review agents (`stargate-codereview`, `stargate-redteam`, `stargate-perf`)
are `task: deny` in `opencode.json` **on purpose**: they must not spawn child
subagents. A child resolves permissions against the global config (whose bash
catch-all is `"ask"`), and an `"ask"` inside a non-interactive subagent hangs
silently until interrupted — the root cause of the 2026-07-16 review freezes.
These agents receive the diff in their prompt and inspect it with their own
allow-listed, fail-fast (`"deny"`, never `"ask"`) git tools. Do not remove
`task: deny` without first making every subagent safe under `"ask"` (e.g.
running autopilot with `--auto`, which auto-approves anything not explicitly
`"deny"`). See `.claude/skills/run/SKILL.md` "Cross-cutting rules".
