# Stargate — AI Assistant Context

Stargate is an open-source, multi-protocol privacy-routing proxy. A browser
extension picks the route per request (Tor, I2P, Nym mixnet, Direct); the
proxy forwards bytes to the appropriate sidecar. Family-shareable, Docker
deployed, privacy-first.

## Source of truth

**Before any non-trivial change, read `.specify/memory/constitution.md`.**
It defines 8 binding principles and is the authoritative source for design
decisions. All specs and code must comply; conflicts are resolved by
amending the constitution (governance section), not the code.

Related artefacts (some may not exist yet — author when needed):

- `.specify/memory/constitution.md` — principles, scope, governance.
- `specs/` — feature specifications produced via spec-kit slash commands.
- `ARCHITECTURE.md` — concrete system design (modules, ports, schemas).
- `THREAT-MODEL.md` — per-deployment-mode and per-route threat models.
- `SECURITY-DECISIONS.md` — append-only log of accepted-finding rationales.
- `CONTRIBUTING.md` — contributor onboarding, AI-assisted workflow guidance.
- `BUILD-DIFFS.md` — expected variations in native-image reproducibility.

<!-- SPECKIT START -->
**Current plan**: `specs/001-tor-route/plan.md` (Tor route v1 vertical
slice — first end-to-end working route; local profile only, manual
bearer-token config). Phase 0/1 artefacts alongside: `research.md`,
`data-model.md`, `quickstart.md`, `contracts/`.

For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
and its sibling artefacts.
<!-- SPECKIT END -->

## Architecture at a glance

Two processes, distinct lifecycles, gRPC over Unix socket between them:

| Plane | Language | Responsibility |
|---|---|---|
| **Data plane** | Go | Network transport, sidecar coordination, per-port routing. Privacy-critical hot path. |
| **Control plane** | Quarkus (JDK 21+) | Admin UI, settings, sidecar lifecycle commands, audit. SQLite for state. |

The **data plane is a dumb router** (Constitution Principle I): no payload
parsing, no TLS termination, no local DNS resolution, no header inspection,
no per-request logs, no cover traffic. Routing decisions are made by the
browser extension; the proxy forwards bytes for the port it received them on.

The data plane **must continue routing if the control plane is unreachable**
(Principle II).

## Deployment

Docker Compose stack, three profiles:

- `docker-compose.local.yml` — loopback only, single user.
- `docker-compose.lan.yml` — WireGuard sidecar; household multi-device.
- `docker-compose.vps.yml` — WireGuard/Tailscale tunnel from devices to VPS.

The proxy refuses to start if it would bind a non-loopback interface without
a corresponding tunnel sidecar in the same compose stack.

## v1 scope

- Routes: Tor (`.onion` + optional clearnet-via-Tor-exit), I2P (`.i2p`),
  Nym mixnet (clearnet), Direct.
- IPFS deferred to v2 — port `8883` is reserved.
- Tor bridges supported, toggleable, default off.
- Reference browser: **Mullvad Browser** (first-class). LibreWolf
  tested-secondary. Chromium browsers explicitly unsupported.

## Spec-driven development

All non-trivial work flows through spec-kit:

1. `/speckit-specify` → `specs/NNN-feature/spec.md`
2. `/speckit-clarify` (optional)
3. `/speckit-plan` → must include a **Constitution Check** gate
4. `/speckit-tasks` → task list
5. `/speckit-implement` → executes tasks

For privacy-critical code (DNS, routing, headers, auth, sidecar contracts),
**tests are written before implementation** (Principle VII). Tests are
derived from the spec, then implementation is driven to satisfy them.

## Adversarial review

Each feature spec and each release passes review by two subagents (defined
under `.claude/agents/` when scaffolded):

- `stargate-redteam` — security/privacy fresh-eyes pass.
- `stargate-perf` — performance and resource pass.

Blocker / Major findings are resolved or accepted with rationale in
`SECURITY-DECISIONS.md` (append-only).

## Conventions for AI-assisted contributions

- **Constitution is authoritative.** When in doubt, re-read it.
- **Comment the *why*** of non-obvious decisions; link back to the
  principle / spec / threat-model entry. Skip "what" comments for
  self-explanatory code.
- **Tests-first** for privacy-critical paths; tests derived from the spec.
- **No outbound network connections** from Stargate except those a request
  explicitly routes through. Status, monitoring, notifications are
  local-only in v1.
- **License is Apache 2.0.** New files carry the standard header.
