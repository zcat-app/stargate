# Prompt 01 — Write the architecture spec

Goal: produce `specs/000-architecture/spec.md` capturing the concrete system
design for Stargate, derived from and consistent with the constitution.

## Before you start

Read these in order:

1. `.specify/memory/constitution.md` — the 8 principles + Tech Stack /
   Deployment / Non-Goals sections. This is **authoritative**.
2. `CLAUDE.md` — quick-reference architecture overview.

If anything in the constitution is unclear, surface the ambiguity rather than
guessing. Do not invent decisions the constitution doesn't authorise.

## Deliverable

Create `specs/000-architecture/spec.md`. This is a **pre-feature spec**
documenting the system shape that v1 features will build inside. Use this
outline (sections may be merged or split as the content suggests, but cover
all of these areas):

### Required sections

1. **Purpose & scope** — one paragraph. What this spec defines and what it
   defers to feature specs.
2. **High-level topology** — diagram (ASCII is fine) of browser → extension →
   proxy ports → sidecars → networks. Include WireGuard sidecar for LAN/VPS
   profiles.
3. **Repository layout** — concrete directory tree. Two top-level modules:
   - `data-plane/` — Go module (proxy core, sidecar coordination).
   - `control-plane/` — Quarkus multi-module Maven project.
   - `extension/` — WebExtensions JavaScript.
   - `proto/stargate/v1/` — protobuf schemas.
   - `tests/contract/<sidecar>/` — sidecar contract test suites.
   - `compose/` — `docker-compose.{local,lan,vps}.yml`.
   - `scripts/` — `stargate init`, `enroll`, `export`, `import`, `wipe`.
4. **Port assignments** — exhaustive table of every listening port across
   all components, with binding interface per deployment profile. Reserve
   port `8883` for IPFS (deferred v2). Suggested defaults:
   - `8881` — Tor route (HTTP/SOCKS forward)
   - `8882` — I2P route
   - `8883` — RESERVED, IPFS (v2)
   - `8884` — Mixnet (Nym) / Direct (clearnet)
   - Pick concrete numbers for: control-plane admin UI, gRPC Unix socket
     (path, not port), Tor SOCKS, i2pd HTTP, Nym SOCKS, WireGuard.
5. **Inter-plane gRPC contract sketch** — high-level surface for `proto/stargate/v1/control.proto`.
   At minimum (you may add):
   - `EnableProtocol(port) / DisableProtocol(port)`
   - `ReloadTokens(list)`
   - `RestartSidecar(name)`
   - `GetStatus() → per-sidecar health + aggregate counters`
   - Streaming `WatchEvents() → sidecar lifecycle events`
   Note mutual-auth scheme (keys generated at install, stored in compose
   volume mounted only on both planes).
6. **SQLite schema sketch** — tables for: `enrolled_devices` (name, pubkey,
   bearer-token-hash, created_at), `admin_credentials` (webauthn credential
   ids), `tor_bridges` (line, transport, enabled), `aggregate_counters`
   (route, count, hour-bucket), `audit_log` (admin actions, append-only).
   No per-user routing history; Principle III forbids it.
7. **Sidecar image strategy** — pin candidate digests for each (Tor, i2pd,
   Nym client) by reading their official docs / Docker Hub. If you can't
   resolve a specific digest from the current state, mark `NEEDS CLARIFICATION`
   with the reason; do not invent digests.
8. **Sidecar config generation** — does the control plane write sidecar
   config files, or are they templated at compose-up time, or are they
   static in the image? Make a defensible decision and document why. Cover:
   Tor `torrc` (especially when bridges toggle on/off), i2pd config,
   Nym config.
9. **Init script behaviour** — concrete steps `scripts/stargate init`
   performs, expected output format (the user wants a status table), failure
   modes, idempotency (re-running init must be safe).
10. **Error response contract** — when a sidecar is unreachable / misbehaving,
    what HTTP response does the proxy return to the browser? Strict template
    (no exit IPs, no upstream addresses, no timing). Define a small set of
    error codes; contract test pattern that verifies the template is
    privacy-safe.
11. **Hot reload vs restart matrix** — for each kind of config change:
    bearer-token list, port topology, sidecar version, Tor bridges, admin
    credentials. State whether change applies live or requires restart of
    which component.
12. **Build pipeline** — Go static binary build flags
    (`-trimpath -buildvcs=false -ldflags='-s -w'` etc.), Quarkus native-image
    invocation, extension zip packaging. Note reproducibility tier per
    Principle VI.
13. **Backup / restore / decommission** — concrete `scripts/stargate
    {export,import,wipe}` behaviour. Export bundle format (encrypted tarball
    with passphrase), what it includes and excludes, restore flow, what
    `wipe` removes and what it cannot remove.
14. **Browser extension architecture** — manifest version, permissions list
    (each with justification), `proxy.onRequest` routing logic sketch,
    storage layout in `browser.storage.local`, install-time config audit
    flow, anti-pattern blocklist data structure.
15. **Open questions** — `NEEDS CLARIFICATION` items for anything you
    could not resolve from the constitution. Do not invent answers.

### Constraints

- **No implementation code** in this spec. Schemas, ports, config keys are
  fine; method bodies are not.
- **Cite the constitution** by principle number where a design choice is
  driven by it. e.g. *"Per Principle III, the proxy MUST resolve hostnames
  only at the upstream sidecar (SOCKS5h); the relevant code path is in
  `data-plane/internal/forward/socks5.go`."*
- **Flag any deviation** from constitution intent as `NEEDS CLARIFICATION`
  and stop — that's an amendment-flow decision, not a spec decision.
- **Do not start implementing.** This is a planning artefact. Stop when
  the spec is complete.

### Definition of done

- File exists at `specs/000-architecture/spec.md`.
- All 15 required sections present (or merged into clearly-named alternatives).
- Every concrete number/identifier/path is either defined or marked
  `NEEDS CLARIFICATION`.
- A reader who has read only the constitution + this spec can describe the
  system end-to-end in their own words.
- No code files created; only the spec document.

When done, summarise what's in the spec (top-level outline) and list any
`NEEDS CLARIFICATION` items that need user resolution before the spec is
implementation-ready.
