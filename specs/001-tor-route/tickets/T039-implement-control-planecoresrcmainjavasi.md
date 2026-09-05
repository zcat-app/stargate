---
id: T039
title: 'Implement `control-plane/core/src/main/java/.../SidecarMonitor.java`'
status: done
created: 2026-07-04
last_updated: 2026-09-05
source: tasks.md#T039
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T094a]
parallel: false
files_budget: 8
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §FR-012 (ControlPort reached only by SidecarMonitor + contract harness, via the cookie; NEVER host-published)
  - specs/001-tor-route/spec.md §FR-014 (SidecarEvent kinds; detail is a fixed-vocabulary token; advisory only)
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents · Contract" (v1 (kind, detail) pairings)
  - specs/001-tor-route/contracts/torrc.md §"Invariants" rows 3–4 + 11 (ControlPort + CookieAuthFileGroupReadable; cookie path)
  - specs/001-tor-route/data-model.md §4 (sidecar_healthy row shape) + §6 (stargate-tor-state identity)
  - THREAT-MODEL.md §4.2 (entry-guard state sensitivity) + §5.8 (CP→tor:9051 residue)
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-16 — docker-socket-proxy mechanism removed (T094a)"
  - specs/001-tor-route/tickets/T094a-drop-docker-socket-proxy-use-tor-cookie.md §Analysis "Grounding decisions" (cookie-read path deferred to T039, constrained by must-hold #2)
reviews: { round: 2, date: 2026-09-05, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T039: Implement `control-plane/core/src/main/java/.../SidecarMonitor.java`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/core/src/main/java/.../SidecarMonitor.java` — for the Tor sidecar only, emit `STARTED` + `HEALTHY` `SidecarEvent`s (with fixed-vocabulary `detail` `container_start`, `healthcheck_pass`) over the gRPC stream, **and** write a `sidecar_healthy` row to `audit_log` via `AuditLogService` (T036) on each transition into HEALTHY (`detail_json` shape per data-model.md §4).
>
> **Observation channel (T094a amendment):** the CP observes Tor via Tor's cookie-authenticated ControlPort at `tor:9051` over the compose-internal network, authenticating with the control cookie (`CookieAuthentication 1` + `CookieAuthFileGroupReadable 1`; `contracts/torrc.md` invariants #3–#4). This **replaces** the `docker-socket-proxy` Docker-Engine observer that T094a removed (the proxy's `CONTAINERS=1` ACL granted `GET /archive` over every container's filesystem, including Tor's entry-guard state — THREAT-MODEL §4.2). SidecarMonitor opens an authenticated control-port connection and polls Tor's bootstrap/health state on a bounded interval — the same surface the Tor Dockerfile's HEALTHCHECK probes (`GETINFO status/bootstrap-phase`, `PROGRESS=100` → `HEALTHY`). SidecarMonitor MUST connect only to `tor:9051` (never a host-published port — FR-012 forbids it), MUST authenticate with the cookie (no other control-port auth method), and MUST issue only the read-only `GETINFO`/`GETCONF` commands it needs. The narrow cookie-read volume + GID alignment that lands with this ticket MUST NOT over-grant read of Tor's entry-guard state beyond the cookie exchange (T094a §Analysis "Grounding decisions" constrains this). UNHEALTHY/STOPPED/CRASHED/RESTARTED transitions are added in T074.

## Analysis

Grounded 2026-09-05. Blockers verified done on disk: T009 (proto stubs +
`EventsGrpc` generated), T094a (proxy removed; `stargate-cp-tor` net up; the
narrow cookie-read is THIS ticket's payload). T038's `ControlGrpcService`
already exposes the emitter seam (`publish(SidecarEvent)`); core stays
gRPC-free — the monitor defines neutral ports (event record + sink, audit
sink) and T041's runtime wiring adapts them, mirroring the T035a
port-in-core / adapter-elsewhere pattern. `AuditLogService.write` (T036)
validates the §4 vocabulary; the monitor supplies
`action=sidecar_healthy, target=tor, detail_json={"generation":<gen>}`
(`<gen>` = current token generation via a `LongSupplier` port wired by T041;
`0` = none per §1.8).

### Property map (docs/process/analysis.md — required, `privacy_critical: true`)

**Must hold**

1. **COOKIE auth only.** `AUTHENTICATE` carries the lowercase hex of the
   cookie file (subpath-mounted at `/run/tor/control_auth_cookie`); no null
   auth, no other control-port auth method (ticket body; torrc invariants
   #3–#4; FR-012).
2. **Dial target pinned to `tor:9051`.** The monitor's only outbound dial is
   the configured (host, 9051) over `stargate-cp-tor`; never a host-published
   port (FR-012). This is the CP's sole outbound socket (Principle III).
3. **Read-only command allowlist.** Wire commands ⊆ {`AUTHENTICATE <hex>`,
   `GETINFO status/bootstrap-phase`, `QUIT`} — hard-coded literals; no
   reply-derived or external string is ever sent. Tor's control protocol has
   no per-command ACL (open finding 20260727-001 enumerates SETEVENTS /
   SETCONF / ATTACHSTREAM / ADD_ONION consequences), so the allowlist is the
   only policy-mechanism boundary the monitor itself owns.
4. **Fixed-vocabulary `detail`.** Emitted `detail` ∈ {`container_start`,
   `healthcheck_pass`} paired `STARTED→container_start`,
   `HEALTHY→healthcheck_pass`; Tor's reply text (bootstrap strings) never
   enters `detail`, events, or logs (control-grpc.md §"WatchEvents"; arch
   §5.2; FR-014).
5. **Edge-triggered audit.** Exactly one `sidecar_healthy` row per entry
   into HEALTHY (never while level); audit write failure logs a warning and
   never crashes the poll loop (Principle II — advisory surface).
6. **Narrow cookie read (T094a must-hold #2).** The CP container mounts ONLY
   the cookie file of `stargate-tor-state` (read-only volume `subpath`
   mount) — never the whole volume: entry-guard state stays unreadable
   (THREAT-MODEL §4.2). GID alignment: the tor image pins UID/GID 5103
   (`CookieAuthFileGroupReadable 1` → cookie 0640 `tor:tor`), the CP adds
   5103 as a supplementary group (`group_add`); the DP gets neither.
7. **Advisory + survivable (Principle II).** Failed cycles (connect refused,
   auth 5xx, cookie absent, malformed/oversized reply) emit nothing, write
   nothing, never throw out of the loop; bounded poll interval, bounded
   socket timeouts, bounded line reads (replies are external input —
   validated at this edge).
8. **Tests-first (Principle VII).** Auth is a mandatory test-first category:
   the unit suite pins must-holds 1–5 and 7 against a scripted fake control
   server, authored before the implementation.

**Gated** (verify.sh catches fail-closed)

- Must-holds 3, 4, 5, 7, 8: `SidecarMonitorTest` in the Maven test gate.
- Must-holds 1, 2, 6 (shape): extended `local_compose_test.sh` (new M14:
  CP's only `stargate-tor-state` mount is the cookie subpath, read-only;
  `group_add` literal == the Dockerfile-pinned GID; tor keeps the whole
  volume) + `docker compose config` render validating the subpath schema.
- License headers, ticket lint (verify.sh mechanical gates).

**Residue** (no gate catches; redteam focus)

- "No future code path in the monitor dials anywhere but the configured
  control port or sends any command outside the allowlist" — today's wire
  shape is unit-pinned, but a later edit could add a dial/command past the
  fake. → code review + redteam.
- "Cookie bytes never reach a log line" — the wire test pins the
  AUTHENTICATE line shape; future logging discipline is human. Monitor logs
  state tokens only.
- "The subpath mount actually yields a readable cookie and nothing else" —
  provable only at compose-up (docker-tagged runtime tests, release
  cadence); static M14 asserts the shape; T070 (pending) is the runtime
  gate.
- **Open finding interaction (reviewer must weigh):** `redteam/findings/
  open/20260727-001-tor-controlport-unbounded-cp-authority.md` (major,
  open, unadjudicated) contests the cookie-holding-CP design itself and
  proposes DP-relayed liveness or a ControlSocket instead. The spec —
  FR-012 as amended by T094a (round-1 APPROVE) — mandates the cookie
  channel, so T039 implements THAT design in its narrowest structural form
  (single-file subpath mount); the finding's disposition is a spec-level
  decision above this ticket and stays open. This ticket amends the now-
  stale THREAT-MODEL §5.8 cookie-isolation clause in the same change
  (same-PR rule) and names the authority surface; it does NOT adjudicate
  the finding, rewrite FR-012, or touch the torrc byte contract.

## Acceptance

1. **`SidecarMonitorTest`** (`control-plane/core/src/test/java/app/zcat/
   stargate/sidecar/`, JUnit 5, scripted fake ControlPort server on
   loopback) asserts, against `SidecarMonitor.runOnce()` cycles:
   - **a. Event sequence + vocabulary**: successful hex-cookie auth +
     `GETINFO status/bootstrap-phase` carrying `PROGRESS=100` emits
     `STARTED`/`container_start` then `HEALTHY`/`healthcheck_pass`, with
     `sidecar = "tor"` and a per-event timestamp.
   - **b. COOKIE auth only**: the AUTHENTICATE payload equals the lowercase
     hex of the seeded cookie bytes; the fake rejects null auth and any
     other method with `5xx` and the monitor treats it as a failed cycle.
   - **c. Command allowlist**: every wire line recorded across all cycles
     ∈ {`AUTHENTICATE <hex>`, `GETINFO status/bootstrap-phase`, `QUIT`}.
   - **d. Edge-triggered audit**: two consecutive healthy cycles → exactly
     one `sidecar_healthy` row (`target = tor`,
     `detail_json = {"generation":N}` from the injected generation
     supplier); `PROGRESS=95` then `PROGRESS=100` again → a second row; no
     rows on any cycle that does not ENTER healthy.
   - **e. Survivability**: connection refused / auth `5xx` / cookie file
     absent / malformed reply → no events, no rows, no throw; the next
     cycle still proceeds.
   - **f. No free text**: whatever bootstrap text the fake returns, every
     emitted `detail` ∈ {`container_start`, `healthcheck_pass`}.
2. **Narrow cookie read lands (T094a deferral)**:
   - `compose/docker-compose.local.yml`: `stargate-control` gains a
     read-only single-file volume `subpath` mount of
     `stargate-tor-state:control_auth_cookie` (target
     `/run/tor/control_auth_cookie`), `group_add: ["5103"]`, and
     `depends_on: {tor: {condition: service_healthy}}` (the subpath must
     exist at CP container create; tor's own healthcheck proves cookie
     presence). `sidecars/tor/Dockerfile` pins the tor user/group at
     UID/GID 5103 (matching the 5100–5102 plane scheme).
   - `tests/contract/compose/local_compose_test.sh` gains **M14**: the CP's
     ONLY `stargate-tor-state` mount is the cookie subpath (read_only,
     subpath literal `control_auth_cookie`); `group_add` == the
     Dockerfile-pinned GID (cross-file grep); tor mounts the whole volume
     at `/var/lib/tor`; no other service mounts `stargate-tor-state`.
3. **Same-PR doc honesty (Principle V)**: `data-model.md` §6
   `stargate-tor-state` row records the CP's single-file subpath read;
   THREAT-MODEL §5.8's "cookie … volume-isolated to `tor`" clause is
   amended for the CP read and names the control-authority surface
   (finding 20260727-001 referenced, disposition unchanged).
4. `python3 scripts/lint-ticket.py <ticket>` clean; `scripts/verify.sh`
   green.

## Out-of-scope

- T074's `UNHEALTHY`/`STOPPED`/`CRASHED`/`RESTARTED` events and
  `sidecar_unhealthy` rows.
- T041's runtime wiring (start order; the adapters monitor→
  `ControlGrpcService.publish` and monitor→`AuditLogService.write`).
- Disposing of redteam finding 20260727-001 (FR-012 redesign, torrc
  ControlSocket variant, THREAT-MODEL §5.15) — spec-level, stays open.
- The runtime cookie-mount regression inside
  `network_hardening_test.go` (docker-tagged) — follow-up candidate from
  the finding.
- torrc byte-contract changes (T087 owns the golden), T037
  `TorrcRenderer`, T062's Go control-port helper.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
