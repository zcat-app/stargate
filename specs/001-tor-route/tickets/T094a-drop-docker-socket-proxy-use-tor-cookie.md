---
id: T094a
title: 'Drop docker-socket-proxy; use Tor cookie-auth control port'
status: pending
created: 2026-07-16
last_updated: 2026-07-16
source: specs/001-tor-route/tickets/T094-harden-compose-network-boundaries.md (decomposed)
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T089, T090]
parallel: false
files_budget: 14
privacy_critical: true
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §16.1
  - specs/001-tor-route/spec.md §FR-012
  - specs/001-tor-route/contracts/torrc.md §"Invariants" (rows 3 + 4: ControlPort + CookieAuthFileGroupReadable)
  - THREAT-MODEL.md §5.8
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-04 — docker-socket-proxy trust rationale"
  - SECURITY-DECISIONS.md §"2026-07-06 — docker-socket-proxy CONTAINERS=1 read surface"
decomposed_from: T094
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T094a: Drop docker-socket-proxy; use Tor cookie-auth control port

## Context

Decomposed from T094 (which exceeded `files_budget: 10`). T094's Context:
the local stack gives every service access to a generic Docker API observer
(the `docker-socket-proxy`), and request admission is no longer controlled
by control-plane events (T090 removed that gating), so the generic Docker
socket proxy is unnecessary for routing correctness. This child removes the
proxy as an auxiliary container and points the CP's Tor-lifecycle
observation at the **cookie-authenticated Tor ControlPort** — a surface that
already exists: `contracts/torrc.md` invariants #3 (`ControlPort
0.0.0.0:9051`) and #4 (`CookieAuthFileGroupReadable 1`, so the cookie is
group-readable by volume callers) plus the T062 control-port helper
(`tests/contract/tor/control_port.go`) already make that channel usable
without privilege escalation.

The sibling child **T094b** (split compose networks + container hardening +
the docker-backed regression test) is blocked on this one: both edit
`compose/docker-compose.local.yml` and `tests/contract/compose/local_compose_test.sh`,
so they serialise. T094a leaves the stack on a single `stargate-internal`
network (the network split is T094b's mandate).

## Analysis

- **Must hold:**
  - No service in `compose/docker-compose.local.yml` mounts
    `/var/run/docker.sock`; the `docker-socket-proxy` service is gone; the
    CP no longer `depends_on` it (Constitution Principle III — no
    auxiliary host-root-pivot surface).
  - The CP observes Tor lifecycle through Tor's cookie-authenticated
    ControlPort (`tor:9051`), reusing the `CookieAuthFileGroupReadable`
    invariant + the T062 control-port helper — NOT through a Docker Engine
    observer. The cookie is obtained through a narrow, documented,
    read-only path; the CP gains no read access to Tor's entry-guard state
    beyond what that exchange requires (THREAT-MODEL §4.2 guard-state
    sensitivity).
  - The superseding `SECURITY-DECISIONS.md` entry records the proxy
    mechanism's removal (append-discipline: new dated entry; `Superseded
    by:` back-links on the 2026-07-04 + 2026-07-06 entries; their prose
    stays verbatim). T019c's ticket body is NOT rewritten (acceptance #5).
  - Every spec/plan/threat-model row that names the proxy as the CP's
    observation mechanism is amended in the same change (Principle V — no
    governance artifact may describe a proxy the code lacks).
  - `scripts/verify.sh` is green: the two cross-consistency tests that
    hard-assert the removed entry/section/digest are removed (not left red).
- **Gated:**
  - `tests/contract/compose/local_compose_test.sh` (rewritten here) keeps
    gating port exposure, UID/GID numerics, the seven named volumes, and
    DP `no-depends_on` (Principle II) — minus the proxy-specific M4/M5/M9
    assertions.
  - `scripts/lint-ticket.py` + license-header gate cover mechanical shape.
  - T094b's docker-backed regression test (later) gates the negative-path
    network properties; this ticket does not assert them.
- **Residue:**
  - The least-privilege cookie-access mechanism is the load-bearing
    privacy surface `stargate-redteam` should hunt. See grounding below.
  - arch §16.1 becomes "no auxiliary containers" or is folded into the Tor
    section — the exact structural edit is a grounding decision; the
    must-hold is "no stale proxy prose remains."

### Grounding decisions (2026-07-16 /run T094a)

- **Cookie-access mechanism — NOT wired in T094a; deferred to T039.**
  Grounding against `sidecars/tor/Dockerfile` + the live-sidecar contract
  test (`tests/contract/torrc/live_sidecar_test.go` §"Control-port
  access", lines 40-46) shows the cookie lives at
  `/var/lib/tor/control_auth_cookie` on `stargate-tor-state`, mounted
  ONLY into tor; the AUTHENTICATE exchange runs INSIDE tor as USER tor
  because **no peer can read the cookie today** (T062's Go-side client
  is still `pending`). The only compose-only CP mechanisms either (a)
  mount all of `stargate-tor-state` :ro into the CP — over-granting
  entry-guard read, violating must-hold #2 / THREAT-MODEL §4.2 and
  recreating the `/containers/archive` exfil the proxy's removal exists
  to close — or (b) relocate the cookie via a `CookieAuthFile` directive,
  a torrc byte-contract change owned by T087 and explicitly out of bounds
  (T094b Out-of-scope). T094a therefore removes the Docker observer and
  preserves `tor:9051` reachability (shared `stargate-internal` network)
  **without** adding a CP cookie mount; the narrow cookie-read path +
  GID alignment lands with T039 (SidecarMonitor impl), constrained by
  must-hold #2. The compose why-comment records this. (Acceptance #1's
  "wire the CP to read the cookie" resolves to: surface established +
  documented; volume deferred for the must-hold-#2 safety reason above.)
- **THREAT-MODEL.md — NO edit.** A grep of `THREAT-MODEL.md` finds ZERO
  `docker-socket-proxy` / `2375` / root-pivot references; §5.8 (Sidecar
  compromise) and §3.1 (Local profile) never name the proxy. Acceptance
  #6's "drop the proxy from §5.8 / §3.1" is a no-op (nothing to drop);
  §3.1's "Docker daemon" trusted-party line stays (it predates the proxy
  and is mode-level, not proxy-level). The "Docker isolation is not a
  sandbox" note belongs to **T094b** (its acceptance #5), not T094a.
  Falsified per "falsify before publishing."
- **T039 / T074 — `blocked_by` amended `T094` → `T094a`.** Both carry
  `blocked_by: [..., T094, ...]`; T094 is now `deferred` (decomposed), so
  it can never reach `done` and would strand both tickets un-runnable.
  T094a is the real blocker (it establishes the control-port surface
  T039's SidecarMonitor targets). Folded into the acceptance #11 edits
  (same two files — no budget cost).
- **quickstart.md — orphan cleanup.** Its "docker ps will also list a
  fourth container, docker-socket-proxy" blockquote becomes false the
  moment the proxy service is removed; updated for operator-facing
  honesty (Principle V). Consumes the one file of budget headroom freed
  by the THREAT-MODEL no-op.
- **Verify-gate safety (confirmed):** `scripts/ground-check.sh:207-216`
  skips `stargate/*` build-keyed image refs and tolerates zero external
  refs (`:242-244`), so removing the only external image stays GREEN;
  `tests/contract/security-decisions/tor_entry_test.sh` has NO functional
  dependency on the proxy entry (mentions are comment-only); the
  `sidecarproxy` Go package has NO external importers (safe to delete the
  directory).

## Acceptance

1. `compose/docker-compose.local.yml`: remove the `docker-socket-proxy`
   service, its `/var/run/docker.sock` mount, and the proxy `environment`
   block; drop `docker-socket-proxy` from `stargate-control.depends_on`.
   Wire the CP to read the Tor control cookie via a narrow read-only path
   (grounding decides sub-path mount vs. dedicated volume; the
   `CookieAuthFileGroupReadable` invariant is load-bearing). Add a why-
   comment citing T094a + Principle III.
2. `compose/env/local.env.example`: remove the `DOCKER_SOCKET_PROXY_IMAGE=`
   line and its comment block (the image is no longer pulled).
3. `specs/000-architecture/spec.md` §16.1: replace the docker-socket-proxy
   auxiliary-container section so it no longer describes a proxy the code
   lacks; record the cookie-auth ControlPort as the CP's Tor-observation
   surface (or fold into the Tor sidecar section — grounding decides).
4. `specs/001-tor-route/spec.md` §FR-012: amend the "only the contract-
   test harness needs ControlPort access" clause — the CP (SidecarMonitor)
   now also reaches `tor:9051` via cookie auth; ControlPort is still NEVER
   host-published.
5. `specs/001-tor-route/plan.md`: amend the service-topology table rows
   for `stargate-control` (observe via cookie-auth control port) and
   remove the `docker-socket-proxy` row + the "privacy TCB" paragraph that
   names it.
6. `THREAT-MODEL.md`: §5.8 drop the docker-socket-proxy from sidecar-
   compromise mitigations; §3.1 keep the Docker daemon as a trusted party
   but drop the proxy-as-host-root-pivot residual; fix any §16.1 cross-refs.
7. `SECURITY-DECISIONS.md`: add a new dated (reverse-chronological top)
   superseding entry recording that T094a removed the docker-socket-proxy
   mechanism from feature 001 (why: T090 removed CP-event admission gating,
   so the proxy is unnecessary for routing; the cookie-auth control port
   is the narrower observation surface). Add `Superseded by:` back-links
   on the 2026-07-04 and 2026-07-06 entries; do NOT edit their body prose.
8. `tests/contract/compose/local_compose_test.sh`: drop the proxy-specific
   assertions (docker.sock sole-mounter, proxy env lockdown, proxy digest
   shape) and re-assert exactly three services. Keep M13 as a single
   `stargate-internal` network for now (the split is T094b). Keep port /
   UID-GID / seven-volume / DP-no-depends_on assertions green.
9. Remove `tests/contract/sidecar-proxy/lockdown_test.go` and the
   `tests/contract/sidecar-proxy/` directory — the proxy it gates no
   longer exists. (Record the removal rationale in the superseding
   SECURITY-DECISIONS entry.)
10. Remove `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`
    and `tests/contract/arch/docker_socket_proxy_section_test.sh` — both
    hard-assert the removed entry/§16.1/digest and would otherwise fail
    `verify.sh`. (Their load-bearing invariants are moot once the proxy is
    gone; the superseding decision-log entry carries the record.)
11. Refine `T039` and `T074` acceptance so SidecarMonitor observes Tor
    through the cookie-authenticated ControlPort (not docker-socket-proxy).
    T019c stays untouched (done, historical).
12. `python3 scripts/lint-ticket.py` clean for T094a (and the refined
    T039/T074); `scripts/verify.sh` green.

## Out-of-scope

- Splitting compose networks (DP+Tor transport vs CP+Tor mgmt; Tor-only
  egress) — that is **T094b**, blocked on this ticket.
- Container hardening (`read_only`, `tmpfs`, `cap_drop`, `no-new-
  privileges`, mem/PID limits) — **T094b**.
- The docker-backed negative-path regression test — **T094b** (Principle
  VII tests-first for the network-split properties lives there).
- Implementing SidecarMonitor's control-port client in Java — T039/T074
  (this ticket only refines their acceptance to target the new surface).
- Rewriting T019c's ticket body or the 2026-07-04 / 2026-07-06 SECURITY-
  DECISIONS entry bodies (acceptance #5 of the parent forbids it; a
  superseding entry + back-links is the sanctioned mutation).

## Notes

- The cookie-auth observation mechanism is not new infrastructure:
  `contracts/torrc.md` invariant #4 (`CookieAuthFileGroupReadable 1`)
  exists precisely "so the cookie file is readable by callers sharing the
  volume's group", and T062 (`tests/contract/tor/control_port.go`) is the
  existing cookie-authenticated control-port helper. T094a promotes that
  surface from "contract-test harness only" to "CP observation surface".
- LAN/VPS release-blocker carry-over: the superseding SECURITY-DECISIONS
  entry MUST preserve the "any future LAN/VPS profile re-visits Tor
  observation surface" framing, now scoped to the control-port channel
  rather than the removed proxy.
