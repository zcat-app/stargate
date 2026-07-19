---
id: T094b
title: 'Split compose networks; harden containers'
status: done
created: 2026-07-16
last_updated: 2026-07-17
source: specs/001-tor-route/tickets/T094-harden-compose-network-boundaries.md (decomposed)
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T094a]
parallel: false
files_budget: 6
privacy_critical: true
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §4 (network/port topology)
  - specs/000-architecture/spec.md §8 (read-only rootfs hardening)
  - specs/001-tor-route/spec.md §FR-012
  - THREAT-MODEL.md §5.8
  - THREAT-MODEL.md §3.1
decision_refs: []
decomposed_from: T094
reviews: { round: 2, date: 2026-07-17, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T094b: Split compose networks; harden containers

## Context

Decomposed from T094 (the network-split + hardening half, blocked on
**T094a** which removed the `docker-socket-proxy` and established the
cookie-auth ControlPort as the CP's Tor-observation surface). The local
stack still puts every service on a single `stargate-internal` bridge that
grants Docker's default NAT egress to all of them, and omits the per-
container hardening the threat model claims (arch §8: "read-only root
filesystems"; the only writable mount is the config/state volume). This
ticket splits the networks so only Tor has egress, hardens every service,
and writes the docker-backed regression test that asserts the negative
paths from inside each container's namespace.

## Analysis

- **Must hold:**
  - DP can reach only Tor's SOCKS surface (`tor:9050`); CP can reach only
    Tor's cookie-authenticated ControlPort (`tor:9051`) and the inter-plane
    UDS — neither application plane can reach the public network, the
    Docker API, or each other's unauthorised surface (Constitution III).
  - Only Tor is attached to an egress-capable network; DP and CP sit on
    `internal: true` networks with no external connectivity.
  - Every service runs `read_only: true`, drops all capabilities
    (`cap_drop: [ALL]`), sets `no-new-privileges:true`, and has explicit
    memory + PID limits; only the documented state/config named volumes
    are writable, with minimal `tmpfs` for `/tmp` + `/run` (arch §8).
  - The docker-backed regression test is written FIRST (Principle VII) and
    asserts the negative paths before the topology is declared done.
- **Gated:**
  - `tests/contract/compose/local_compose_test.sh` (amended here) gates the
    split topology statically — network count, membership, `internal: true`
    flags, Tor as sole egress attachee.
  - The new `//go:build docker` regression suite (this ticket) gates the
    runtime negative paths; compile-checked at PR cadence by the
    go-workspace gate's `-tags` vet, run via `STARGATE_TEST_TAGS=docker`.
- **Residue:**
  - Docker container isolation is NOT a security sandbox — a kernel-level
    exploit or a sufficiently malicious image breaks out. THREAT-MODEL §5.8
    must state this honestly (Principle V); Tor remains the sole egress
    TCB. This residue is exactly what `stargate-redteam` should hunt.
  - The exact network shape (one egress net for Tor + two `internal: true`
    nets shared per the DP/CP reach matrices, vs. a finer per-service
    segmentation) is a `/start` grounding decision; the must-hold is the
    reach-matrix above, not a specific net count.

### Grounding decisions (2026-07-16 /run T094b)

- **Network shape — 3-net model (resolves the open `/start` decision above).**
  - `stargate-egress` — bridge, **NOT** `internal` (keeps Docker's default
    NAT egress). Attached: `tor` only. This is the sole egress path; Tor
    is the only service that can reach the public network.
  - `stargate-internal` — bridge, `internal: true`. Attached: `stargate-dp`
    + `tor`. Carries DP→`tor:9050` (FR-007). `internal:true` removes the
    default route AND blocks DNS exfil via Docker's embedded resolver
    (127.0.0.11 returns SERVFAIL for external names — verified at runtime
    in T094b, and confirmed by a non-internal control that resolves the
    same names) ⇒ DP has no public egress and no clearnet side-channel.
  - `stargate-cp-tor` — bridge, `internal: true`. Attached: `stargate-control`
    + `tor`. Carries CP→`tor:9051` (cookie-auth ControlPort, T094a). Same
    no-public-egress / no-DNS-exfil properties as above.
  - DP and CP share no network ⇒ mutually unreachable at L3 (gated
    statically by M13 and, once the images build, at runtime).
  - **Cross-plane tor-port residue (Principle V — documented, NOT closed
    here; corrected after redteam M1).** An earlier draft of this section
    asserted the narrow matrix "DP→{tor:9050}; CP→{tor:9051}" with
    "Internal ⇒ no route to the other tor port." That is **false**: `tor`
    binds `SocksPort 0.0.0.0:9050` + `ControlPort 0.0.0.0:9051`
    (contracts/torrc.md) and is multi-homed across all three networks, so
    the ACTUAL L3 reach matrix is wider — DP can also TCP-reach `tor:9051`
    (inert: the auth cookie is volume-isolated to `tor` on
    `stargate-tor-state`, mounted only into tor) and CP can also TCP-reach
    `tor:9050` (the unauthenticated SOCKS surface — a Tor-transiting exfil
    channel that bypasses the DP's routing authority + per-first-party
    stream isolation). This does NOT breach "Tor is the sole egress TCB"
    (the exfil still transits Tor; no clearnet leak, no Docker-API route,
    no DP↔CP surface), but it IS wider than the design-intent matrix.
    Closing it requires per-interface SocksPort/ControlPort binds, a torrc
    byte-contract change owned by T087 and explicitly out-of-scope here.
    Accepted as v1 residue; stated honestly in THREAT-MODEL §5.8 and pinned
    as expected-reachable in `network_hardening_test.go`
    (CrossPlaneTorPortResidue…) so a future T087 change that closes it
    fails the test and forces §5.8 to update in lockstep.
- **`stargate-internal` name preserved deliberately.** T019b's
  `tests/contract/tor/port_exposure_test.go` resolves the DP↔tor network by
  the literal compose name `stargate-internal` (lookupComposeNetwork,
  line 257). Renaming it would be a cross-ticket drive-by; keeping it as the
  DP↔tor transport net is the surgical choice (no edit to port_exposure_test
  .go). M13 is updated to the split topology instead.
- **Hardening — applied uniformly to all three services.** `read_only: true`;
  `tmpfs: [/tmp, /run]` (arch §8 "minimal tmpfs"); `cap_drop: [ALL]`;
  `security_opt: [no-new-privileges:true]`; explicit `mem_limit` +
  `pids_limit`. Chosen limits (no spec pin exists; documented here as the
  grounding choice): DP `mem_limit: 512m`, `pids_limit: 256`; Tor
  `mem_limit: 512m`, `pids_limit: 256`; CP `mem_limit: 1g`, `pids_limit: 512`
  (JVM thread count). Only the documented named volumes remain writable.
  Tor needs no extra caps (binds >1024) and writes only to
  `/var/lib/tor` (`stargate-tor-state`) with `AvoidDiskWrites 1`.
- **DP/CP images are NOT buildable today** (`data-plane/cmd/stargate-proxy/
  main.go` absent; same state T019b's sub-test (c) content-gates on). The new
  Go suite therefore tests **network reachability via ephemeral digest-pinned
  probes on each network** — which exist once `tor` is up — so acceptance #1
  (a)/(b)/(d) (negative paths + intended internal paths) and the runtime
  network/hardening inspection on `tor` RUN now without DP/CP buildable.
  Only the DP/CP **container** hardening inspection self-skips on the
  content-gate (mirroring T019b (c)), lifting when their main.go lands.
- **THREAT-MODEL edit is minimal.** §5.8 already states "Docker isolation is
  not a security sandbox... a sufficiently malicious image with kernel-level
  exploit can break out" (lines 942–948). This ticket adds the load-bearing
  framing it currently lacks — **the network split makes Tor the sole egress
  TCB** — to §5.8, and a one-line pointer in §3.1 (the local profile gains
  the internal-network split + the trusted-Docker-daemon residual already
  noted there). No §5.8 removal; honest additive note per Principle V.
- **Cadence.** The Go suite is `//go:build docker` (SKIP[docker] in the
  hermetic verify.sh PR gate; compile-checked via `go vet -tags docker`;
  executed in the named job `STARGATE_TEST_TAGS=docker scripts/verify.sh`,
  which this environment can run — Docker 29.1.3 daemon present). M13
  (shell) runs at PR cadence under verify.sh gate 4 and is the static
  topology gate.

## Acceptance

1. **Tests first.** Add a `//go:build docker` Go suite (mirroring the
   T019b/T019c harness: unique compose project, `t.Cleanup` teardown,
   `t.Skip` when the daemon is unreachable) that brings up
   `compose/docker-compose.local.yml` and, from inside each container's
   namespace (ephemeral digest-pinned probe containers), asserts:
   (a) DP cannot reach a public IP, the Docker API, or CP's surfaces;
   (b) CP cannot reach a public IP, the Docker API, or DP's SOCKS surface;
   (c) Tor alone bootstraps (`State.Health.Status == healthy`);
   (d) intended internal paths work (DP→`tor:9050`, CP→`tor:9051` via
   cookie). It also inspects each container's capabilities, rootfs mode
   (`read_only`), security options, resource limits, networks, and
   published ports and asserts the hardened shape.
2. `compose/docker-compose.local.yml`: split networks so DP+Tor-transport
   and CP+Tor-management are `internal: true`; attach only Tor to an
   egress-capable network. Preserve FR-005 (DP loopback-only) and FR-012
   (Tor ports never host-published).
3. `compose/docker-compose.local.yml`: add to every service `read_only:
   true`, minimal `tmpfs` (`/tmp`, `/run`), `cap_drop: [ALL]`,
   `security_opt: [no-new-privileges:true]`, and explicit `mem_limit` +
   `pids_limit`; only the documented named volumes remain writable.
4. `tests/contract/compose/local_compose_test.sh` M13: assert the split
   topology statically (multiple nets, `internal: true` flags, per-service
   membership, Tor as the sole egress attachee). Keep the assertions
   T094a left green.
5. `THREAT-MODEL.md` §5.8 / §3.1: add the honest note that Docker
   isolation is not a security sandbox and Tor remains the sole egress
   TCB (the parent's §Analysis residue).
6. `scripts/verify.sh` green; `python3 scripts/lint-ticket.py` clean.

## Out-of-scope

- Removing the docker-socket-proxy / cookie-auth observation swap — that
  is **T094a** (this ticket's blocker).
- LAN/VPS profile topology — out of scope for v1 (parent Out-of-scope).
- A general sidecar lifecycle daemon — out of scope (parent Out-of-scope).
- Any change to the Tor `torrc` byte contract or the cookie-auth invariant
  — those are owned by T087 / contracts/torrc.md, unchanged here.
