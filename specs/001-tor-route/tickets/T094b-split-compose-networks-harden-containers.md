---
id: T094b
title: 'Split compose networks; harden containers'
status: pending
created: 2026-07-16
last_updated: 2026-07-16
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
reviews: {}
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
