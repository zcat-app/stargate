---
id: T015
title: 'Author `compose/docker-compose.local.yml` and `compose/env/local.env.e'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T015
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T015: Author `compose/docker-compose.local.yml` and `compose/env/local.env.e

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `compose/docker-compose.local.yml` and `compose/env/local.env.example` — **four services**: `stargate-dp`, `stargate-control`, `tor`, and `docker-socket-proxy` (a digest-pinned `tecnativa/docker-socket-proxy` instance that bridges `/var/run/docker.sock` to a filtered HTTP API; see SidecarMonitor at T039 and the trust rationale at T017a). Loopback-only port binding for 8881 on the data plane; no host port mapping for the Tor SocksPort or ControlPort; no host port mapping for the proxy. Named volumes per data-model.md §6. Per-plane runtime users created in each Stargate-owned image's Dockerfile and pinned via the compose `user:` directive — `stargate-cp` (UID 5101) for `stargate-control`, `stargate-dp` (UID 5102) for `stargate-dp`. A **shared supplementary group `stargate-ipc` (GID 5100)** is declared in both Stargate Dockerfiles, and both runtime users are added to it; this group owns the UDS files in `stargate-ipc` (per `contracts/control-grpc.md` §"Socket topology": `control.sock` owned `stargate-cp:stargate-ipc`, `dp.sock` owned `stargate-dp:stargate-ipc`, mode 0660). The mode/group scheme is the kernel-enforced gate that (a) lets the peer plane `connect(2)` its dial-direction socket — `0600` with distinct UIDs would silently break inter-plane comms — while (b) keeping random unprivileged same-host processes outside the dial surface; role separation itself is enforced by `bind(2)` (only the hosting plane is wired to call it on each path), not by the file mode. Distinct hosting UIDs are retained as defense-in-depth: a compromise of one plane does not yield filesystem-write access to the *other plane's* state volume (`stargate-control-state` vs `stargate-dp-state`); only the IPC volume is shared. The GID/UID numeric values used here MUST match the values referenced by the `user:` directives and any `chown` invocations across the CP and DP Dockerfiles. The Tor container drops to its own `tor` user per T014; `docker-socket-proxy` runs as the unprivileged user its upstream image declares. `docker-socket-proxy` is the ONLY service that mounts `/var/run/docker.sock` (read-only) from the host; the CP reaches it as `http://docker-socket-proxy:2375` over the compose-internal network. Proxy environment locked to the minimum surface SidecarMonitor needs: `EVENTS=1`, `CONTAINERS=1`, all other endpoint flags unset so they default to deny, and `POST=0` to forbid container spawn/kill/exec (verified by T019c). sha256-pinned image digests for the Debian-slim base, the final Tor sidecar image (FR-015), and the docker-socket-proxy image (Principle IV — every external component is digest-pinned). The Tor sidecar's compose service key is `tor` so its in-network DNS name matches FR-007 / T047's `tor:9050` dial target. **Verified by T019b (Tor port exposure), T019c (proxy lockdown), and T022's extended invariants (peer-dial succeeds, out-of-group dial fails).**

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
