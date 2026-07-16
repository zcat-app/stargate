---
id: T094
title: 'Harden Compose network and container boundaries'
status: deferred
created: 2026-07-11
last_updated: 2026-07-16
source: review/sol-review.md#M2
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T089, T090]
parallel: false
files_budget: 10
deferred_on: T094a
deferred_reason: decomposed
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: No outbound except routed requests"
  - "V: Honest threat model"
  - "VII: Tests-first for sidecar contracts"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §16.1
  - specs/001-tor-route/spec.md §FR-012
  - THREAT-MODEL.md §5.8
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-06 — docker-socket-proxy `CONTAINERS=1` read surface"
remediates: T019c
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T094: Harden Compose network and container boundaries

> **Decomposed 2026-07-16** — the `/run` autopilot hit bright-line #2
> (Scope): the full acceptance touches ~15-17 files (4 spec/governance
> docs + compose + env + the rewritten `local_compose_test.sh` + removal
> of `sidecar-proxy/` + the two docker-socket-proxy cross-consistency
> tests + a new docker-backed regression test + T039/T074/T019c ticket
> refinements + a SECURITY-DECISIONS superseding entry), decisively over
> `files_budget: 10`. Per workflow.md §"Escalation menu" item 3
> (decompose), split into two serial children along the "coupling to the
> proxy" vs "independent hardening" seam:
>
> - **T094a** — Drop docker-socket-proxy; CP observes Tor via the
>   cookie-authenticated ControlPort (reuses `CookieAuthFileGroupReadable`
>   + the T062 control-port helper). Removes the proxy + its 5 tests,
>   syncs arch §16.1 / spec FR-012 / plan / THREAT-MODEL / SECURITY-
>   DECISIONS, refines T039/T074. `files_budget: 14`.
> - **T094b** — Split compose networks (Tor sole egress), add container
>   hardening (`read_only` / `cap_drop` / limits), write the docker-backed
>   negative-path regression test first (Principle VII). Blocked on T094a.
>   `files_budget: 6`.
>
> This ticket stays `deferred` (reason `decomposed`) as the audit record;
> its acceptance is satisfied when both children are `done`.

## Context

The local stack gives every service Docker-NAT egress and access to a generic
Docker API observer. It also omits the container hardening claimed by the
threat model. With request admission no longer controlled by CP events, the
generic Docker socket proxy is unnecessary for routing correctness.

## Analysis

- **Must hold** — only Tor has general egress; DP can reach only Tor's SOCKS
  surface; CP can reach only the authenticated Tor control/status surface;
  neither application plane can reach Docker API or the public network.
- **Gated** — Docker-backed negative-path tests run from each container
  namespace and inspect capabilities, rootfs mode, security options, limits,
  networks, and published ports.
- **Residue** — Tor remains the sole egress TCB and Docker isolation is not a
  security sandbox; the threat model must state both honestly.

## Acceptance

1. Amend architecture, plan, spec, and threat model to remove the generic
   docker-socket-proxy from feature 001 and use Tor's cookie-authenticated
   control port for local health/status observation.
2. Split networks so DP+Tor transport and CP+Tor management are internal;
   attach only Tor to an egress-capable network.
3. Add `read_only`, minimal `tmpfs`, dropped capabilities,
   `no-new-privileges`, and explicit memory/PID limits to every service, with
   only documented state/config mounts writable.
4. Write the Docker-backed regression test first. Assert DP and CP cannot
   reach public IPs, Docker API, or each other's unauthorized surface; Tor
   alone can bootstrap and the intended internal paths work.
5. Remove obsolete proxy configuration/tests through this remediation ticket
   without rewriting the completed T019c history or its decision-log entry.
6. Refine T039/T074 to observe Tor through the amended authenticated surface.
7. Update `THREAT-MODEL.md` in the same change and pass `scripts/verify.sh`.

## Out-of-scope

LAN/VPS profile topology and a general sidecar lifecycle daemon.
