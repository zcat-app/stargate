---
id: T017a
title: 'Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-sock'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T017a
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

# T017a: Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-sock

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-socket-proxy` aux container** trust rationale (T015 / T039): why a privilege-isolating proxy instead of mounting `/var/run/docker.sock` directly into the CP. State the property the proxy buys: a compromise of the Quarkus control plane (YAML parser, gRPC server, future admin UI) does NOT escalate to host root, because the CP holds no docker.sock handle and can only invoke the `EVENTS=1 CONTAINERS=1` GET-only surface the proxy exposes. State the residual trust honestly: the proxy itself IS in the TCB; a compromise of the proxy is host-root-equivalent. Mitigations recorded: digest-pinned image (Principle IV); `POST=0` lockdown gated by T019c contract test; proxy runs as the unprivileged user its upstream image declares; proxy is not reachable from outside the compose-internal network. Cross-reference THREAT-MODEL.md §3.1 (local profile assumes local code execution is already game-over) so the residual-risk framing is consistent. **Release-blocker on any future LAN or VPS profile feature spec**: that profile exposes the CP to non-localhost callers and changes the compromise-probability calculus; this entry MUST be revisited (and likely the proxy mechanism replaced) before the LAN/VPS spec ships.

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
