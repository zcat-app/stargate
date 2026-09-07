---
id: T125
title: 'Local profile cannot expose 8881: FR-010 bind vs compose publish'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: []
parallel: false   # touches the FR-010 bind contract + its tests; other tickets should not build on the current shape
files_budget: 8
privacy_critical: true   # the bind check IS a privacy control (Principle III boundary); its amendment is a spec-level decision
complexity: high
risk: medium
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-005   # loopback-only host port 8881 — the USER-facing guarantee
   - specs/001-tor-route/spec.md#FR-010   # in-process bind check — currently contradicts the only mechanism that can serve FR-005 under docker publishing
   - specs/001-tor-route/spec.md §"Constitution Check" Principle III row   # the privacy rationale the bind check implements
   - compose/docker-compose.local.yml stargate-dp ports comment   # the long-form 127.0.0.1 publish the design assumes
   - specs/001-tor-route/tasks.md#T059   # discoverer (live probe chain, 2026-09-07)
decision_refs:
   - .specify/memory/constitution.md#Principle-III   # any amendment keeps "no non-host exposure" as the invariant
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens:
   - 2026-09-07 (round 2, live falsification): the T059 live run minutes
     after landing proved the wildcard-bind fix NECESSARY but NOT
     SUFFICIENT — Docker silently discards published ports on
     internal:true networks (container config carried 127.0.0.1:8881
     while NetworkSettings.Ports was null; host CONNECT refused with the
     DP listener up). Fix: dedicated stargate-host bridge (NOT internal,
     enable_ip_masquerade "false", DP-only) + M13/network-hardening
     contract updates + SD/THREAT-MODEL/spec wording; probed green
     (HOST-TCP-OK; egress blocked as designed) before this reopen.
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T125: Local profile can't expose 8881: FR-010 bind vs compose publish

## Context

Hand-filed from T059's live-probe chain (2026-09-07, docker 29.1.3). The
three contracts that position port 8881 are mutually exclusive under
Docker's publishing semantics:

- **FR-005**: the host-facing proxy port is `127.0.0.1:8881` (loopback
  only). compose publishes it `ports: ["127.0.0.1:8881:8881/tcp"]`.
- **FR-010 / `data-plane/internal/bind`**: the DP REFUSES to bind any
  non-loopback address — `Check("0.0.0.0")` → `ErrBindRefused`. T050's
  startup runs it before any listener; `STARGATE_LISTEN_ADDR` cannot
  legally be set to anything but a loopback literal.
- **Docker publishing**: `ports:` reaches the container via DNAT /
  docker-proxy to the container's **eth0** address. A listener bound to
  the container's **loopback** is unreachable through it — from the host
  AND from compose neighbours alike.

**Live proof (2026-09-07 probe, project `t059x`):** with the DP brought up
per the current tree (after provisioniong keys/volume roots per
`scripts/stargate init`, so the DP boots clean — `startup
listener=127.0.0.1:8881` in its own logs):
- host → `127.0.0.1:8881` (published): **connection refused**;
- compose neighbour (tor) → `stargate-dp:8881`: **refused**;
- in-container loopback listener confirmed up the whole time.

Consequence: NO process outside the DP container's own network namespace
can ever deliver a request to port 8881. The extension's host connection
(FR-005), every US1/US2/US3 acceptance scenario, and the whole local
profile are unreachable as composed. Masked until now: the full stack had
never been brought up end-to-end (see T122/T123/T124 — same discovery
chain), and the hermetic gates never exercise docker networking.

## Analysis

*(The resolution is a spec amendment decision — filed so the human
decides with the evidence in one place.)*

- **Option A (recommended): container-boundary reading of FR-010.** The
  invariant FR-010 protects is "the port must not be reachable from
  anything but the host's loopback". Under the compose topology that
  guarantee is delivered by the HOST-side publish
  (`127.0.0.1:8881:8881`, structural-gated) plus T094b's network split —
  not by the in-container bind address. Amend FR-010: inside a compose
  deployment the DP binds the container-wide address
  (`STARGATE_LISTEN_ADDR=0.0.0.0:8881` from compose env), and
  `bind.Check` enforces loopback ONLY for bare-metal local runs (e.g. it
  accepts the wildcard when an explicit env attests the container
  boundary, or the check is scoped to non-compose deployments). Updates:
  spec FR-010 wording, `bind/check.go` + `check_test.go` (T012a/T013),
  compose env, THREAT-MODEL §3.1 note, SECURITY-DECISIONS.md entry
  (posture-relevant), and the compose structural contract that pins the
  publish.
- **Option B (rejected): `network_mode: host` for the DP.** Makes the
  bind moot but destroys T094b's three-network split (the DP would share
  the host netns and Tor's egress path changes) — a far larger privacy
  regression than A.
- **Option C (rejected): relay/sidecar in front of the DP.** The relay
  needs to reach the DP cross-container — same loopback-bind problem one
  hop up; adds a component without removing the conflict.

## Acceptance

1. A decision is recorded (amend-spec path per Option A, or an
   alternative the human picks); SECURITY-DECISIONS.md entry if the
   posture changes.
2. After the decision lands: host → `127.0.0.1:8881` reaches the DP
   (positive control: a SOCKS5 handshake completes from the host), while
   a non-loopback host interface still cannot reach it (negative
   control preserved).
3. `bind` unit tests updated to the amended contract; full-vertical
   live tests (T033/T059) pass their CONNECT phase end-to-end.
4. `bash scripts/verify.sh` GREEN.

## Out-of-scope

- T059's test artifact (already authored against the spec scenario; its
  live gate unblocks the day this lands — no test change expected).
- The LAN/VPS profiles' tunnel-sidecar bind rules (FR-010's "without a
  corresponding tunnel sidecar" clause) — this ticket concerns only the
  local profile's loopback contract.
