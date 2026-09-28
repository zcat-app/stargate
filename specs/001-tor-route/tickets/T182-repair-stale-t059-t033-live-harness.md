---
id: T182
title: 'Repair stale T059/T033 live harnesses: control socket, sg1 names'
status: pending
created: 2026-09-28
last_updated: 2026-09-28
source: hand-filed (T120 convention) — discovered while grounding T126 (2026-09-28 session); user direction to file
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: []
parallel: true
files_budget: 5   # two suite files + this ticket + STATUS.md regen + evidence/T182-tests-first.json
privacy_critical: true   # edits the observation channel and SOCKS credential shape of isolation/route suites
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-002   # partition username is the isolation identity the suites exercise
  - specs/001-tor-route/spec.md#FR-012   # compose-internal transport; raw control is a private Unix socket
  - specs/001-tor-route/contracts/foundation-boundaries.md   # sg1: partition username shape (T172/T173)
  - specs/001-tor-route/contracts/torrc.md   # ControlSocket /var/lib/tor/control/tor-control.sock (invariant #3)
decision_refs:
  - "T162: replaced the TCP ControlPort 9051 with ControlSocket — the suites' `nc 127.0.0.1 9051` probes can no longer connect"
  - "T172/T173: Tor ingress consumers send complete sg1: partition usernames, not raw first-party domains"
  - "T131 (stack_smoke_test.go): already migrated (Unix-socket bootstrap probe + sg1: username) and live-green on the enforcing VM (T178 evidence) — the reference shape"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T182: Repair stale T059/T033 live harnesses: control socket, sg1 names

## Context

Two release-cadence suites in `tests/integration` (env-gated by
`STARGATE_RUN_NETWORK_TESTS=1`, so invisible to the hermetic gate) still
carry pre-T162 / pre-T172 assumptions:

- `stream_isolation_test.go` (T059): `t059ControlProbe` pipes the cookie
  exchange to `nc 127.0.0.1 9051`. Since T162 Tor exposes control only on
  `ControlSocket /var/lib/tor/control/tor-control.sock`
  (`sidecars/tor/torrc:6`), so bootstrap, stream-status and circuit-status
  probes cannot connect and the suite cannot pass live. Its SOCKS UNAME is
  the raw onion address, not a complete `sg1:` partition.
- `onion_load_test.go` (T033): `t033BootstrapProbe` and
  `t033CircuitStatusProbe` use the same `nc 127.0.0.1 9051` transport; its
  SOCKS UNAME is also the raw onion address.

Both headers also omit the current Local-topology live prerequisites
(`stargate-dp` AppArmor profile, DP owner rules, init-equivalent key and
volume provisioning; see `tests/live-e2e/local-topology/README.md` and
`target/runs/T132-vm/provision.sh`'s procedure).

T131's `stack_smoke_test.go` is NOT stale: it uses the Unix socket and a
`sg1:` username, and passed live on the enforcing VM (T178 evidence). T126
reads circuits through the T062 helper `tests/contract/tor`.

## Analysis

*(Filed for grounding at start; the property map is completed then.)*

- Must hold: every control exchange uses the authenticated Unix
  ControlSocket (the T062 helper or T131's `nc -U` shape); every SOCKS
  CONNECT through 8881 carries a complete `sg1:` partition and the bearer
  only as the DP-facing password; each suite's assertion and cadence are
  otherwise unchanged; failures stay loud.
- Residue: live-only behaviour. Acceptance requires a live run.

## Acceptance

1. No `tests/integration` file dials Tor control on TCP (`grep -n "9051"`
   finds only prose, if any); T059's and T033's probes use the
   Unix ControlSocket (T062 helper or T131's shape).
2. T059's and T033's SOCKS usernames are complete `sg1:` partitions derived
   per `contracts/foundation-boundaries.md` (T059's two targets keep
   distinct partitions), pinned by the reference vector.
3. Suite headers state the current live prerequisites (AppArmor profile,
   owner rules, init-equivalent provisioning, disposable host/VM).
4. Red/green evidence: the unmodified suite fails live at its control probe
   on the enforcing VM; the repaired suite passes live there; `bash
   scripts/verify.sh` green.

## Out-of-scope

- T059's or T033's assertions (isolation, page load) — transport and
  credential shape only.
- `stack_smoke_test.go` and T126's suite (already current).
- Hoisting a shared integration-module helper (T121/T180 deferred it).
- Production code or the torrc contract.
