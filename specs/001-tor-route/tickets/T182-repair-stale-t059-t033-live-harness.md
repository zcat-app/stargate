---
id: T182
title: 'Repair stale T059/T033 live harnesses: control socket, sg1 names'
status: in-progress
created: 2026-09-28
last_updated: 2026-09-28
source: hand-filed (T120 convention) — discovered while grounding T126 (2026-09-28 session); user direction to file
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: []
parallel: true
files_budget: 6   # two suite files + T126 suite comment + this ticket + STATUS.md regen + evidence/T182-tests-first.json (5 -> 6 user-authorized 2026-09-28: fix the T126 header prose T182 makes stale, no deferral)
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

Grounded 2026-09-28 against HEAD `a59ee18`: `stream_isolation_test.go:427`
and `onion_load_test.go:297,305` pipe to `nc 127.0.0.1 9051`;
`sidecars/tor/torrc` exposes only `ControlSocket
/var/lib/tor/control/tor-control.sock`; `stack_smoke_test.go`
`t131WaitBootstrapped` (`nc -q 1 -U <socket>`) is live-green (T178).
`t126PartitionUsername` (untagged, same package) is pinned to the
foundation-boundaries vector by `TestT126PartitionUsernameReferenceVector`
and already shared cross-suite in the T131/T126 manner (`t059NewToken`,
`t059ClassifyDialErr`).

- **Must hold:**
  1. Every Tor control exchange in T059/T033 rides the cookie-authenticated
     private Unix ControlSocket; nothing dials TCP 9051 (FR-012, torrc
     invariant #3).
  2. Every SOCKS CONNECT through 8881 carries a complete 68-char `sg1:`
     partition derived by the vector-pinned helper; the bearer is only the
     DP-facing PASSWD, never the UNAME. T059's two targets yield distinct
     partitions (the tuple's `onion:<addr>` element differs).
  3. Assertions, project names and the env-gated release cadence are
     unchanged; every probe failure stays a loud `Fatal`. Windows are
     unchanged unless the green live run shows a window too short for the
     current stack (e.g. T033's 90 s load window vs the cold CP): then it
     is widened here, T131/T126-style (user-authorized 2026-09-28, no
     separate ask or follow-up).
  4. Headers name the current Local-topology live prerequisites.
  5. T033's bring-up names its services (`tor stargate-dp
     stargate-control`, T059/T126/T131's set). Red live run 1 found its
     list-less `up` pulling `tor-observer` from the example env's
     placeholder `STARGATE_OBSERVER_IMAGE` (an init-written local image
     ID) and failing before any probe — a third stale assumption, fixed
     here rather than deferred.
- **Gated:** the partition derivation (hermetic reference-vector test in the
  PR gate); compile + vet of both files (go-workspace gate); `grep -n 9051`
  over `tests/integration` (acceptance 1, mechanical).
- **Residue:** live-only behaviour — socket reachability as the exec user,
  reply shape over `nc -U`, and DP admission of the `sg1:` names. Closed by
  acceptance 4's red (control probe fails on the unmodified transport) and
  green live runs on the enforcing VM. T033 has no token seed step; its
  live run relies on the operator seeding `tokens.yaml` for its project
  (stated in its header, performed by the live wrapper).

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
- `stack_smoke_test.go` and T126's suite (already current), except the one
  `stream_isolation_dp_uname_test.go` header sentence claiming T059's probe
  still dials TCP 9051 — prose this ticket falsifies; corrected here
  (user-directed 2026-09-28, no follow-up ticket).
- Hoisting a shared integration-module helper (T121/T180 deferred it).
- Production code or the torrc contract.

## Notes

### Tests-first evidence (disposable VM)

Executed 2026-09-28 on a copy of the saved enforcing Ubuntu VM
(`guest-t126.qcow2` → `guest-t182.qcow2`, QEMU TCG, 4 vCPU, 6 GiB; kernel
`6.8.0-142-generic`; `stargate-dp (enforce)`, IPv4/IPv6 owner rules, synthetic
keys/pepper and volume roots provisioned for `stargate-t033-test` and
`stargate-t059-test`, plus T033's operator token seeded on stdin). Probe
(identical for red and green): `bash target/runs/T182-vm/live.sh`
(gitignored T126-derived wrapper) running
`^(TestOnionLoad|TestT126PartitionUsernameReferenceVector|TestStreamIsolationPerFirstPartyDomain)$`.

- Red 1 (superseded): T059 failed at its 9051 bootstrap probe; T033 failed
  earlier, at the list-less `up` pulling `tor-observer` (Analysis item 5).
- **Red 2** (recorded): every change staged except the probe transport —
  both suites fail at the control probe (`no PROGRESS=100 within 5m0s`).
- **Green**: `nc -q 1 -U` ControlSocket probes — T033 loads 212506 bytes
  after one AUTH retry within the unchanged 90 s window, circuit BUILT;
  T059 streams on distinct BUILT circuits 13 / 21. No window widened.
