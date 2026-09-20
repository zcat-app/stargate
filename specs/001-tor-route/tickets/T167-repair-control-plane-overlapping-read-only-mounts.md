---
id: "T167"
title: "Repair overlapping read-only control-plane mounts"
status: done
created: "2026-09-20"
last_updated: 2026-09-20
source: "T163 production-namespace live attempt"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T162"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs:
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
  - "specs/001-tor-route/spec.md"
decision_refs:
  - "specs/001-tor-route/tickets/T163-verify-packet-level-topology-boundaries.md"
remediates: "T162"
tests_first: []
reviews: { round: 1, date: 2026-09-20, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T167: Repair overlapping read-only control-plane mounts

## Context

T163's live Local deployment could not reach packet capture. In the checked-in
Compose file, CP mounts `stargate-control-config` read-only at `/etc/stargate`
and mounts `stargate-keys` under that parent at `/etc/stargate/keys`. Docker
cannot create the child mountpoint inside the read-only parent volume when it
is absent. The full `scripts/stargate init` path failed during `compose up`
before CP/DP admission. A direct two-volume `docker run --read-only --network
none` with the real CP image reproduced exit 125 and the same mount error on
the workstation's Docker daemon. A keys-only control mounted successfully
and reached CP application startup, discriminating the overlapping read-only
mounts from a missing mountpoint in the image. T163's failed full-run state
and daemon diagnostics are preserved locally under `target/live-e2e/`.

## Analysis

- **Must hold:** CP can start with the production read-only config and key
  mounts. It retains only its intended keys/config and does not gain Tor state,
  a raw control endpoint, SOCKS reachability or public-network egress.
- **Gated:** a real Docker mount/start regression using the effective Compose
  volume configuration, with the pre-fix exit 125 preserved; the existing
  Compose structural and Tor socket caller gates; `scripts/verify.sh`.
- **Residue:** T163 owns production-namespace packet, resolver and rule-absence
  evidence. A mount fix alone is not a topology verification result.

## Acceptance

1. Author the spec-derived Docker regression first. The pre-fix production CP
   mount set must fail with exit 125 and `read-only file system` at
   `/etc/stargate/keys`; a keys-only control must reach application startup.
   Preserve both results. Missing Docker/tooling is reported as unavailable,
   never a green runtime proof.
2. Repair the CP mount layout or provisioning so the full checked-in
   read-only Compose mount set starts a CP container. The test checks actual
   mounted source/target/mode and application-start reachability, not merely
   YAML text. It must reject removal of either required mount and reject a
   writable config parent as a shortcut.
3. Preserve CP `network_mode: none`, the reserved observer fabric boundary,
   and the T162 Tor caller matrix before/after socket recreation. No CP Tor
   cookie/raw-control or SOCKS path is introduced.
4. Run `bash scripts/verify.sh` GREEN on the exact candidate. T163 then
   repeats its live suite on the repaired topology.

## Out-of-scope

T163's packet measurements and rule-absence behavior, T164's sanitized
observer, Tor circuits, browser behavior, Constitution amendments.

## Evidence (2026-09-20)

- Tests-first red: against source snapshot `c25a8851c60cad1137a6f4fca8c51af5b54366e0`
  (ticket only) with `control_mount_test.sh` SHA-256
  `4b1b1d93905ce4d8c20475847b48faf543727bdf5e771f8a70ae4cb8704ba949`,
  `bash tests/contract/compose/control_mount_test.sh` exited 1. The keys-only
  control reached Quarkus startup; the full effective Compose mount set failed
  with Docker exit 125 at `/etc/stargate/keys` (`read-only file system`). The
  local log is `target/runs/T167-exact-test-red.log`.
- Green on the repaired tree: the same test and the fixture-backed
  `init_docker_test.sh` passed. The T162 Docker enforcement gate and
  `TestTorSocketCallerMatrix` passed, including its Tor restart and second
  caller-matrix check. `bash scripts/verify.sh` reported PASS=25, SKIP=1,
  FAIL=0; the skip was the opt-in release reproducibility gate. T163 still
  owns the production-namespace packet and rule-absence run.
