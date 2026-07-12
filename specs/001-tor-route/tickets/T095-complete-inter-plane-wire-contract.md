---
id: T095
title: 'Complete the inter-plane wire contract'
status: in-review
created: 2026-07-11
last_updated: 2026-07-12
source: review/sol-review.md#M5
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T090]
parallel: false
files_budget: 10
privacy_critical: true
constitution_refs:
  - "II: Versioned authenticated inter-plane contract"
  - "VII: Contract test-first"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §5.3
  - specs/000-architecture/spec.md §5.4
  - specs/001-tor-route/contracts/control-grpc.md §"Transport invariants"
decision_refs: []
remediates: T022
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T095: Complete the inter-plane wire contract

## Context

T022 was completed while deferring real UID/GID, peer authentication,
unknown-major rejection, and plane-restart behavior. Production tickets must
not invent the missing wire contract.

## Analysis

- **Must hold** — both UDS peers are mutually authenticated by pinned Ed25519
  identities; protocol major/minor is authenticated and rejected before any
  RPC handler accepts behavior; filesystem roles work under real service IDs.
  The wire-auth contract (`contracts/wire-auth.md`) + the structural
  regression gate (`tests/contract/compose/inter_plane_wire_test.sh` §S1-S9)
  pin these properties at the contract/document/UID-GID level NOW, before
  T038/T045/T050 implement.
- **Gated** — the structural tier of `inter_plane_wire_test.sh` runs at PR
  cadence under verify.sh gate 4 and asserts: wire-auth.md pins the binding
  shape (cert fields, byte-equal pin, validity window, metadata keys,
  interceptor placement); arch §5.3/§5.4 reference it; control-grpc.md
  references it; init installs keys-only; compose UID/GID numerics match;
  proto package is `stargate.v1`; SECURITY-DECISIONS + THREAT-MODEL carry
  the residue; T038/T045/T050 consume it verbatim. License-header gate
  covers SPDX.
- **Residue** —
  - **The 8 runtime auth properties (R1-R8: socket mode/owner, peer-group
    dial, out-of-group EACCES, wrong-key rejection, major mismatch, minor
    compatibility, no-TCP-beyond-proxy, CP-restart survival) cannot be
    exercised before T038/T045/T050 create the impl surface.** They are
    NOT gated today. `inter_plane_wire_test.sh` carries the R1-R8 row list
    (§Notes) and a **FAIL-forcing content gate**: when the impl files land,
    the runtime tier FAILs until R1-R8 are authored in the same file —
    the lift cannot be silently skipped. The lift is authored by the first
    impl ticket whose diff turns the gate red (or by a dedicated follow-up
    ticket filed at that point); either path is forced by the FAIL, not by
    discipline. This residue classification is honest per
    docs/process/analysis.md: the residue is named, the lift mechanism is
    named, and the gate enforces it.
  - Certificate validity/rotation policy (30-day window, 5-min skew,
    no automated rotation) is operator-visible and recorded in
    THREAT-MODEL.md §5.13 + SECURITY-DECISIONS.md (T095 entry). The
    binding incident-response residue is **private-key compromise**: an
    attacker who reads process memory obtains the long-lived key (not
    just the transient cert) and can impersonate indefinitely until the
    operator manually rotates the on-disk keypair; the 30-day cert window
    does NOT bound this. Recorded honestly per Principle V.

## Acceptance

1. Specify Ed25519 X.509 certificate derivation, peer public-key pinning,
   validity policy, UDS authority/SAN handling, and key ownership.
2. Define authenticated gRPC metadata carrying protocol major/minor and
   capabilities on every RPC; an interceptor rejects an unknown major before
   invoking application behavior. Additive minor versions remain compatible.
3. Update architecture, control contract, proto-generation notes, installer
   key contract, and `SECURITY-DECISIONS.md` before implementation tickets.
4. Add container-level regression tests for socket ownership/mode, peer-group
   dial success, out-of-group `EACCES`, wrong-key rejection, major mismatch,
   minor compatibility, no TCP transport, and CP restart survival.
5. Refine T038/T045/T050 to consume the exact contract; do not leave any
   acceptance row deferred to implementation detail.
6. Wire the tests into T076's exhaustive module accounting and pass verify.

## Out-of-scope

Remote TCP gRPC and automated certificate rotation.

## Notes

### The R1-R8 runtime lift (deferred from §Acceptance #4, enforced by FAIL-gate)

`tests/contract/compose/inter_plane_wire_test.sh` carries a runtime tier
that exercises the 8 load-bearing transport properties against a live
compose stack. The runtime tier cannot be authored in T095 because the
impl surface (T038/T045/T050) does not exist yet; it is **residue with a
FAIL-forcing gate**, not silently skipped. The gate logic:

- When any of the 4 impl gate files is absent → runtime tier SKIPs
  (structural tier still runs; this is the state at T095 land time).
- When ALL 4 impl gate files are present → runtime tier **FAILs** with
  "runtime lift required: author R1-R8 in this file" until the assertions
  are written. This forces whichever impl ticket lands last (or a dedicated
  follow-up) to author the lift; the test cannot stay green with the
  runtime properties dark.

The R1-R8 rows the lift must author (asserted as the stargate-cp /
stargate-dp / arbitrary UIDs against a `stargate init`-brought-up stack):

| Row | Property | Source |
|---|---|---|
| R1 | socket mode 0660, owner `stargate-{cp,dp}:stargate-ipc` | control-grpc.md §"Socket topology"; wire-auth.md §6.1 |
| R2 | peer-plane UID `connect(2)` succeeds on its dial-direction socket | control-grpc.md invariant row 5 |
| R3 | non-group UID `connect(2)` fails with `EACCES` on both sockets | control-grpc.md invariant row 6 |
| R4 | wrong-key peer (replaced `*.pub`) rejected at TLS handshake | wire-auth.md §3 |
| R5 | unknown `x-stargate-proto-major` rejected with `FailedPrecondition` before app handler | wire-auth.md §5.2; arch §5.5 row 4 |
| R6 | additive minor version accepted (minor compatibility) | wire-auth.md §5.2; arch §5.3 |
| R7 | no TCP LISTEN beyond the proxy port (no TCP gRPC transport) | control-grpc.md invariant row 1; wire-auth.md §4 |
| R8 | DP keeps routing port 8881 across a CP restart (Principle II) | control-grpc.md invariant row 9; arch §5.5 |
| R9 | after replacing `cp.pub` + restarting CP, the running DP accepts the new CP on its next `ReloadTokens` push without a DP restart (per-handshake pin re-read, wire-auth.md §3.1 step 3) | wire-auth.md §3.1 step 3; §6.2 |
