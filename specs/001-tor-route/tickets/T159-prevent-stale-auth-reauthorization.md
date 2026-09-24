---
id: "T159"
title: "Preserve acknowledged auth state across rollback and restart"
status: "pending"
created: "2026-09-12"
last_updated: 2026-09-24
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T156", "T139", "T135", "T137"]
parallel: false
files_budget: 20
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/contracts/foundation-boundaries.md"]
decision_refs: []
remediates: "T092"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T159: Preserve acknowledged auth state across rollback and restart

## Context

Current reconciliation contracts allow a restored CP backup to retry old token contents at a
higher generation. The DP snapshot failure test also permits OK despite persistence failure.
T156 forbids silently reauthorizing revoked clients or overstating durable application.

## Analysis

- Must hold: the CP never promotes rejected stale credential content to a newer generation, and
  the DP acknowledges a generation only after its exact verifier set is durably recoverable.
  Same-generation replay is successful only for identical content. Missing, corrupt or
  incompatible authority state denies admission; a valid durable empty generation revokes all.
- Gated: unit tests cover snapshot parsing and reload ordering; real mTLS/UDS probes must cover
  stale-CP reconnect, persistence failure, process crash and DP restart. Both peers must recognize
  the strengthened acknowledgment marker so a mixed-version transition fails pending, not open.
- Residue: SIGKILL and local-filesystem probes do not prove every power-loss/filesystem behavior.
  A lost response can leave application pending even when the exact candidate is already durable.
  Whole-host/root rollback of both trusted states remains outside the guarantee.

## Acceptance

1. Specify source authority, acknowledgment/durability, CP/DP restart and explicit operator
   rollback recovery before implementation. Do not automatically relabel stale credential content
   as a fresh generation; version and test the transition on both peers.
2. Author failing regressions: revoke a token, restore stale CP state, reconnect; revoked token
   remains rejected. Inject snapshot write failure/crash and prove acknowledged revocation does
   not silently revert on supported DP restart. Preserve valid CP-down cold snapshots.
3. Missing/corrupt/incompatible state denies admission, explicit empty valid generation revokes
   all, failed delivery stays pending and current valid byte pipes need no CP participation.
4. Run real IPC/crash-recovery probes, update the threat model with supported recovery limits,
   then verify and independent reviews. Host/root rollback of all trusted state is not claimed safe.

## Out-of-scope

Authorized existing-test updates: replace `TestReloadTokensSnapshotFailureStillOK` in
data-plane/internal/controlclient/controlclient_test.go with durable-acknowledgment/failure
expectations, and replace CP stale-content renumbering expectations with authority/recovery
probes. Preserve legitimate current-authority reconnect and valid CP-down admission coverage.

Constitution weakening, unrelated feature work, and claiming unavailable tests passed.

## Notes

2026-09-24: maintainer authorized retaining one coherent ticket and extending files_budget to 20
under the T148 scope-refinement precedent after reviewing the grounded 17–19-path estimate.
Acceptance and independent review gates are unchanged. Supported explicit rollback is an offline,
operator-confirmed procedure: stop both planes, preserve the newer DP snapshot, deliberately reset
DP authority to its fail-closed uninitialized state, restore the selected CP state and matching
key material, then reseed before reopening admission. It intentionally may reauthorize credentials,
terminates existing pipes because the DP is stopped, and is not a claim of safety after host/root
rollback of all trusted state. This ticket documents that procedure; it does not add an ad-hoc
database or snapshot mutation command.

Privacy regressions are authored first within this ticket; empty tests_first is not an exemption.
If decomposed, create concrete children and add them to T155 and affected consumers before closure.
