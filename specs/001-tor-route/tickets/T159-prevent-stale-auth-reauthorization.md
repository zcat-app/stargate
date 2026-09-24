---
id: "T159"
title: "Preserve acknowledged auth state across rollback and restart"
status: in-progress
created: "2026-09-12"
last_updated: 2026-09-24
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T156", "T139", "T135", "T137"]
parallel: false
files_budget: 21
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
   not silently revert on supported DP restart. Kill production SQLite/JTA child processes after
   generation reservation and after candidate commit, then reopen the original database in fresh
   processes; cover revocation and first enrollment from generation zero. Preserve valid CP-down
   cold snapshots.
3. Missing/corrupt/incompatible state denies admission, explicit empty valid generation revokes
   all, failed delivery stays pending and current valid byte pipes need no CP participation. A
   peer-side authenticated-channel disconnect replays current authority, but the client's own
   scheduled channel rotation MUST NOT issue `ReloadTokens` or rewrite the DP snapshot.
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

Round-1 review tightened the recovery proof without expanding the 20-path scope: fixed commitment
vectors calibrate both language implementations; generation reservation precedes candidate-row
mutation (gaps are safe); exact replay reasserts the active snapshot after ambiguous persistence;
and a coalescing capped-backoff local-IPC worker delivers pending authority when a DP returns while
the CP stays up. The cross-language probe uses the production Java bootstrap and production Go
control server over mTLS/UDS. The SIGKILL probe reopens the original DP state directory, and a live
relay probe pins that established application pipes finish across revocation.

Round-2 review exposed one additional load-bearing existing test path:
`control-plane/persistence/.../SqliteTokenStateTest.java`. Under the same maintainer-authorized
T148 refinement precedent, files_budget is 21 solely to exercise reservation-gap recovery through
the production SQLite/JTA adapter for both revocation and first enrollment. Acceptance is unchanged.

Round-3 evidence also retains the latest acknowledged non-stale authority for event-driven replay
on an authenticated reconnect (no periodic proxy traffic), restarts only the production Go DP
without its snapshot under a running production Java bootstrap, restores an older production
SQLite/JTA CP authority against a newer DP and checks the real Go verifier stays revoked, and sends
both mixed-peer directions through serialized mTLS/UDS RPCs. These probes remain within the same
21 paths.

After the round-3 cap, the maintainer directed Codex to fix the defects it introduced. This
refinement makes the two surviving findings explicit acceptance requirements: distinguish local
55-second channel retirement from a peer disconnect, and replace adapter-only rollback simulations
with abruptly killed production SQLite/JTA child processes reopened against their original files.
The archived round-3 verdict remains the falsifier; scope stays at the existing 21 paths.

The targeted repair distinguishes each physical client-channel epoch: scheduled local retirement
starts a fresh READY baseline and cannot enqueue authority, while an observed peer outage remains
latched across local retirement and replays once after recovery. The persistence regression now
uses four production SQLite/JTA crash pairs (reservation and committed-candidate boundaries for
both revocation and generation-zero enrollment), forcibly terminates the writer process, and
reopens the same database files in a fresh process without rollback or cleanup.
