---
id: "T159"
title: "Preserve acknowledged auth state across rollback and restart"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T156", "T139", "T135", "T137"]
parallel: false
files_budget: 12
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

- Must hold: the constitutional property named below across the actual trust boundary.
- Gated: existing baseline does not establish the new acceptance; do not infer a live leak.
- Residue: test doubles and static text cannot prove browser/network or crash semantics.

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

Privacy regressions are authored first within this ticket; empty tests_first is not an exemption.
If decomposed, create concrete children and add them to T155 and affected consumers before closure.
