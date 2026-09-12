---
id: "T158"
title: "Publish only finalized aggregate counter buckets"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T156", "T139", "T149"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/contracts/foundation-boundaries.md"]
decision_refs: []
remediates: "T047"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T158: Publish only finalized aggregate counter buckets

## Context

Current Counters.Snapshot/GetStatus exports in-memory buckets. Hour labels alone do not prevent
fine-grained observation by repeated reads. T156 requires completed immutable buckets.

## Analysis

- Must hold: the constitutional property named below across the actual trust boundary.
- Gated: existing baseline does not establish the new acceptance; do not infer a live leak.
- Residue: test doubles and static text cannot prove browser/network or crash semantics.

## Acceptance

1. Record a failing repeated-poll regression proving the current hour cannot be observed;
   test hour rollover, clock regression, late/long-lived connection completion and concurrent reads.
2. Keep current traffic counts private and volatile; export/persist only finalized immutable
   buckets, with no per-user labels. Preserve T149 loss-free totals and define retention/expiry.
3. Update both sides of the status contract with explicit pre-release transition and compatibility
   probes; no RPC must leak counts through an alternate field/health response or debug output.
4. Test retention and repeated reads against actual RPCs, document limits and run verify/reviews.

## Out-of-scope

Authorized existing-test updates: data-plane/internal/audit/counters_test.go and
controlclient's GetStatus tests must replace current-hour visibility expectations with
completed-hour publication, while preserving loss-free totals and side-effect-free reads.
Contract/IPC callers require the corresponding transition tests; do not merely remove assertions.

Constitution weakening, unrelated feature work, and claiming unavailable tests passed.

## Notes

Privacy regressions are authored first within this ticket; empty tests_first is not an exemption.
If decomposed, create concrete children and add them to T155 and affected consumers before closure.
