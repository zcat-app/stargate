---
id: "T156"
title: "Strengthen constitution and reconcile implementation prerequisites"
status: "in-review"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: []
parallel: false
files_budget: 128
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/contracts/foundation-boundaries.md"]
decision_refs: []
remediates: "T133"
tests_first: []
decomposed_from: "T154"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T156: Strengthen constitution and reconcile implementation prerequisites

## Context

The maintainer explicitly requests constitution strengthening, resolving the evaluated weak points
and newly discovered document smells, then revising ticket order before runtime implementation.

## Analysis

- Must hold: the constitutional property named below across the actual trust boundary.
- Gated: existing baseline does not establish the new acceptance; do not infer a live leak.
- Residue: test doubles and static text cannot prove browser/network or crash semantics.

## Acceptance

1. Resolve terms, listener namespaces/tunnel lifecycle, actor egress, proxy negotiation vs payload,
   client partition isolation, fail-closed behavior, auth recovery/rollback and aggregate-only data.
   Retain loopback/tunnel restrictions and aggregate-only logs; do not adopt T125's exception.
2. Make governance precedence, pre-release authorization, evidence, review and external-human
   release obligations explicit. Identify semantic permissions honestly; preserve amendment history.
3. Reconcile affected authority docs, templates and reviewer guidance; preserve binding toolchain
   pins in architecture/build contracts. Record current implementation gaps, not false compliance.
4. Declare the complete reviewed path budget, including specs, tracked/untracked source and
   necessary delivery evidence; no specs exemption. Refine existing tickets and create missing implementation owners; ensure investigations cannot
   close without required children/blockers. Validate dependency existence/cycles, tests_first and
   full queue coverage; regenerate STATUS. Do not change production code or completed ticket history.
5. Run scripts/verify.sh, consistency/link checks and sync-agents. Obtain fresh codereview and
   independent redteam on an exact scoped manifest including untracked documents. Record actual
   reviewer identity, limitations and durable verdicts. Complete through normal reviewed delivery.

## Out-of-scope

Constitution weakening, unrelated feature work, and claiming unavailable tests passed.

## Notes

Privacy regressions are authored first within this ticket; empty tests_first is not an exemption.
If decomposed, create concrete children and add them to T155 and affected consumers before closure.
