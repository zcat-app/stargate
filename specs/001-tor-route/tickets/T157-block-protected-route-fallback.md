---
id: "T157"
title: "Block protected-route failure without Direct fallback"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T156", "T139", "T136"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/contracts/foundation-boundaries.md"]
decision_refs: []
remediates: "T055"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T157: Block protected-route failure without Direct fallback

## Context

The audit observed Direct descriptors on failed hardening/token/context paths but did not prove
actual browser egress. Constitution III now defines the network outcome explicitly.

## Analysis

- Must hold: the constitutional property named below across the actual trust boundary.
- Gated: existing baseline does not establish the new acceptance; do not infer a live leak.
- Residue: test doubles and static text cannot prove browser/network or crash semantics.

## Acceptance

1. Ground the real browser APIs and specify request cancellation/blocking behavior before code.
   Test missing/invalid credentials, failed/unknown hardening, absent initiating context, startup
   races, sidecar failure, redirects, retries and subresources. Preserve intentional Direct use.
2. Record failing descriptor and browser-network probes before the fix; prove no protected
   request goes to Direct, system proxy or an unintended route. Include positive capture controls.
3. Give truthful failure UI without claiming a notification cancels the request. Update extension
   contracts/threat-model evidence, run relevant tests and scripts/verify.sh with required reviews.
4. Real-browser evidence is required for completion; unavailable execution remains pending. If
   decomposition is needed, keep its browser evidence child blocking T155.

## Out-of-scope

Constitution weakening, unrelated feature work, and claiming unavailable tests passed.

## Notes

Privacy regressions are authored first within this ticket; empty tests_first is not an exemption.
If decomposed, create concrete children and add them to T155 and affected consumers before closure.
