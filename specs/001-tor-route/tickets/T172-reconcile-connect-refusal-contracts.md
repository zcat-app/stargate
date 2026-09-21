---
id: "T172"
title: "Reconcile Tor HTTP CONNECT refusal contracts"
status: "pending"
created: "2026-09-21"
last_updated: "2026-09-21"
source: "T147 investigation and recommendation"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T147"]
parallel: false
files_budget: 40
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md Principles I/II/III/V/VII/VIII"
  - "specs/001-tor-route/spec.md FR-005–FR-009"
  - "specs/001-tor-route/contracts/foundation-boundaries.md §Negotiation and isolation"
  - "specs/001-tor-route/contracts/socks5-auth.md §HTTP CONNECT path"
decision_refs:
  - "specs/001-tor-route/tickets/T147-resolve-connect-isolation-contract.md §Investigation and recommendation"
remediates: "T043"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T172: Reconcile Tor HTTP CONNECT refusal contracts

## Context

T147 recommends refusing HTTP CONNECT because it has no first-party partition. Before the
runtime change, reconcile the legacy success/error promises and every affected test consumer.
This is a normative document change, not implementation or a claim of repaired isolation.

## Analysis

- Must hold: unsupported HTTP cannot reach Tor; supported SOCKS retains device/profile/site
  identity, authentication, no destination DNS and CP-independent byte forwarding.
- Gated: ticket lint, dependency graph and exact-candidate verification check consistency.
- Residue: independent review must detect lost privacy coverage or a remaining authoritative
  HTTP-success promise. T173 supplies runtime falsifiers; T126/T155 supply circuit evidence.

## Acceptance

1. Adopt T147's exact target for Tor port 8881: demux `C` closes with zero response bytes,
   no auth evaluation, no counter increments and no upstream socket. No HTTP success,
   error-template ingress, negotiation extension, fallback or configuration bypass remains
   supported. Preserve authenticated SOCKS behavior; distinguish HTTP CONNECT from the SOCKS
   CONNECT command throughout. No decision about other routes is implied.
2. Reconcile `specs/001-tor-route/spec.md`, `plan.md` Constitution Check,
   `contracts/foundation-boundaries.md`, `contracts/socks5-auth.md`,
   `contracts/error-template.md`, `contracts/control-grpc.md`, `data-model.md`,
   `specs/000-architecture/spec.md`, `ARCHITECTURE.md`, `THREAT-MODEL.md` and applicable
   quickstart/README guidance. Search current normative consumers before editing; each
   remaining HTTP mention must be historical, a future format, a refusal or another route.
   State clearly that current code still conflicts until T173; do not label the target PASS.
3. Record a per-file/per-invariant inventory for T173 covering at least
   `data-plane/internal/listener/{connect,socks5}_test.go`,
   `data-plane/internal/forward/tor_test.go`, `tests/contract/socks5/`,
   `tests/contract/error-template/`, `tests/contract/control-grpc/` and affected integration
   helpers. Map each HTTP-dependent test to refusal, equivalent SOCKS transport coverage,
   or renderer-only coverage. Preserve every invariant named in T147's coverage migration;
   no silent deletion, skip or relaxation to make removal green.
4. Reconcile pending consumer acceptance T064–T073 (including T067a/b and T070a/b), and
   relevant T123/T132/T126 instructions, to the selected ingress. Preserve their underlying
   privacy tests and measurable outcomes; existing completed tickets are historical and are
   not rewritten. Keep T173 a blocker of T155/T123/T132 (T126 via T132 and US3 via T155).
   Check the dependency graph for cycles; T173 cannot depend on its own consumers.
5. Publish the pre-release breaking migration described by T147: stop old admission/restart
   DP, no mixed-version safety claim, extension stays on SOCKS, no generic constant-username
   SOCKS or Direct workaround, context-incapable clients unsupported. Explicitly assess
   existing tunnels, credentials/snapshots, fixed route configuration and remaining live gaps.
6. Run ticket lint and `bash scripts/verify.sh`; independently review normative consistency
   under Principles I/III/V/VIII. Pure document work uses consistency evidence, not a fabricated
   runtime red/green sequence. If the inventory exceeds 40 files, stop for refinement before
   expanding it. Do not resolve any new policy conflict by weakening the constitution.

## Out-of-scope

Production source/test implementation, SOCKS identity redesign, Tor configuration changes,
other routes, constitution amendments, risk acceptance, or marking M2 repaired. Test edits
and the new failing regression belong to T173 after these contracts have been reviewed.

## Notes

The budget includes the ticket and derived STATUS board, normative docs and pending tickets.
T173 is a combined regression/fix owner so no permanently red test dependency is created.
