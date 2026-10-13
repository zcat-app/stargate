---
id: T219
title: 'Amend SC-001 and SC-003 browser measurement venue'
status: done
created: 2026-10-11
last_updated: '2026-10-11'
source: tasks.md#T219
phase: '6: Polish & Cross-Cutting Concerns'
story: '-'
blocked_by: []
parallel: false
files_budget: 10
privacy_critical: true
tests_first: []
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md §SC-001'
  - 'specs/001-tor-route/spec.md §SC-003'
  - 'specs/001-tor-route/spec.md §SC-005'
constitution_refs:
  - 'III: Privacy-Preserving by Construction'
  - 'V: Honest Threat Model'
  - 'VII: Tests-first'
  - 'VIII: Independent Reviews'
decision_refs:
  - 'plan.md §T219 Constitution Check'
reviews: { round: 4, date: 2026-10-11, verdict: APPROVE, reviewers: "gpt-6-astra/high; gpt-6-luna/high" }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T219: Amend SC-001 and SC-003 browser measurement venue

## Context

The SC-001 usability walkthrough and SC-003 DNS measurement were tied to the
physical reference workstation even though their assertions can be observed in
a private remote/virtual browser session and on the existing VPS Local profile.
This amendment permits those venues without altering SC-001's first-time-human
claim, SC-005's physical performance baseline or the release evidence standard.
The contract is spec.md §SC-001/SC-003/SC-005 and plan.md §T219 Constitution Check.

## Analysis

- **Must hold:** Principle III's no `.onion` DNS leak claim remains bounded to
  complete decoded guest-host captures with safe positive controls. Principle V
  requires explicit guest-NIC/namespace, encrypted-DNS and Alpha-channel limits.
  SC-001 remains a first-time-human timed page load; SC-005 remains a physical
  workstation measurement. Principle VIII requires independent source review.
- **Gated:** Ticket lint, generated STATUS and source consistency checks can
  catch missing dependencies, malformed metadata and contradictory wording.
  Existing T034 privacy tests and T034a live work remain separate.
- **Residue:** Source checks cannot prove a live onion page, DNS capture or
  human usability. T034a and T077 must produce those receipts; stable-browser
  and encrypted-DNS coverage must be evidenced separately.

## Acceptance

1. Reconcile spec.md, plan.md and tasks.md so SC-001 permits a private
   remote/virtual browser session on the existing VPS but still requires a
   first-time human, a fresh supported profile, and under five minutes from
   extension installation through token paste to rendered page. Record total
   clean-checkout setup duration separately; agent automation cannot pass SC-001.
2. SC-003 permits the VPS Local profile and bounded automation through the
   ordinary full-browser interface, loading only `.onion` content through
   repeated successful page loads throughout at least ten minutes. Require
   simultaneous complete guest-host
   loopback and active-egress pcaps, safe pre/post DNS query-and-answer positive
   controls on each interface, zero drops/truncation and zero canonical
   query-or-answer filter matches on both pcaps. `tcpdump` plus grounded pinned
   `tshark` offline analysis is allowed; real `.onion` names never go to public
   DNS for controls.
3. State that the VPS result covers only decoded DNS at the measured guest
   interfaces. Physical NIC, hypervisor, other namespaces and encrypted DNS are
   outside that observation. Preserve separate encrypted-DNS hardening proof.
   Record exact browser build/channel and disclose Alpha-only coverage; stable
   support remains an open release condition.
4. Keep SC-005's physical reference workstation unchanged. Align the T034a and
   T077 executable tickets, their T219 dependencies, quickstart timer/capture
   prose, live-e2e release tracker R-1 and THREAT-MODEL §5.2 with the amended
   contract. T034f egress evidence is separately owned; SC-003's VPS capture
   cannot prove it. Regenerate STATUS.
5. Run affected docs/ticket consistency checks and freeze the exact staged
   candidate for independent Astra/Luna correctness and security review.

## Out-of-scope

This ticket does not run the T034a capture or T077 human walkthrough, change
production data-plane/control-plane/extension code or runtime policy, provision
a VM, run Docker/native-browser acceptance, or relax stable-browser release
coverage. T034a and T077 own the eventual receipts. T034f's task, ticket and
tracker R-2 are not reconciled by this venue amendment.

## Notes

The existing VPS has a usable Mullvad Browser Alpha/Gecko 153 development
target, but this amendment does not present its future result as stable-browser
support. The system browser below the manifest's Gecko 153 floor is not a
supported test target. The earlier workstation wording remains in git history.
