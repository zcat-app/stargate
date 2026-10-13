---
id: T034a
title: 'Measure SC-003 in a supported browser on a Local-profile host'
status: pending
created: 2026-07-04
last_updated: "2026-10-11"
source: tasks.md#T034a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: ["T009", "T155", "T071", "T072", "T073", "T126", "T156", "T219"]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T034a: Measure SC-003 in a supported browser on a Local-profile host

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Measure SC-003 on the existing Linux x86_64 VPS Local profile (or another supported Local-profile host) after T219 — use a fresh supported full Mullvad Browser profile with the reviewed extension; bounded automation through the ordinary browser interface may repeatedly load `.onion` pages. Require at least 10 continuous minutes of demonstrably successful loads, simultaneous complete guest-host `lo` and active-egress pcaps, safe pre/post DNS query-and-answer positive controls on each interface, zero capture drops/truncation, and zero matches for `dns.qry.name contains ".onion" || dns.resp.name contains ".onion"` in the offline analysis of both complete pcaps. Never send real `.onion` names to public DNS for controls. `tcpdump` capture plus grounded pinned `tshark` offline analysis is allowed. Record exact browser build/channel and the guest-NIC/namespace, encrypted-DNS and Alpha-versus-stable limits in `tests/integration/sc003_dns_leak.md`; preserve separate encrypted-DNS hardening proof. Run before each release tag, not on every PR. Depends on T219.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

- Record the exact Local-profile stack, reviewed extension, fresh full supported
  Mullvad Browser profile, build/channel, interface names, namespaces and command/tool
  identities. The existing VPS is an allowed venue; an Alpha run is explicitly
  Alpha-only evidence and leaves stable-browser coverage open.
- Show repeated successful `.onion` page renders for at least 10 continuous
  minutes while loading only `.onion` content through the ordinary browser
  interface. Automation may navigate but
  must not replace browser/network success evidence.
- Preserve simultaneous complete guest-host `lo` and active-egress pcaps with
  zero drops/truncation and safe pre/post DNS query-and-answer positive controls
  visible on each interface. Do not submit a real `.onion` name to public DNS.
- Analyze both complete pcaps with the spec's canonical query-and-answer filter;
  require zero `.onion` matches. Ground and pin an offline `tshark` if using
  `tcpdump` for capture.
- State the guest-interface/namespace boundary and the separate encrypted-DNS
  hardening proof. Do not claim physical-NIC, hypervisor or stable-browser
  coverage from this VPS run.

## Out-of-scope

T219 changes venue permission only; this ticket owns the live receipt.
T077 owns the first-time-human walkthrough, and SC-005 retains its physical
workstation baseline.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
T219 venue amendment, 2026-10-11: retain original history and release-tag
cadence; the VPS Local profile is an allowed measurement host under spec SC-003.
