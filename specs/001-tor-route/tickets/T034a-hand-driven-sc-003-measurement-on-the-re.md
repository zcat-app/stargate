---
id: T034a
title: 'Hand-driven SC-003 measurement on the reference workstation'
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T034a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: ["T009", "T155", "T071", "T072", "T073", "T126", "T156"]
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

# T034a: Hand-driven SC-003 measurement on the reference workstation

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Hand-driven SC-003 measurement on the reference workstation — fresh Mullvad Browser profile, 10-minute continuous `.onion`-only browsing session through the local-profile stack, simultaneous Wireshark capture on `lo` and egress NIC, display filter `dns.qry.name contains ".onion" || dns.resp.name contains ".onion"` returning zero matches across both interfaces (canonical filter per spec SC-003). Result recorded in `tests/integration/sc003_dns_leak.md` (markdown artefact alongside T077's walkthrough record). Run before each release tag, not on every PR.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
