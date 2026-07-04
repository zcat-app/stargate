---
id: T034
title: 'Integration test asserting no DNS query for any `*.onion` name appears'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T034
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
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

# T034: Integration test asserting no DNS query for any `*.onion` name appears

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test asserting no DNS query for any `*.onion` name appears on `lo` or egress NIC for the duration of a 60-second Go-driven routed session — `tests/integration/dns_leak_test.go`. Uses `gopacket` to capture both interfaces; fails on any A/AAAA/MX containing `.onion`. This is a fast PR-time regression gate on the SOCKS5h + `proxyDNS:true` mechanism (FR-003, FR-007); the spec-level SC-003 measurement is T034a.

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
