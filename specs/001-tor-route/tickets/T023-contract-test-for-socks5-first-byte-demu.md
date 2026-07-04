---
id: T023
title: 'Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `''C'''
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T023
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

# T023: Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `'C'

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `'C'` → CONNECT, anything else → silent close) and method negotiation: (a) `0x05 0x02` for `[0x02]`-only (input `0x05 0x01 0x02`); (b) `0x05 0x02` for `[0x00, 0x02]` mixed (input `0x05 0x02 0x00 0x02` — USERNAME/PASSWORD MUST win even when NO_AUTH is also offered); (c) `0x05 0xFF` for `[0x00]`-only (input `0x05 0x01 0x00`). In `tests/contract/socks5/demux_test.go` — per `contracts/socks5-auth.md` §"Two inbound protocols, one port" and §"Auth method negotiation".

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
