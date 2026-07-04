---
id: T025b
title: 'Contract test for long-lived bidirectional CONNECT (Principle I byte-p'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T025b
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

# T025b: Contract test for long-lived bidirectional CONNECT (Principle I byte-p

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for long-lived bidirectional CONNECT (Principle I byte-pipe invariant; spec §"Edge Cases" rows *WebSocket upgrade through CONNECT* and *HTTP/2 connections (forced fallback from QUIC)* — both mechanically subsumed: any TLS-over-CONNECT payload (H1, H2, WebSocket) is opaque bytes to the data plane after the SOCKS5/CONNECT handshake completes, so the byte-pipe transparency assertion covers all three protocol shapes without needing protocol-specific tests) — open an authenticated SOCKS5 *and* HTTP CONNECT through port 8881 to the `accept-and-relay` upstream from T019a; after handshake, exchange interleaved frames in both directions for ≥30s (mix of small / medium / large byte runs; asymmetric bandwidth; idle gaps up to 5s); assert (a) every byte round-trips unmodified — no insertion, deletion, reordering, or rewriting in either direction; (b) the data plane emits no log line for the frame traffic (the T025a shared allowlist applies); (c) the connection stays open until *either end* initiates close — the data plane MUST NOT close it due to inactivity, frame content, or size; (d) the same property holds whether the inbound framing was SOCKS5 or HTTP CONNECT — in `tests/contract/socks5/long_lived_connect_test.go`.

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
