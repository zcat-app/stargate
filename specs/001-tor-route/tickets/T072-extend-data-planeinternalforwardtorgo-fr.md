---
id: T072
title: 'Extend `data-plane/internal/forward/tor.go` (from T047) to map upstrea'
status: pending
created: 2026-07-04
last_updated: "2026-09-21"
source: tasks.md#T072
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T065", "T066", "T067", "T067a", "T067b", "T070", "T071", "T156"]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
tests_first: ["T065", "T066", "T067", "T067a", "T067b", "T070"]
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T072: Extend `data-plane/internal/forward/tor.go` (from T047) to map upstrea

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Extend `data-plane/internal/forward/tor.go` (from T047) to map upstream SOCKS5 connect-failure replies to `ROUTE_REFUSED` and to enforce the 30 s dial-and-handshake deadline mapped to `ROUTE_TIMEOUT` per `contracts/socks5-auth.md` §"Deadlines" (wired as a single named constant; no idle deadline after handshake — the post-handshake byte pipe is intentionally long-lived per Principle I). The mapping emits the **inbound-protocol-appropriate** response shape: on the HTTP CONNECT path, the privacy-safe HTML template via T071; on the SOCKS5 path, the 10-byte RFC 1928 §6 reply with `BND.ADDR`/`BND.PORT` zeroed per `contracts/socks5-auth.md` §"SOCKS5 request-phase failures (post-auth)" — `ROUTE_DOWN→0x03`, `ROUTE_REFUSED→0x04`, `ROUTE_TIMEOUT→0x06`. **No Tor reason text or upstream error string propagates into the response on either shape** (FR-009). Verified by T065–T070 (CONNECT shape), T067a (SOCKS5 shape), and T067b (counter-increment asymmetry across both shapes).

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

## T172 selected acceptance (supersedes conflicting historical task text)

Implement the 30 s upstream dial/handshake timeout and map `ROUTE_DOWN/REFUSED/TIMEOUT` only to the fixed SOCKS5 REP `03/04/06` with zero BND fields, EOF and no upstream text. No idle deadline after handshake, event-gated admission, HTTP template path or fallback. T065–T070/T067a/b remain the verification consumers.

## T173 renderer dependency refinement

T071 owns the consolidated T068/T069 tests and renderer implementation. Retain T071 as
the blocker; the superseded deferred test tickets must not independently block this consumer.
