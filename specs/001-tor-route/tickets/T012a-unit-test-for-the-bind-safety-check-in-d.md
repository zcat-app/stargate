---
id: T012a
title: 'Unit test for the bind-safety check in `data-plane/internal/bind/check'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T012a
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006, T013]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T012a: Unit test for the bind-safety check in `data-plane/internal/bind/check

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for the bind-safety check in `data-plane/internal/bind/check_test.go` (precedes T013; Principle VII — bind/routing decisions are privacy-critical, FR-010 prevents the local-profile loopback-only invariant from drifting). Table-driven cases assert: (a) IPv4 loopback `127.0.0.1` and other `127.0.0.0/8` addresses accepted; (b) IPv6 loopback `::1` accepted; (c) `0.0.0.0`, `::`, RFC1918 (`192.168.x.x`, `10.x.x.x`, `172.16.x.x`), link-local (`169.254.x.x`, `fe80::/10`), and any public-routable IP rejected with the package's `BIND_REFUSED` error sentinel; (d) DNS names (`localhost`, arbitrary strings) rejected — the check operates on parsed IP literals only, so name resolution cannot smuggle a non-loopback bind past it; (e) malformed inputs (empty string, garbage bytes) rejected. Pure unit test — no listener side effects, no goroutines, no sockets. Pairs with T013 (impl) and is referenced from T050's startup sequence (`bind/check.go` runs FIRST before any listener opens).

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
