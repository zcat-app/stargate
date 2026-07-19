---
id: T054
title: 'Author `extension/background/router.js`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T054
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T091, T034b, T055]
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

# T054: Author `extension/background/router.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/background/router.js` — `browser.proxy.onRequest` listener that returns `{ type: "socks", host: "127.0.0.1", port: 8881, username: <first-party from T053>, password: <bearer token from T052>, proxyDNS: true }` for hosts matching `.onion` (**FR-001** — this is the canonical implementation of the `.onion`→port-8881 routing rule); no proxy for other hosts in this feature. `failoverTimeout` is intentionally NOT set — Firefox's default (5 seconds) is acceptable and pinning it would create a magic number with no spec-level rationale; if a future feature needs a tighter or looser failover, the change ships with a justification in that feature's research doc.

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
