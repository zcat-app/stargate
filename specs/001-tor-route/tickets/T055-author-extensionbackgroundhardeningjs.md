---
id: T055
title: 'Author `extension/background/hardening.js`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T055
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T055: Author `extension/background/hardening.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/background/hardening.js` — DoH off (`network.trr.mode = 5`) / DoT off (`network.dns.over_tls.*` family absent or all-false; defense-in-depth against future ESR adding DoT) / WebRTC fully disabled (`privacy.network.peerConnectionEnabled = false`, read via `browser.privacy.network.peerConnectionEnabled`) / HTTP/3 off (`network.http.http3.enable = false`) audit per arch §14.5; blocking dialog on failure; routing is blocked via a flag that `router.js` (T054) checks before returning the SOCKS descriptor (FR-004). **Verified by T034b.**

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
