---
id: T016
title: 'Author `scripts/stargate` entrypoint and `scripts/subcommands/init` de'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T016
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T016: Author `scripts/stargate` entrypoint and `scripts/subcommands/init` de

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `scripts/stargate` entrypoint and `scripts/subcommands/init` delivering the minimum subset per research.md §8: preflight, ed25519 key generation into `stargate-keys` volume (private keys `cp.priv` mode 0600 owned `stargate-cp`, `dp.priv` mode 0600 owned `stargate-dp`; public keys `cp.pub` and `dp.pub` mode 0644 — public material, both planes must read both pubs for the mutual handshake), hard-coded `compose/docker-compose.local.yml`, bounded healthcheck wait, Tor-only verification, status table, stable exit codes (10/20/30/40/50).

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
