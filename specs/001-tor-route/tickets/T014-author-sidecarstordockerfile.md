---
id: T014
title: 'Author `sidecars/tor/Dockerfile`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T014
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T014: Author `sidecars/tor/Dockerfile`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `sidecars/tor/Dockerfile` — pinned `debian:12-slim` base by sha256 digest, installs `tor` from `deb.torproject.org`, verifies the apt-repo signing key at build time against `sidecars/tor/apt-key.fingerprint` (per FR-015), drops privileges to a non-root `tor` user, declares `HEALTHCHECK` parsing for "Bootstrapped 100%" against `Log notice stdout` from the rendered config.

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
