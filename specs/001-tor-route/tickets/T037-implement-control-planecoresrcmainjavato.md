---
id: T037
title: 'Implement `control-plane/core/src/main/java/.../TorrcRenderer.java` re'
status: deferred
created: 2026-07-04
last_updated: 2026-07-12
source: tasks.md#T037
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T089]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
deferred_on: T089
deferred_reason: spec-amend
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T037: Implement `control-plane/core/src/main/java/.../TorrcRenderer.java` re

## Context

**Deferred by T089 (spec-amend).** T089 amended FR-011 /
`contracts/torrc.md` so the static Tor-only slice bakes the byte-pinned
safe `torrc` into the Tor image at build time (T087) and the control
plane does NOT render `torrc` at boot (Constitution Principle II /
sol-review B2: Compose starts Tor before the CP). The `TorrcRenderer`
and its atomic-write-to-`stargate-tor-config` flow are therefore not
needed for v1 — they are future work for a dynamic-config feature
(bridges toggle, live reload). This ticket is deferred until that
feature re-opens the ownership decision. The byte-for-byte gate the
renderer would have satisfied is held for v1 by the Go-only chain
`contracts/torrc.md` == `wantTorrc` golden (T029) == image-baked
`/etc/tor/torrc` (T087 cold-volume test); the Java `render() == golden`
link is deferred with this ticket.

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/core/src/main/java/.../TorrcRenderer.java` rendering the byte-exact template from `contracts/torrc.md`; atomic write (`tmp` + fsync + rename) to the `stargate-tor-config` named volume. Verified by T029.

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
