---
id: T058
title: 'Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T058
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062]   # manual edge: task body consumes T062's control-port helper (derive-deps missed prose deps; tightened 2026-09-07)
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

# T058: Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.go` — spins up the Tor sidecar with the rendered config, issues two SOCKS5 CONNECTs with distinct usernames, queries the control port for `circuit-status`, asserts the two streams attached to distinct circuit IDs. (`contracts/torrc.md` §"isolate_socks_auth_effect_test.go".)

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
