---
id: T073
title: 'In `data-plane/internal/controlclient/client.go` (from T045), wire the'
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T073
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T090", "T155", "T070b", "T156"]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
tests_first: ["T070b"]
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T073: In `data-plane/internal/controlclient/client.go` (from T045), wire the

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> In `data-plane/internal/controlclient/client.go` (from T045), wire the `SidecarEvent` consumer to treat all events as **advisory** status per data-model.md §2 (Principle II — events MUST NOT gate admission and MUST NOT short-circuit the dial). The forwarding path ALWAYS dials the upstream; events feed the audit journal (`sidecar_healthy` / `sidecar_unhealthy` rows per §4) and status reporting only. A `STOPPED`/`CRASHED` event is recorded in the audit log but the DP still dials `tor:9050` — a stale or forged event cannot suppress a dial that would succeed. `HEALTHY`/`STARTED`/`RESTARTED` update advisory status only.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

### Required planning refinement


T070b covers the event producer. Additionally author an in-ticket negative regression before
consumer changes: STOPPED/CRASHED, stale events and CP disconnect must not suppress an
otherwise successful upstream dial (Principle II). Reconcile journal output with T152 and its
implementation follow-ups. Existing behavior needs evidence, not an artificial rewrite.

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Keep SidecarEvent status advisory under Principle II. Verify with authenticated SOCKS5 that STOPPED/CRASHED/stale events and CP outage do not suppress a reachable Tor dial; no HTTP CONNECT admission is relied upon.
