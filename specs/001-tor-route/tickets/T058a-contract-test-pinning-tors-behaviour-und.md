---
id: T058a
title: 'Contract test pinning Tor''s behaviour under `IsolateSOCKSAuth` when an'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T058a
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062]   # manual edge: task body uses the T062 control-port helper for circuit-status queries (derive-deps missed prose deps; tightened 2026-09-07)
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

# T058a: Contract test pinning Tor's behaviour under `IsolateSOCKSAuth` when an

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test pinning Tor's behaviour under `IsolateSOCKSAuth` when an upstream SOCKS5 client provides no username — `tests/contract/tor/username_less_isolation_test.go` (negative companion to T058). Spins up the Tor sidecar with the rendered torrc; connects directly to `tor:9050` (bypassing port 8881) twice with auth method `0x00` (NO_AUTH) and no username; uses the T062 control-port helper to query `circuit-status` and capture the circuit ID each stream attached to. Asserts: (a) Tor accepts both NO_AUTH connections (Tor's `SocksPort` permits NO_AUTH by default); (b) both streams attach to the SAME circuit ID — a default/shared circuit, because `IsolateSOCKSAuth` only isolates when a username is provided, so no-username traffic shares a circuit by design. This task exists to **pin Tor's actual behaviour** so T047's outbound-SOCKS5 contract (data plane always forwards with the inbound first-party username) is verified to be defensive against the real failure mode: silent circuit sharing if the data plane ever forwarded a username-less request. If a future Tor release changes this behaviour (e.g., rejects NO_AUTH outright under `IsolateSOCKSAuth`), this test fails during the digest-bump PR (Principle IV manual-promotion gate) and the data plane's outbound contract is renegotiated with a `SECURITY-DECISIONS.md` entry. Lives under `tests/contract/tor/` (not `torrc/`) so FR-016's `tor/` directory holds at least one behavioural-invariant test, not just the port-exposure assertion.

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
