---
id: T070b
title: 'Test WatchEvents failure transitions remain advisory'
status: in-progress
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T070b
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T156"]
parallel: true
files_budget: 3   # test file, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/contracts/control-grpc.md §"WatchEvents · Contract" and §"Tests"'
  - 'specs/001-tor-route/contracts/foundation-boundaries.md §2; Constitution Principle II'
decision_refs:
  - 'T172 selected acceptance: keep WatchEvents advisory; stale events and CP disconnect cannot suppress an authenticated SOCKS5 dial'
  - 'T090: sidecar events never gate admission; upstream dial is the ground truth'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T070b: Test WatchEvents failure transitions remain advisory

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test for `WatchEvents` failure transitions (`UNHEALTHY`/`STOPPED`/`CRASHED`/`RESTARTED` for `tor`, fixed-vocabulary `detail`) in `tests/contract/control-grpc/watch_events_failure_transitions_test.go` — per `contracts/control-grpc.md` §"WatchEvents · Contract" v1 `(kind, detail)` pairing table:

## Analysis

- **Must hold:** each selected finite failure transition is delivered over the
  fake authenticated control stream without suppressing an authenticated SOCKS5
  dial to a reachable fake upstream. A control-plane stream disconnect and
  reconnect likewise cannot stop routing. The test must not claim that the
  current control plane emits STOPPED, CRASHED, or RESTARTED; those are stale or
  forged advisory inputs for the regression.
- **Gated:** one focused Go contract test exercises the failure-event matrix,
  forwarding before/after events, and forwarding across disconnect/reconnect.
  Existing forbidden-detail coverage remains intact.
- **Residue:** this fake-backed test cannot establish real container lifecycle
  reporting or Tor reachability; those are outside this ticket and do not
  justify Docker, Java, VM, or host mutation here.

## Acceptance

1. In `tests/contract/control-grpc/watch_events_test.go`, preserve coverage of
   the finite failure pairings `UNHEALTHY/healthcheck_fail`,
   `STOPPED/container_exit`, `CRASHED/container_exit`, and
   `RESTARTED/container_start`. Inject STOPPED, CRASHED, and RESTARTED as
   deliberately stale/forged fake-stream events with timestamps at least one
   hour before the test; do not claim a current
   production lifecycle source emits them. Send `UNHEALTHY/healthcheck_fail`
   as an advisory event. After each event, prove that a valid token still
   completes an authenticated SOCKS5 CONNECT through the reachable fake
   upstream. No HTTP request is part of this test.
2. Preserve the existing bounded stream reconnect and authenticated forwarding
   assertions before and after control-plane disconnect, plus forbidden-detail
   rejection. Do not add event logs, expose event payloads, weaken the fixed
   detail vocabulary, or infer route health from the event kind.
3. Run only the affected test with
   `cd tests/contract && go test ./control-grpc -run '^TestWatchEvents$'`.
   Re-run it after any test or helper correction. This test-only ticket does
   not require a production-code RED/GREEN record, a Java suite, or the
   repository-wide verification gate.

## Out-of-scope

- No control-plane Java lifecycle monitor, Docker mock/daemon, audit database,
  production implementation, or schema changes.
- No HTTP ingress or error-template assertion; T172 selects SOCKS5 only.
- No VM, live Tor, or host-policy operation.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Preserve all finite WatchEvents kind/detail and reconnect assertions. Add/retain an authenticated SOCKS5 dial control proving STOPPED/CRASHED/stale events and CP disconnect cannot suppress a reachable upstream dial; no HTTP ingress is used.
