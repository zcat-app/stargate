---
id: T067
title: "Test SOCKS5 ROUTE_TIMEOUT failure reply"
status: in-progress
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T067
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
parallel: true
files_budget: 3   # route_timeout_test.go, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md SC-004 and US3 acceptance scenario 2'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" and §"Deadlines"'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
decision_refs:
  - 'T172 selected acceptance: the dial-and-handshake deadline maps to fixed SOCKS5 REP 0x06; no post-handshake idle deadline'
  - 'T019a: slow fake SOCKS backend delays its BND reply before handshake completion'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T067: Test SOCKS5 ROUTE_TIMEOUT failure reply

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test `tests/contract/error-template/route_timeout_test.go` — substitute the synthetic slow SOCKS5 backend (`tests/integration/fake_socks5_tor.go` from T019a, configured in `slow` mode); CONNECT to a hung target; assert 504 + template + `ROUTE_TIMEOUT`.

## Analysis

- **Must hold:** the valid token passes auth, then a slow fake SOCKS backend
  accepts the request but withholds its BND reply past the production
  250-second dial-and-handshake deadline. The data plane returns exactly
  `05 06 00 01 00 00 00 00 00 00`, closes, and emits no trailing bytes or
  upstream detail (Principles I and III).
- **Gated:** use the existing T019a `Slow` mode with its delay set beyond 250
  seconds. Preserve the production deadline; do not add an environment override
  or test-only production control. The targeted contract test may take about
  250 seconds, and its socket deadline/test timeout must exceed that bound.
- **Residue:** the slow fake proves behavior at the deployed process boundary,
  not the timing of real Tor. It does not test post-success idle behavior;
  T025b/T070a own long-lived connection behavior.

## Acceptance

1. Add `tests/contract/socks5/route_timeout_test.go`. Start the T019a fake
   backend in `Slow` mode with latency just beyond 250 seconds, boot the data
   plane with `dpharness.WithUpstream`, load a valid token, and issue one
   authenticated SOCKS5 CONNECT to a fixed target. Confirm the fake accepted
   the SOCKS5 request; read exactly
   `05 06 00 01 00 00 00 00 00 00`, then EOF, with no HTML or extra bytes.
2. Scan the full reply and request-time diagnostics against the T064 static
   corpus plus the run's token and destination. Use a client deadline and Go
   test timeout longer than the 250-second contract deadline; do not shorten or
   override the production deadline. Do not infer or test an idle timeout after
   a successful BND reply here.
3. Run only
   `cd tests/contract && go test -timeout 5m ./socks5 -run '^TestRouteTimeoutSOCKS5Reply$'`.
   Re-run after corrections; do not run Java, Docker, VM, or repository-wide
   verification for this contract test.

## Out-of-scope

- No HTTP template, counter delta (T067b), real Tor, external network, Docker,
  VM, or production deadline change.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Implement authenticated SOCKS5 `ROUTE_TIMEOUT` under `tests/contract/socks5/`: slow fake SOCKS backend exceeding the bounded dial/handshake deadline (250 s since T208; this ticket decides whether the test waits out the production value or runs the data plane with a shortened deadline, `contracts/socks5-auth.md` §Deadlines) yields exactly `05 06 00 01 00 00 00 00 00 00`, then EOF; no idle deadline is introduced after success.
