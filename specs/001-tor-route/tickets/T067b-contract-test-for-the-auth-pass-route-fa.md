---
id: T067b
title: 'Contract test for the auth-pass + route-failure counter-increment asym'
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T067b
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T156", "T067"]
parallel: true
files_budget: 3   # route_failure_counter_test.go, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/data-model.md §3 (`request_count` and `byte_count`)'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
decision_refs:
  - 'T172 selected acceptance: authenticated SOCKS5 only; 20 requests for each route failure, aggregate request delta 60 and byte delta 0'
  - 'T173 selected acceptance: HTTP C is tested separately and cannot be counted as authenticated traffic'
  - 'T064: scan with shared static corpus and add per-run token/destinations in memory'
reviews: { round: 1, date: 2026-10-09, verdict: APPROVE, findings: [], diff_stats: "1 Go test file" } # Astra and Luna approved; exact focused target passed in 255.022s.
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T067b: Contract test for the auth-pass + route-failure counter-increment asym

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test for the auth-pass + route-failure counter-increment asymmetry (FR-008 second half; data-model.md §3 — "Route failures (`ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`) DO increment `request_count` once authentication has passed"; the synthesised error-template body is NOT included in `byte_count`) in `tests/contract/socks5/route_failure_counter_test.go`. Uses the same DP-hosted `GetStatus` RPC from T007 / T045 that T025c and T025d use, on the same `/run/stargate/dp.sock`. Three sub-cases, each opening N=20 authenticated CONNECTs through port 8881 (mix of SOCKS5 and HTTP CONNECT inbound framing per sub-case so both protocol surfaces are exercised):

## Analysis

- **Must hold:** each authenticated route-failure request increments
  `request_count` once, but contributes zero forwarded `byte_count`; the
  listener's synthesized 10-byte SOCKS reply is not an upstream byte.
- **Gated:** three isolated process-backed subcases use a deterministic test
  hour, query the DP's existing `GetStatus` before and after each set, and
  drive 20 authenticated SOCKS5 CONNECTs for ROUTE_DOWN, ROUTE_REFUSED, and
  ROUTE_TIMEOUT. Assert +20 requests and +0 bytes in each case, aggregate +60
  and +0, exact replies, EOF, the T064 corpus, and the shared log allowlist.
  The 20 timeout attempts run concurrently against T019a Slow so the 250-second
  production deadline is paid once, not sequentially. Assert all 20 complete
  CONNECT requests reached the fake after its parser consumed each request;
  `CircuitIDs()` alone proves only upstream authentication.
- **Residue:** the test proves in-memory DP counter semantics at the process
  boundary. It does not exercise HTTP `C` refusal (T173) or SQLite persistence;
  neither is a v1 data-plane behavior.

## Acceptance

1. Add `tests/contract/socks5/route_failure_counter_test.go`. For each
   isolated route outcome, boot the process harness with the deterministic
   counter clock, load one valid token, take a `GetStatus` baseline, and issue
   exactly 20 authenticated SOCKS5 CONNECTs. The counter bucket must be the
   frozen `TOR` hour for every request.
2. ROUTE_DOWN uses a known-absent Unix upstream socket and expects
   `05 03 00 01 00 00 00 00 00 00`; ROUTE_REFUSED uses a scripted local SOCKS5
   server that records each CONNECT and returns REP `0x04`, expecting
   `05 04 00 01 00 00 00 00 00 00`; ROUTE_TIMEOUT uses T019a Slow with a
   251-second reply delay, expects `05 06 00 01 00 00 00 00 00 00`, and drives
   the 20 requests concurrently so the 250-second deadline is bounded once.
   Every connection must authenticate first, receive exactly ten reply bytes,
   then close with EOF and no additional bytes.
3. After each case, assert `request_count` delta `+20`, `byte_count` delta `0`,
   and the expected `TOR` hour bucket. Assert the combined deltas are exactly
   `+60` and `0`. Check only the request-window journal delta with the shared
   allowlist and scan replies/logs against the T064 corpus plus all runtime
   destinations and the token. Do not include HTTP `C` requests.
   For ROUTE_TIMEOUT, assert `slow.ConnectCount() == 20` after all replies,
   proving every fake handler consumed a complete CONNECT before the 251-second
   delay; retain the distinct-identity check as separate upstream-auth evidence.
4. Run only
   `cd tests/contract && go test -timeout 5m ./socks5 -run '^TestRouteFailureCounterAsymmetry$'`.
   This targeted test takes about 250 seconds because it preserves the
   production deadline; do not run Java, Docker, VM, or repository-wide
   verification for this test-only ticket.

## Out-of-scope

- No HTTP refusal or HTML renderer test, no error-template generation, and no
  SQLite/Control Plane persistence assertion.
- No production code, deadline override, external network, Docker, or VM.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Use authenticated SOCKS5 CONNECT only for each of three route-failure subcases (N=20 each). Assert `request_count` delta 60 and `byte_count` delta 0, exact REP bytes and no logs/leak-corpus hits. T173 separately checks HTTP `C` leaves both counters unchanged; HTTP cannot count as an auth-passed request.
