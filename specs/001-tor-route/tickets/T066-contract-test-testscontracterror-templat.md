---
id: T066
title: "Test SOCKS5 ROUTE_REFUSED failure reply"
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T066
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
parallel: true
files_budget: 3   # route_refused_test.go, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md SC-004 and US3 acceptance scenario 2'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" and §"Invariants enforced by the contract test"'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
decision_refs:
  - 'T172 selected acceptance: a sidecar SOCKS refusal maps to fixed REP 0x04 without upstream reason text'
  - 'T064: static leak corpus is the shared source; per-run token and destination are added in memory'
reviews: { round: 2, date: 2026-10-09, verdict: APPROVE, findings: 0, diff_stats: "1 Go test file" } # Astra and Luna approved after round-1 fixes.
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T066: Test SOCKS5 ROUTE_REFUSED failure reply

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test `tests/contract/error-template/route_refused_test.go` — Tor up, CONNECT targets a non-resolvable `.onion`; assert 502 + template + `ROUTE_REFUSED`; leak-corpus scan passes (in particular, no Tor SOCKS5 reason text in the body).

## Analysis

- **Must hold:** the valid token passes auth and the upstream dial actually
  occurs. A scripted SOCKS5 sidecar refusal is mapped to exactly
  `05 04 00 01 00 00 00 00 00 00`, then close with no trailing bytes; upstream
  reason bytes never reach the client or request-time diagnostics (Principles I
  and III).
- **Gated:** one fake upstream accepts the data-plane connection, completes
  method/auth negotiation, records the requested `.onion` target, and returns a
  refusal plus a distinctive private trailing sentinel. The test scans the
  full reply and post-boot journal delta against T064's corpus and dynamic
  token, target, and sentinel.
- **Residue:** this controls the SOCKS boundary and refusal mapping; it does not
  establish live onion reachability or Tor's complete refusal implementation.

## Acceptance

1. Add `tests/contract/socks5/route_refused_test.go`. Authenticate with a valid
   token; drive the data plane through a local scripted SOCKS5 upstream that
   records the request and returns REP `0x04`. Assert the client reply is
   byte-exactly `05 04 00 01 00 00 00 00 00 00`, followed by EOF and no extra
   bytes. The upstream must observe exactly one dial and the intended `.onion`
   target.
2. Append a unique upstream-only sentinel after the upstream failure reply and
   assert it appears neither in the client reply nor in the request-time
   journal delta. Scan the full reply and journal delta against the T064 static
   corpus and this run's token and destination. Assert no HTML marker appears.
3. Run only
   `cd tests/contract && go test ./socks5 -run '^TestRouteRefusedSOCKS5Reply$'`.
   Re-run after corrections; do not run Java, Docker, VM, or repository-wide
   verification for this contract test.

## Out-of-scope

- No HTTP renderer/template assertion, counters, or production code change.
- No real Tor service, external network, Docker, or VM.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Implement authenticated SOCKS5 `ROUTE_REFUSED` under `tests/contract/socks5/`: upstream refusal yields exactly `05 04 00 01 00 00 00 00 00 00`, then EOF, with no upstream reason or corpus hit. Use the real/fake upstream control needed to prove a dial occurred.
