---
id: T065
title: "Test SOCKS5 ROUTE_DOWN failure reply"
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T065
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
parallel: true
files_budget: 3   # route_down_test.go, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md SC-004 and US3 acceptance scenario 1'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" and §"Invariants enforced by the contract test"'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
decision_refs:
  - 'T172 selected acceptance: Tor-route failures use authenticated SOCKS5 replies; no HTML is reachable on port 8881'
  - 'T064: static leak corpus is the shared source; per-run token and destination are added in memory'
reviews: { round: 2, date: 2026-10-09, verdict: APPROVE, findings: 0 }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T065: Test SOCKS5 ROUTE_DOWN failure reply

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test `tests/contract/error-template/route_down_test.go` — stop the Tor container, send CONNECT with valid auth; assert 502 + template + `X-Stargate-Error: ROUTE_DOWN`; leak-corpus scan passes.

## Analysis

- **Must hold:** a valid token passes RFC 1929 authentication before the
  request-phase failure. A deliberately absent Unix upstream socket yields
  exactly `05 03 00 01 00 00 00 00 00 00`, followed by connection close and no
  additional bytes. The data plane does not inspect a `SidecarEvent` to decide
  whether to admit the request (Principle II).
- **Gated:** run one authenticated SOCKS5 CONNECT against a known-missing
  `unix://` socket configured through `dpharness.WithUpstream`; scan the full
  reply and post-boot journal delta against the committed T064 corpus plus the
  test's token and destination. Assert no HTML marker or private value appears.
- **Residue:** this process-harness test proves the fixed failure surface for
  an unavailable local SOCKS endpoint. It does not prove real Tor health,
  Docker lifecycle reporting, or remote reachability; those are out of scope.

## Acceptance

1. Add `tests/contract/socks5/route_down_test.go`. Load a valid token, confirm
   auth succeeds, then issue one CONNECT to a fixed `.onion` target while the
   configured upstream is a Unix socket path verified absent before the
   request. Assert the reply is byte-exactly `05 03 00 01 00 00 00 00 00 00`
   and then EOF; reject trailing bytes, HTML, any T064 corpus match, or the
   token/destination in the reply or request-time journal delta.
2. The test uses only the existing process-backed `dpharness`, loopback proxy
   listener, and absent local Unix socket. It neither needs a control-plane
   event nor treats an unhealthy/withheld event as a route failure.
3. Run only
   `cd tests/contract && go test ./socks5 -run '^TestRouteDownSOCKS5Reply$'`.
   Re-run after any correction; do not run Java, Docker, VM, or repository-wide
   verification for this contract test.

## Out-of-scope

- No HTTP status, template, renderer, or header assertion; the HTTP format is
  renderer-only and port 8881 rejects HTTP framing.
- No counter assertion (T067b), remote Tor, container lifecycle, or production
  code change.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Implement an authenticated SOCKS5 `ROUTE_DOWN` test under `tests/contract/socks5/`: Tor socket unreachable yields exactly `05 03 00 01 00 00 00 00 00 00`, then EOF. Scan full reply and diagnostics against T064 corpus. A withheld/unhealthy advisory event with reachable Tor must not produce this failure.
