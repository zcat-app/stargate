---
id: T067a
title: 'Retain SOCKS5 failure privacy assertions'
status: in-progress
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T067a
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156", "T065", "T066", "T067"]
parallel: true
files_budget: 5   # three existing SOCKS5 failure tests, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" and §"Invariants enforced by the contract test"'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
  - 'specs/001-tor-route/spec.md FR-009 and US3 failure-path acceptance'
decision_refs:
  - 'T172 selected acceptance: preserve the three exact SOCKS5 replies, EOF, no HTML/upstream text, and leak scans without duplicate fixtures'
  - 'T025a shared log allowlist applies to route-failure request windows; historical T067a task invariant (g) remains in force'
  - 'T065, T066, and T067 own the isolated route-failure fixtures; T067a fills the missing shared log-allowlist assertion'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T067a: Contract test for SOCKS5 request-phase failure replies (FR-009 SOCKS5 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Contract test for SOCKS5 request-phase failure replies (FR-009 SOCKS5 path; `contracts/socks5-auth.md` §"SOCKS5 request-phase failures (post-auth)") in `tests/contract/socks5/request_phase_failures_test.go`. Three sub-cases, all over an authenticated SOCKS5 connection on port 8881:

## Analysis

- **Must hold:** all three authenticated route failures return their exact
  ten-byte SOCKS5 reply with zeroed BND fields, then clean EOF and no extra
  bytes. The complete reply and request-window diagnostics remain free of T064
  corpus values and run-specific token/destination values. No per-request log
  line is emitted for these failures (T025a allowlist, Principle III).
- **Existing coverage:** `TestRouteDownSOCKS5Reply` (T065),
  `TestRouteRefusedSOCKS5Reply` (T066), and `TestRouteTimeoutSOCKS5Reply`
  (T067) already assert authenticated setup, exact REP 0x03/0x04/0x06 frames,
  EOF/no trailing bytes, and reply/journal corpus scans. T066 also proves the
  upstream refusal and private sentinel are not leaked. Exact replies plus
  clean EOF exclude HTML and upstream response text.
- **Residue:** the historical T067a task body additionally requires the
  shared request-log allowlist across all three cases. The existing tests
  collect the request-window `journalDelta` but do not apply that allowlist;
  corpus scanning alone cannot reject arbitrary per-request log text.
- **Plan:** add
  `loginvariants.AssertOnlyAllowedLines(t, journalDelta)` to those three
  existing tests. Do not create a second fixture or modify production code.
  This follow-up preserves the already-committed T065/T067 commits and keeps
  this ticket's change within five paths. An independent Astra plan review
  confirmed the coverage map and required re-running every changed focused
  test, including T067's production-deadline timeout case.

## Acceptance

1. Add `loginvariants.AssertOnlyAllowedLines(t, journalDelta)` to each of
   `tests/contract/socks5/route_down_test.go`,
   `tests/contract/socks5/route_refused_test.go`, and
   `tests/contract/socks5/route_timeout_test.go`, using each test's existing
   request-window journal delta. Preserve the fixtures and all current exact
   reply, EOF, and leak-corpus assertions.
2. Do not add another route-failure fixture. The three existing tests jointly
   cover valid SOCKS5 authentication, exact REP 0x03/0x04/0x06 responses with
   zero BND fields, clean EOF/no trailing bytes, no HTML/upstream response
   text, T064 corpus plus dynamic token/destination scans, and (for T066) the
   upstream-only sentinel. The added allowlist call closes historical T067a
   task invariant (g), which is not implied by a corpus scan.
3. Run only the affected tests:
   `cd tests/contract && go test -count=1 -timeout 5m ./socks5 -run '^(TestRouteDownSOCKS5Reply|TestRouteRefusedSOCKS5Reply|TestRouteTimeoutSOCKS5Reply)$'`.
   T067 intentionally preserves the 250-second production deadline. Do not
   run Java, VM, Docker, or repository-wide verification for this test-only
   follow-up.

## Out-of-scope

- No new SOCKS5 failure fixtures, protocol behavior, production code, or
  changes to the accepted T065/T066/T067 response assertions.
- No HTTP renderer assertion, Java test, VM, Docker stack, or broad suite.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Retain all three byte-exact authenticated SOCKS5 route-failure replies, zero BND fields, EOF, no HTML or upstream text and corpus scanning. This is the supported Tor error path; avoid duplicate fixtures with T065–T067 while retaining every assertion.
