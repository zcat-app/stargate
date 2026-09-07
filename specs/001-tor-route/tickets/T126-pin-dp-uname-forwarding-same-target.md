---
id: T126
title: 'Pin DP UNAME forwarding: same target, distinct usernames, via 8881'
status: pending
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention; T059 round-1 review Finding 4 + RECOMMENDED-FOLLOW-UP)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T059, T125]   # extends T059's harness; no live full-stack run is feasible until the T125 bind/publish conflict is decided
parallel: false   # same test file family as T059; lands after it
files_budget: 3
privacy_critical: true   # this is the actual FR-002 end-to-end isolation gate — the DP-side credential-fusion failure mode
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-002   # distinct first-party domains produce distinct circuits — the property the DP hop is load-bearing for
   - specs/001-tor-route/spec.md#FR-007   # DP forwards the inbound UNAME verbatim upstream (forward/tor.go dialUpstream)
   - specs/001-tor-route/contracts/socks5-auth.md   # UNAME/PASSWD mapping the test reproduces
   - specs/001-tor-route/tasks.md#T059   # harness this extends
decision_refs:
   - .specify/memory/constitution.md#Principle-VII   # tests-first: the DP's forwarding contract currently has no runtime gate through the DP
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T126: Pin DP UNAME forwarding: same target, distinct usernames, via 8881

## Context

Hand-filed from T059's round-1 review (2026-09-07). T059's honest-mechanism
note (live-captured) established that its two DISTINCT onion destinations
make distinct circuits overdetermined: rendezvous circuits are
destination-bound, so a DP regression that fused, dropped, or constant-
folded the upstream SOCKS5 username (`forward/tor.go dialUpstream`'s
FR-007 contract) would still see two distinct circuit IDs and pass T059.
T058/T058a pin the username-isolation axis at tor level but dial
`tor:9050` directly — they bypass the DP hop entirely. No runtime test
today drives SAME target / DIFFERENT inbound usernames THROUGH port 8881;
the DP's UNAME-forwarding contract is therefore unpinned end-to-end.

## Analysis

*(Quick pass — extends T059's harness machinery; same module, same
project-isolation conventions.)*

- Shape: two parallel CONNECTs through 8881 to the SAME real onion
  (the spec-pinned DuckDuckGo reference) with two different first-party
  UNAMEs and the seeded PASSWD; assert the two streams land on distinct
  non-zero circuit IDs, both BUILT. A credential-fusing DP sends one
  upstream credential twice → tor's IsolateSOCKSAuth attaches both
  streams to one circuit → the assertion fails (positive control: T058
  already proved the tor-side mechanism with this exact shape).
- Real target required (stream-level attribution; T059 §Analysis).
- The transport/probe/seed/forensics machinery is T059's, reused; only
  the dial matrix (same target, distinct UNAMEs) is new.

## Acceptance

1. Named test in `tests/integration/` (e.g.
   `stream_isolation_dp_uname_test.go`) asserting the same-target /
   distinct-UNAME pair through 8881 lands on distinct, non-zero, BUILT
   circuits — with T059's classification + log-tail forensics on the
   fatal path.
2. Runnable live (T059 acceptance item 2's cadence + prerequisites).
3. `bash scripts/verify.sh` green (hermetic compile/vet; env-skip).

## Out-of-scope

- T059's distinct-destination scenario (complementary, already filed).
- Any production-code change — this is a verification-surface ticket.

## Notes

Hand-filed by the T059 session per the review follow-up; deliberately
NOT folded into T059 (its diff is under must-shrink on round 2, and the
two scenarios exercise different DP failure modes).
