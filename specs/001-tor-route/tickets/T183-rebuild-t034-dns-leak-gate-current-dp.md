---
id: T183
title: 'Rebuild the T034 DNS-leak gate on the current DP interface'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 1 M2, survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 4
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"   # DNS and route failure
  - "VII: Tests-First for Privacy-Critical and Contract Code"   # coverage cannot disappear through skips
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-003
  - specs/001-tor-route/spec.md#FR-007
decision_refs: []
remediates: "T034"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-001-dns-leak-gate-stale"]
clarity_check: {}
---

# T183: Rebuild the T034 DNS-leak gate on the current DP interface

## Context

`tests/integration/dns_leak_test.go` (T034, `status: done`) boots the DP with
`STARGATE_TOR_SOCKS5` and `STARGATE_TEST_TOKEN_PLAINTEXT`. Neither exists in
the DP: `data-plane/cmd/stargate-proxy/main.go` reads `STARGATE_TOR_SOCKS_ADDR`,
requires a `unix://` upstream and loads a pepper from the keys directory.
Falsification (2026-09-29) ran the real DP with the test's environment: it
exits 1 at startup. The test's `CircuitIDs()==0` guard makes it fail rather
than pass vacuously, but no current evidence covers FR-003's "no DNS during a
routed session". The property is defended structurally (no resolver code,
seccomp/Landlock, owner DROP rules, T163 packet evidence); the gate is not.

## Analysis

- Must hold: a routed `.onion`/hostname SOCKS5h session through the real DP
  emits zero DNS packets from the DP, observed on a capture that is proven able
  to see DNS.
- Gated: the rebuilt gate runs in its declared cadence with RUN/PASS, not SKIP.
- Residue: capture scope (loopback/host) is stated; it does not cover the
  browser, which T157/T188 own.

## Acceptance

1. Rebuild T034 on the current DP interface (e.g. `tests/contract/internal/dpharness`
   with a Unix upstream, seeded pepper and a token delivered through
   `ReloadTokens`, or the Local compose stack). No test-only DP environment
   surface is added to production code.
2. Keep the capture-started and forwarding-exercised guards. Add a positive
   control: a deliberate resolver query from an unconfined helper must appear
   in the same capture before the DP's zero-DNS assertion counts.
3. Red before green: record the current failing run, then the passing run of
   the identical command with `scripts/test-first-evidence.py`. Record that the
   positive control fails the assertion when the DP-side query is simulated.
4. `scripts/verify.sh` reports the gate honestly (RUN/PASS in its cadence, a
   `SKIP:` line otherwise).

## Out-of-scope

Production DP behaviour changes; browser-side DNS (T188/T157); IPv6 routed egress.
