---
id: T186
title: 'Fail closed in proxy.onRequest for blocked protected requests'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 2 M1, survived falsification, sharpened)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 5
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"   # no silent fallback to Direct or system proxy
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md#FR-004a
decision_refs:
  - "T157 (done): blocking listener plus null proxy result; its combined mutant disabled the blocker only on the Tor-descriptor path"
remediates: "T157"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-004-blocked-null-is-direct"]
clarity_check: {}
---

# T186: Fail closed in proxy.onRequest for blocked protected requests

## Context

`extension/background/router.js` returns `null` from `proxy.onRequest` for a
blocked protected request (missing request id, non-tor decision, rejected
decision). In Gecko's `ProxyChannelFilter.sys.mjs` a `null` result removes any
proxy configuration: an explicit direct connection that also bypasses a
configured browser/system proxy. FR-004a says the matching result is never
Direct; today only the separate `webRequest.onBeforeRequest` cancel prevents
the connection.

Falsification (2026-09-29, Mullvad Browser 153.3.0esr, a null-returning test
extension with no blocker): `x.onion` is stopped by Gecko's
`network.dns.blockDotOnion` (no port-53 traffic under strace), but a trailing
dot `x.onion.` escapes that check. A DNS query for the onion name went to the
system resolver and, with a local domain mapping, the request reached the
destination directly. T157 never exercised "blocked → null with the blocker
disabled".

## Analysis

- Must hold: a blocked protected request's proxy result can never produce a
  direct connection, a system-proxy connection or a DNS query for the name,
  independently of the cancel listener. Intentional Direct stays unchanged.
- Gated: unit tests assert the fail-closed result; a real-browser probe with the
  cancel listener disabled observes zero direct, proxy and DNS traffic,
  including trailing-dot and mixed-case onion hosts, with positive controls.
- Residue: a fail-closed descriptor pointing at a loopback port must not hand
  the hostname to a later process binding that port; weigh and document the
  choice.

## Acceptance

1. Specify and implement a fail-closed proxy result for every blocked protected
   path (id missing, non-tor decision, rejection). Keep the cancel listener as a
   second layer. Normalise trailing-dot/case variants when classifying onion
   destinations.
2. Fix unit tests that encode `null` as "blocked"; add regressions for each
   blocked path and for `x.onion.`.
3. Real-browser evidence extending the T157 harness: disable the cancel listener,
   show zero direct/ordinary-proxy/DNS captures for blocked `.onion` and
   `.onion.` requests, with calibrated positive controls. Record red (current
   null path leaks for `.onion.`) before green.
4. Update THREAT-MODEL's T157 note ("return no proxy descriptor") to state the
   actual Gecko semantics.

## Out-of-scope

Private-window access (T188); WebRTC re-audit (T190).
