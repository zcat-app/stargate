---
id: T186
title: 'Fail closed in proxy.onRequest for blocked protected requests'
status: in-progress
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 2 M1, survived falsification, sharpened)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 8   # router.js + router.test.js + THREAT-MODEL.md + live-e2e probe.py + live-e2e README.md + this ticket + STATUS.md regen + evidence/T186-tests-first.json (5 -> 8 maintainer-authorised 2026-09-29)
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

## Notes

Maintainer decisions (2026-09-29, maintainer-authorised, relayed by the orchestrator):

1. `files_budget` raised 5 -> 8 to cover the eight paths in the frontmatter comment,
   including the live-e2e harness README whose "no SOCKS descriptor" wording this ticket
   makes stale.
2. Fail-closed descriptor: the developer's proposal (Stargate DP port plus invalid
   credential) is rejected: while the DP is down, whatever binds that port can receive
   the onion name. Chosen order: (a) D5, a SOCKS descriptor over a Unix domain socket at a
   path nobody can listen on (e.g. `/dev/null/x`), if Mullvad Browser's `proxy.onRequest`
   supports it; otherwise (b) D4, an `https`-type descriptor to `127.0.0.1` on an unused
   privileged port (CONNECT only after TLS validation an impostor cannot pass; an
   IP-literal proxy host puts no hostname in the TLS hello). Before implementing, a
   real-browser feasibility run (host Mullvad Browser, disposable profile, cancel listener
   disabled) must establish D5 support/fail-closed, zero destination bytes at plain-TCP and
   self-signed-TLS impostors on the D4 target, no DIRECT/failover after proxy failure, no
   destination names in the DNS capture, and record whether a fake SOCKS listener on the
   D1-style port receives the name. If neither D5 nor D4 passes, stop and return.
