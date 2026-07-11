---
id: T087
title: 'Fix tor sidecar DataDirectory mismatch (HEALTHCHECK+ENTRYPOINT)'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#B2+M3
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T089]
parallel: true
files_budget: 7
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - spec.md §FR-014
  - spec.md §FR-011
  - contracts/torrc.md §"Invariants" row 11
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-07-11
  verdict: PASS
  discovered_by: T032
---

# T087: Fix tor sidecar DataDirectory mismatch (HEALTHCHECK+ENTRYPOINT)

## Context

Discovered by T032 at /start (recorded in T032 §Residue). The tor sidecar
image's ENTRYPOINT runs `tor -f /etc/tor/torrc` WITHOUT
`--defaults-torrc /etc/tor/torrc-defaults`, so Debian's defaults file
(which would set `DataDirectory /var/lib/tor`) is never loaded. Tor falls
back to its compile-time default of `$HOME/.tor` = `/var/lib/tor/.tor` for
USER tor (HOME=/var/lib/tor). The cookie lands at
`/var/lib/tor/.tor/control_auth_cookie`, not the
`/var/lib/tor/control_auth_cookie` that the Dockerfile HEALTHCHECK and
three documents assume.

## Impact

The Dockerfile HEALTHCHECK (sidecars/tor/Dockerfile:136) hardcodes
`/var/lib/tor/control_auth_cookie` and would therefore ALWAYS fail. Under
FR-014, a persistent UNHEALTHY verdict from the healthcheck drives
`routeEnableMask[TOR]` to DISABLED → ROUTE_DOWN for every Tor-routed
request. This breaks the entire Tor route at the healthcheck layer before
any data-plane forwarder (T047) or contract test (T058/T058a) can
exercise it.

THREE documents carry the now-known-wrong path:
- `sidecars/tor/Dockerfile:136` (HEALTHCHECK cookie path)
- `specs/001-tor-route/data-model.md:336` (cookie path in volume table)
- `specs/001-tor-route/contracts/torrc.md` invariant #11 comment ("default
  `/var/lib/tor` from the Debian package" — this is the torrc-defaults
  default, NOT the compile-time default that applies when torrc-defaults
  is not loaded)

## Acceptance

1. Write a cold-volume regression test first. Start the production Tor image
   without seeding config from the harness and assert Docker reports
   `State.Health.Status == healthy`.
2. Implement T089's amended contract: the image contains the byte-pinned safe
   `torrc` before entrypoint, including explicit
   `DataDirectory /var/lib/tor`; Tor does not wait for CP rendering.
3. Assert the loaded configuration contains every torrc contract invariant,
   the control cookie is exactly `/var/lib/tor/control_auth_cookie`, and the
   SOCKS/control ports remain compose-internal.
4. Update the Docker healthcheck to read the authoritative cookie path and
   perform the authenticated bootstrap probe.
5. Update `data-model.md`, `contracts/torrc.md`, T029/T030 goldens, and
   `SECURITY-DECISIONS.md` as required by T089; remove `find`-based test
   workarounds that could mask a path regression.
6. T032, the new cold-volume test, and `scripts/verify.sh` pass.

## Out-of-scope

- T062 (Go-side control-port client with cookie volume mount) — separate
  Phase 4 ticket.
- Any change to the IsolateSOCKSAuth / IsolateClientAddr directives
  themselves — those are invariant #1, untouched here.

## Notes

Filed by T032 round-1 review (stargate-codereview finding 2). The T032
test works around this via `find /var/lib/tor -name control_auth_cookie`
(robust to any DataDirectory), so T032 is not blocked by this defect.
T087 is `risk: medium` because it touches the tor image's ENTRYPOINT,
which is the highest-trust artefact in the stack (sidecars/tor/Dockerfile
header: "this front mounts the persisted onion signing key... its image
is the highest-trust artifact in the stack"). A redteam pass is
recommended before merge given `privacy_critical: true`.
