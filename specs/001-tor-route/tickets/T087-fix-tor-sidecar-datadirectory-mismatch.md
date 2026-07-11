---
id: T087
title: 'Fix tor sidecar DataDirectory mismatch (HEALTHCHECK+ENTRYPOINT)'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: follow-up-from-T032
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: true
files_budget: 4
privacy_critical: true
complexity: low
risk: medium
round_cap: 2
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

Pick ONE of the two resolution paths below (the choice is a design
decision for this ticket's /start; both are viable):

### Path A: Load torrc-defaults (preferred)

Amend `sidecars/tor/Dockerfile`'s ENTRYPOINT to pass
`--defaults-torrc /etc/tor/torrc-defaults`:

```
ENTRYPOINT ["tor", "--defaults-torrc", "/etc/tor/torrc-defaults", "-f", "/etc/tor/torrc"]
```

This makes the Debian package's intended defaults (including
`DataDirectory /var/lib/tor`) take effect, so the cookie lands at the
contract-assumed path and the HEALTHCHECK works as written.

CAVEAT: the `stargate-tor-config` named volume is seeded by the control
plane (T037) or by the T032 test harness. If the volume is seeded from
empty (bypassing Docker's image-content initialization),
`/etc/tor/torrc-defaults` may be absent from the volume and tor will fail
to start. Verify that the volume initialization path (compose auto-create
+ image-content copy) reliably populates `torrc-defaults`, or seed it
alongside `torrc` in the control-plane renderer (T037) and the T032 test
harness.

### Path B: Explicit DataDirectory in the rendered torrc

Add `DataDirectory /var/lib/tor` to the rendered torrc (contracts/torrc.md
§"Rendered file") and update invariant #11 to reflect the explicit
directive. This is a contract change — it amends the byte-match golden
(T029's `wantTorrc`), T030's parsed-directive invariants, and requires a
`SECURITY-DECISIONS.md` entry per contracts/torrc.md §"When this contract
changes" (invariant #11 is not in the privacy-load-bearing set rows
1/5/6/7/8/12, but the change should still be recorded).

### Either path

- Amend the Dockerfile HEALTHCHECK cookie path if it remains stale after
  the resolution (Path A makes it correct; Path B does too if the cookie
  lands at `/var/lib/tor/control_auth_cookie`).
- Amend `data-model.md:336` to match the actual cookie path.
- Amend `contracts/torrc.md` invariant #11's comment to match the actual
  default.
- Verify T032 still passes after the fix (the `find`-based cookie
  discovery in T032's `liveTorControl` is robust to either path and
  should not need changes; if it does, tighten it to assert the specific
  path the fix produces).

## Out-of-scope

- T062 (Go-side control-port client with cookie volume mount) — separate
  Phase 4 ticket; once it lands, T032 and T058/T058a can read the cookie
  directly rather than via `docker exec`.
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
