---
id: T047
title: 'Implement `data-plane/internal/forward/tor.go`'
status: pending
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T047
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true   # /start 2026-09-03: verified — forwards auth-passed bytes + target metadata on the routing hot path (Principle VII routing surface); matches sibling T042/T043/T044/T045/T046
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md FR-007 (forward verbatim, SOCKS5h, no local resolution)
  - specs/001-tor-route/contracts/socks5-auth.md §"Username/password sub-negotiation" step 1 (UNAME verbatim upstream)
  - specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" (REP mapping; BND always zeroed)
  - specs/001-tor-route/contracts/socks5-auth.md §"Deadlines" (30 s dial+handshake only; none post-handshake)
  - .specify/memory/constitution.md Principle I (dumb router; fixed startup binding)
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T047: Implement `data-plane/internal/forward/tor.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/forward/tor.go` — port-8881-to-Tor binding fixed at process startup (Principle I); SOCKS5h dial to `tor:9050` via `golang.org/x/net/proxy`; pass SOCKS5 `UNAME` through verbatim as the upstream SOCKS5 username; never resolve target hostnames locally (FR-007). Verified by T032, T033.

## Analysis

Quick pass (complexity: low). This file IS the privacy hot path — every
auth-passed byte and the target metadata traverse it — so the full
property map follows (`privacy_critical: true`).

Seam obligations (from the landed T042/T043 surfaces — read, verified on
disk): `listener.Forwarder` (`Forward(client, uname, target) error`),
`listener.Tunneler` (`Dial(target)` + `Pipe(client, upstream)`), and
`listener.RouteError` (`error` + `SOCKS5Reply() byte`, consumed via
`errors.As` by both listeners). This package implements all three;
compile-time assertions pin the conformance.

- **Property map**
  - Upstream fixed at startup (Principle I; FR-005's port-8881→Tor
    binding): the sidecar address is a constructor field (`New("tor:9050")`
    — T050 wires it); zero per-request upstream/route selection.
    → Gated by: every unit test dials the constructor-fixed address.
  - SOCKS5h — the target goes upstream as ATYP=0x03 FQDN, never
    resolved locally (FR-007, Principle III). Verified in the pinned
    `golang.org/x/net` v0.54.0 client source (`internal/socks` sends
    `AddrTypeFQDN` when `net.ParseIP(host)` fails; it performs no
    resolution). → Gated by: unit test asserting ATYP=0x03 + a
    `.invalid` target completing end-to-end (a resolving implementation
    fails it).
  - UNAME passes through verbatim as the upstream SOCKS5 username
    (contracts step 1; US2's `IsolateSOCKSAuth` key). Password field
    empty (PLEN=0): FR-007 names ONLY the username as passthrough — the
    bearer token (inbound PASSWD) is auth-layer material and is never
    re-sent upstream. → Gated by: byte-equality assert at a recording
    fake upstream.
  - Route classification (`RouteError`): ROUTE_DOWN→0x03 (no TCP to the
    sidecar), ROUTE_TIMEOUT→0x06 (the 30 s dial+handshake deadline:
    ctx/net timeouts), ROUTE_REFUSED→0x04 (sidecar alive but refused:
    non-zero BND REP, auth rejection). **Documented coupling**: x/net
    v0.54.0 has no typed upstream-refusal error — it wraps non-zero BND
    REPs as `net.OpError` around `errors.New("unknown error …")`
    (auth rejection: `"username/password authentication failed"`), so
    REFUSED classification keys on that wrapper. go.mod pins the module;
    the unit test drives the real client against the real bytes, so an
    upgrade that changes the surface fails the test, not production.
    → Gated by: three classification unit tests through the actual
    x/net client.
  - Inbound success reply is THIS package's job (the listener writes
    only failures — socks5.go:209): exactly `05 00 00 01 00×6` after the
    upstream handshake, before any tunnel byte; BND zeroed — never echo
    the upstream's BND (destination-metadata hygiene, Principle III).
    → Gated by: exact-10-byte assert preceding the first echo byte.
  - Byte pipe (Principle I): no idle deadline post-handshake (§Deadlines
    row 2; T025b); Forward/Pipe close ONLY the upstream conn — never the
    client's; post-establishment pipe errors return nil so no failure
    reply is ever injected into an established tunnel (T070a surface).
    → Gated by: teardown test asserting nil return + client conn left
    unclosed.
  - CONNECT path carries no username: `Dial` offers NO_AUTH only (nil
    auth). Offering user/pass with an empty user isn't just wrong for
    isolation, x/net rejects it outright (`invalid username/password`).
    Isolation is SOCKS5-framed (US2) — the no-username circuit share is
    pinned as by-design at T058a. → Gated by: Dial test asserting
    NO_AUTH selection, no sub-negotiation.
  - FR-008: nothing is logged and no target/UNAME/token material
    reaches any response — errors carry only the classification code;
    the failure-reply bytes are the listeners' (already landed).
    → Gated by: code inspection (no log/slog import); leak surface is
    the landed T025/T064 suites.
- **Residue (no unit gate catches)** — carried, not closed here:
  - Real Tor's method-selection preference when the greeting offers
    `[NO_AUTH, USERPASS]` (does the username actually transmit?) and
    its acceptance of PLEN=0 passwords — invisible to the unit layer;
    pinned against the live sidecar by T058/T058a (US2), live smoke by
    T032/T033.
  - DOWN vs REFUSED boundary under real network conditions — T067a
    drives it at the contract layer.

## Acceptance

In-package suite `data-plane/internal/forward/tor_test.go` (tests-first
per Principle VII — written and failing before tor.go lands), each test
driving the real `golang.org/x/net` client against a minimal in-test
SOCKS5 upstream stub:

- `TestForwardWritesZeroedSuccessReplyAndBridges` — exact
  `05 00 00 01 00 00 00 00 00 00` arrives before any tunnel byte;
  bidirectional frames relay until either end closes; `Forward` returns
  nil after teardown (no post-tunnel failure bytes) and the client conn
  is not closed by the forwarder.
- `TestForwardPassesUNAMEVerbatimAsUpstreamUsername` — the stub records
  the greeting (offers method 0x02) and the RFC 1929 sub-negotiation:
  UNAME byte-identical, PLEN=0.
- `TestForwardSendsDomainTargetUnresolved` — request phase carries
  ATYP=0x03 with the name verbatim; a `*.invalid` target (RFC 6761 —
  unresolvable by construction) still completes a round trip, so any
  local resolution fails the test.
- `TestForwardUnreachableUpstreamIsRouteDown` — closed loopback port →
  error with `SOCKS5Reply() == 0x03`.
- `TestForwardUpstreamRefusalIsRouteRefused` — stub answers the
  handshake then BND REP=0x05 → error with `SOCKS5Reply() == 0x04`
  (pins the x/net wrapper-string coupling named in §Analysis).
- `TestForwardDialDeadlineIsRouteTimeout` — short injected deadline,
  greeting-silent stub → error with `SOCKS5Reply() == 0x06`; the
  production constant stays 30 s (§Deadlines row 1).
- `TestDialNoUsernameOffersNoAuthAndBridges` — CONNECT path: stub
  observes NO_AUTH selected and no sub-negotiation; `Dial` returns the
  bridged upstream; `Pipe` relays and returns nil without closing the
  client conn.
- `scripts/verify.sh` green from repo root.

## Out-of-scope

- Boot wiring — T050 constructs `New("tor:9050")` once and fills
  `listener.Deps.Forward` + `ConnectDeps.Tunnel` (fixed-at-startup
  policy lives there).
- Failure-response shapes and counter asymmetry (ROUTE_REFUSED
  errortpl wiring, inbound-protocol-appropriate replies): T071/T072.
  This ticket ships the three-way classification; T072 refines the
  upstream-REP mapping fidelity if the live sidecar demands it.
- Live-Tor verification: T032 (sidecar spin-up), T033 (full vertical);
  real-Tor method-preference / PLEN=0 pins: T058/T058a (US2).
- Listener changes — T042/T043 surfaces are stable; `RouteError` stays
  defined in `listener` and is satisfied structurally (compile-time
  assertions live in this package).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
