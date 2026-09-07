---
id: T058
title: 'Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T058
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062]   # manual edge: task body consumes T062's control-port helper (derive-deps missed prose deps; tightened 2026-09-07)
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - spec.md §"User Story 2" acceptance scenario 1 (two SOCKS5 CONNECTs with distinct usernames → distinct circuit IDs at the control port)
  - spec.md §FR-011 (SocksPort carries IsolateSOCKSAuth — the directive whose runtime effect this test pins)
  - spec.md §FR-012 (SocksPort 9050 compose-internal only; no host publication to manufacture)
  - spec.md §FR-016 (control-port access cookie-authenticated, via the T062 helper)
  - contracts/torrc.md §"isolate_socks_auth_effect_test.go" (this test's contract sheet)
  - contracts/torrc.md §"Invariants" #1 (IsolateSOCKSAuth — privacy-load-bearing) and #3 (ControlPort 9051)
  - tasks.md#T058
decision_refs:
  - contracts/torrc.md §"live_sidecar_test.go" + tests/contract/torrc/live_sidecar_test.go (T032/T087): live-sidecar bring-up precedent — compose project namespacing, cold image-baked torrc, build-tag `docker` cadence, pre-registered cleanup
  - tests/contract/tor/control_port.go (T062): the consumed helper — ReadCookie/Connect/Authenticate/Command/ControlPortConfig; library code importable from the torrc package
  - tests/contract/tor/control_port_live_test.go (T062): live poll shapes — cookie read + connect + AUTHENTICATE poll, bootstrap PROGRESS=100 poll, BUILT-circuit grace
  - contracts/socks5-auth.md §"Username/password sub-negotiation": UNAME is the first-party domain, NOT a credential — opaque isolation key passed through verbatim
  - docs/process/analysis.md (privacy_critical property-map gate)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T058: Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.go` — spins up the Tor sidecar with the rendered config, issues two SOCKS5 CONNECTs with distinct usernames, queries the control port for `circuit-status`, asserts the two streams attached to distinct circuit IDs. (`contracts/torrc.md` §"isolate_socks_auth_effect_test.go".)

## Analysis

- **Must hold:**
  - The live tor sidecar, booted cold with the image-baked torrc, puts two
    SOCKS5 streams that differ **only** in their username/password auth
    identity onto **distinct** circuits — the runtime effect of invariant #1's
    `IsolateSOCKSAuth` (spec US2 scenario 1's control-port assertion;
    Principle III per-first-party stream isolation).
  - Auth identity is the ONLY variable: both CONNECTs hit the same target
    from the same client address, so circuit distinctness is attributable to
    `IsolateSOCKSAuth` alone — with the flag dropped, tor's default shares one
    circuit across both streams and this test fails (torrc.md's "fails
    immediately" clause).
  - Circuit IDs are read through the cookie-authenticated control port via
    T062's helper (`tests/contract/tor/control_port.go`), never from tor log
    lines (torrc.md #8: Stargate does not consume Tor logs as data).
  - Both transports stay compose-internal (FR-012): SOCKS via in-container
    `nc 127.0.0.1 9050` (two argv words — T062's live lesson), control via the
    helper's exec/nc transport. No host publication is manufactured; the only
    egress is the sidecar's own, toward the spec-pinned reference onion.
  - Harness plumbing must not leak the cookie: errors carry sizes/paths/
    statuses, never hex (T062 §Analysis M5 conventions, inherited by
    construction from the helper).
- **Gated:**
  - Static torrc byte shape: T029 byte-match + T030 invariants + T031
    no-bridges (hermetic, this package).
  - "Tor loaded the directive": T032's live GETCONF gate (this package,
    `docker` tag).
  - Control-port client correctness: T062's hermetic parser suite (PR gate)
    and live self-test (`docker` tag).
  - verify.sh compile-checks this file via `go vet -tags docker` and accounts
    it SKIP[docker] in the hermetic PR run (T076 cadence split); license
    header gate covers the SPDX header.
- **Residue:**
  - "IsolateSOCKSAuth has its EFFECT (distinct auth identity → distinct
    circuit), not just presence in the loaded config" — no gate caught this
    before this ticket; this test IS the promotion into the gated set
    (`docker` cadence).
  - Through-the-data-plane variant (port 8881, UNAME passthrough end-to-end)
    stays open — T059. Same-origin intentional sharing (scenario 3) — T060.
    10-onion ≥9-distinct scale (scenario 2, SC-002) — T061. NO_AUTH
    no-username default-circuit pin — T058a. None belong in this ticket.
  - Environmental residue: bootstrap + onion rendezvous need the live Tor
    network; a network partition fails at the named deadlines (environmental,
    not a code regression). Mitigated by the `docker` build-tag cadence —
    never a hermetic-PR flake surface.

## Acceptance

1. `tests/contract/torrc/isolate_socks_auth_effect_test.go` exists, is
   `//go:build docker` tagged (live cadence — T076), `package torrc`, and
   defines `TestIsolateSOCKSAuthDistinctCircuits` with skip guards mirroring
   T062/T032 (docker CLI absent / daemon unreachable), its own compose project
   (`stargate-t058-test`), pre-registered `down --volumes --remove-orphans`
   cleanup, and `up -d --build tor` (cold volume, image-baked torrc — T087
   posture).
2. Named test, behavioral assertions (subtests):
   - `SidecarBootstraps`: cookie read from the authoritative path + control
     session authenticates (T062 helper) and `GETINFO
     status/bootstrap-phase` reaches `PROGRESS=100` within the deadline.
   - `FirstStreamAttaches`: raw SOCKS5 over an in-container `nc 127.0.0.1
     9050` exec pipe — greeting offers userpass (0x02), UNAME = first
     first-party domain string, CONNECT (ATYP=0x03) to the spec-pinned
     reference onion `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443`
     → reply rep 0x00. `GETINFO stream-status` then shows exactly one
     SUCCEEDED stream for that target; record (streamID → circuitID).
   - `SecondStreamDistinctUsernameAttaches`: same target, second distinct
     UNAME → rep 0x00; the new stream (streamID set-difference) maps to its
     circuit ID.
   - `CircuitsAreDistinct`: the two circuit IDs differ AND both appear as
     entries in `GETINFO circuit-status` — the literal control-port query the
     contract names. A shared circuit ID fails the test (the
     dropped-`IsolateSOCKSAuth` regression).
3. Runnable command: `cd tests/contract && go test -tags docker ./torrc/
   -run TestIsolateSOCKSAuth -v -timeout 20m` (manual), or
   `STARGATE_TEST_TAGS=docker scripts/verify.sh` (named Docker job). Hermetic
   gate stays green: `bash scripts/verify.sh` (compile-checks the file via
   `go vet -tags docker`, accounts SKIP[docker]).

## Out-of-scope

- Through-port-8881 integration variant → T059. Same-origin sharing
  (scenario 3) → T060. 10-onion scale (scenario 2 / SC-002) → T061.
  NO_AUTH no-username companion → T058a.
- No changes to the torrc golden or the contract document (T029/T030/T031 own
  those), to the control-port helper (T062 owns it — consumed as-is via its
  public API), or to compose files (the tor service is used as-is).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

Design note (grounding, 2026-09-07): both CONNECTs intentionally target the
SAME destination (the spec-pinned reference onion) with distinct usernames —
the sharpest probe of `IsolateSOCKSAuth`: tor's default shares one circuit
across streams regardless of destination, so same-target + distinct-username
+ distinct-circuit proves the auth-isolation flag did the isolating.
Scenario 1's two-distinct-destinations variant through port 8881 is T059's
end-to-end scope; the contract sheet for THIS test (torrc.md
§"isolate_socks_auth_effect_test.go") pins only "two SOCKS5 CONNECTs with
distinct username". Usernames are opaque isolation keys (socks5-auth.md:
UNAME is the first-party domain, NOT a credential); stream-correlation uses
the streamID set-difference across the two handshakes because both streams
share one target string.
