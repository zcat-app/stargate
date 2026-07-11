---
id: T031
title: 'Contract test asserting no bridge / pluggable-transport strings appear'
status: done
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T031
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-011"   # Sidecar configuration; bridges absent
  - specs/001-tor-route/contracts/torrc.md §"Invariants" row 7   # UseBridges 0, no Bridge lines
  - specs/001-tor-route/contracts/torrc.md §"no_bridges_test.go"   # the 4 strings to sweep
decision_refs: []
constitution_refs:
  - "I: Dumb router"   # a stray Bridge line routes traffic outside the v1 threat model
  - "VII: Tests-first for privacy-critical paths"   # sidecar contract is privacy-critical
reviews: { round: 1, date: 2026-07-11, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T031: Contract test asserting no bridge / pluggable-transport strings appear

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test asserting no bridge / pluggable-transport strings appear anywhere in the rendered `torrc` in `tests/contract/torrc/no_bridges_test.go`.

## Analysis

The rendered v1 torrc golden (`wantTorrc` in `render_byte_match_test.go`) is
pinned byte-for-byte by T029; this ticket adds the focused, message-clear
bridge / pluggable-transport sweep the contract document names.

- **Must hold:**
  - The rendered v1 torrc contains no `Bridge` directive line and no
    pluggable-transport reference anywhere in the file — FR-011, contracts/
    torrc.md invariant #7 (a stray Bridge line routes traffic outside the v1
    threat model — Principle I).
  - The sweep spans the whole rendered output (comments included), not only
    parsed directives — defence-in-depth beyond T030's directive-map check,
    so a `# using snowflake` comment or a transport name smuggled into a
    directive argument fails loudly.
  - The sweep does NOT false-positive on `UseBridges 0`, which invariant #7
    REQUIRES: the substring "Bridge" legitimately appears inside
    "UseBridges". "Bridge" is therefore matched as a whitespace-delimited
    token, not a raw substring; the pluggable-transport names have no such
    collision and are matched as case-insensitive substrings.
- **Gated:**
  - T029's byte-match pins the exact rendered bytes; any added Bridge line
    changes bytes and trips T029 (reported as an opaque byte offset).
  - T030's `UseBridges_0_no_Bridge_lines` subtest asserts `UseBridges==0`
    and no `Bridge` key in the parsed directive map (directive-level; skips
    comments and directive-argument positions).
  - This test (T031) promotes the residue to gated with a named,
    bridge-specific failure message rather than T029's byte offset.
- **Residue:**
  - A `ClientTransportPlugin` directive that named none of {obfs4, snowflake,
    webtunnel} would slip past the enumerated sweep — but is unreachable in
    practice (a ClientTransportPlugin line must name its transport, and the
    three enumerated names are the only v1-relevant ones). Widening the sweep
    beyond the contract's four enumerated strings is intentionally NOT done
    here; it would be a contracts/torrc.md edit, not a test-only change. This
    is the coverage boundary the redteam pass should probe.

## Acceptance

- **Named test:** `TestNoBridgesOrPluggableTransports` in
  `tests/contract/torrc/no_bridges_test.go` is added and passes. It asserts,
  against the package-level `wantTorrc` golden, that:
  (a) the pluggable-transport names `obfs4`, `snowflake`, `webtunnel` appear
      nowhere (case-insensitive substring of the whole rendered torrc); and
  (b) no whitespace-delimited token equals `bridge` (case-insensitive) —
      catching a `Bridge ...` directive line without matching `UseBridges`.
- **Runnable command:** `cd tests/contract && go test ./torrc/` is green.
  (verify.sh does not yet run the tests/contract Go module — T076 wires it;
  per T029 §Analysis residue the torrc package is invoked manually today.)
- **Behavioral assertion:** mutating the golden to add `Bridge obfs4 1.2.3.4`
  or a `# snowflake` comment fails this test by name, while the existing
  `UseBridges 0` directive does not trip it.

## Out-of-scope

- The live-sidecar `GETCONF` assertion is T032.
- The Java `TorrcRenderer.render()` == golden link is T037's scope; this test
  pins only the Go golden (which T029 cross-checks against the contract doc).
- Widening the sweep beyond the contract's four enumerated strings
  (`Bridge`, `obfs4`, `snowflake`, `webtunnel`) — e.g. adding
  `ClientTransportPlugin` — is intentionally NOT done; the contract
  enumerates the set, and widening is a contracts/torrc.md edit, not a
  test-only change.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
