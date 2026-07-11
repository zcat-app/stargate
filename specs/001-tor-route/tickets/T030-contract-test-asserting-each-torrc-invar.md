---
id: T030
title: 'Contract test asserting each `torrc` invariant individually (rows 1–13'
status: done
created: 2026-07-04
last_updated: 2026-07-08
source: tasks.md#T030
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-011"
  - specs/001-tor-route/contracts/torrc.md §"Invariants"
  - specs/001-tor-route/contracts/torrc.md §"invariants_test.go"
decision_refs:
  - specs/001-tor-route/contracts/torrc.md §"When this contract changes"
constitution_refs:
  - "VII: Tests-first for privacy-critical paths"
reviews: { round: 2, date: 2026-07-08, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T030: Contract test asserting each `torrc` invariant individually (rows 1–13

## Context

Adds `tests/contract/torrc/invariants_test.go` — the per-row companion to
T029's whole-file byte-match gate. FR-011 (`spec.md §"Sidecar
configuration"`) pins the Tor sidecar's rendered `torrc` byte-for-byte
against `contracts/torrc.md §"Rendered file"`; that contract lists 13
invariants in its Invariants table. T029 catches any drift as an opaque
"first diverging byte at offset N"; this ticket breaks the 13 rows out as
named subtests so a missing or mutated directive reports by row. Per
`contracts/torrc.md §"invariants_test.go"`: "This test gives a clearer
diff message than the byte-match test when a directive is missing or
changed."

## Analysis

Property map per `docs/process/analysis.md`. `privacy_critical: true`
because the torrc directives are a Constitution-Principle-III surface
(stream isolation, no bridges, no per-user data in the rendered file).

- **Must hold**
  - Each of the 13 rows in `contracts/torrc.md §"Invariants"` is asserted
    by a named subtest, so a regression reports the row, not an opaque
    byte offset. (Constitution Principle VII — every privacy-load-bearing
    directive has a named assertion.)
  - The test consumes the already-pinned `wantTorrc` golden from T029
    (same package `torrc`) rather than re-transcribing or re-extracting
    from the contract document. T029 already gates doc ↔ golden
    byte-equality; a second transcription would be a third copy that could
    drift.
  - Privacy-load-bearing directives flagged in `contracts/torrc.md
    §"When this contract changes"` (rows 1, 5, 6, 7, 8, 12) each have an
    explicit, falsifiable assertion — not only the transitive byte-match.

- **Gated** (no standing vigilance needed — green verify.sh is the proof)
  - Whole-file drift between the contract document and `wantTorrc` is
    gated by `TestRenderedTorrcByteMatch` (T029).
  - SPDX header, `go vet`, compile errors → gated by verify.sh.
  - Control-plane `TorrcRenderer.render()` == golden → gated by T037's
    JUnit test (out of scope here; cross-plane split per T029 §Analysis).

- **Residue** (no gate catches — scopes the redteam pass)
  - *None introduced by this ticket.* No new code path, no new external
    input, no new state: the test asserts properties of an already-pinned
    in-memory constant. The change sits entirely inside the mechanical
    envelope; redteam scope is empty (procedural gate still fires because
    `privacy_critical: true`).

## Acceptance

1. **Named test added**: `tests/contract/torrc/invariants_test.go`, package
   `torrc`, SPDX header present, defines `TestTorrcInvariants` with one
   subtest per row of `contracts/torrc.md §"Invariants"` (rows 1–13).
2. **Row 1** subtest asserts the `SocksPort` line contains both
   `IsolateClientAddr` and `IsolateSOCKSAuth`.
3. **Row 2** subtest asserts the `SocksPort` line binds `0.0.0.0:9050`.
4. **Row 3** subtest asserts `ControlPort 0.0.0.0:9051` and
   `CookieAuthentication 1` are both present.
5. **Row 4** subtest asserts `CookieAuthFileGroupReadable 1` is present
   alongside `CookieAuthentication 1`.
6. **Row 5** subtest asserts `ClientUseIPv6 0`.
7. **Row 6** subtest asserts `AvoidDiskWrites 1`.
8. **Row 7** subtest asserts `UseBridges 0` AND no `Bridge` directive line.
9. **Row 8** subtest asserts `Log notice stdout` and `SafeLogging 1`.
10. **Row 9** subtest asserts NO `HiddenServiceDir` / `HiddenServicePort`
    directive lines.
11. **Row 10** subtest asserts NO `ExitPolicy` directive line.
12. **Row 11** subtest asserts NO `DataDirectory` directive line.
13. **Row 12** subtest asserts no comment line contains per-user-data
    patterns (email, bare IP literal, domain TLD, `token`/`label`/`user=`
    keys).
14. **Row 13** subtest asserts the file ends with exactly one trailing LF
    and contains no CR anywhere.
15. The subtests consume the package-level `wantTorrc` golden from T029 —
    no second transcription of the template.
16. **Runnable command**: `cd tests/contract && go test ./torrc/` is green
    (both this test and T029's byte-match), and `scripts/verify.sh` is
    green.

## Out-of-scope

- The control-plane renderer output gate (`TorrcRenderer.render()` ==
  golden) is T037's JUnit scope; the cross-plane split is documented in
  T029 §Analysis and `contracts/torrc.md §"render_byte_match_test.go"`.
- The standalone `no_bridges_test.go` substring sweep (`Bridge`, `obfs4`,
  `snowflake`, `webtunnel`) is T031; this ticket asserts row 7 (`UseBridges
  0` + no `Bridge` directive) inline, scoped to the contract's row 7
  wording.
- The live-sidecar GETCONF assertion is T032; the IsolateSOCKSAuth
  *effect* test is the contract's `isolate_socks_auth_effect_test.go`
  (un-ticketed here, sibling to T032).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
