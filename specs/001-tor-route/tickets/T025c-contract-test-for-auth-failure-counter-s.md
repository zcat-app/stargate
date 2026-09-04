---
id: T025c
title: 'Contract test for auth-failure counter side-channel resistance (FR-006'
status: in-review
created: 2026-07-04
last_updated: 2026-09-04
source: tasks.md#T025c
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T049]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-006" (auth-failure response shapes; MUST authenticate every inbound request)
  - specs/001-tor-route/spec.md §"FR-008" ("auth failures leave the counter unchanged" — Principle III side-channel rule)
  - specs/001-tor-route/data-model.md §3 (aggregate counters: auth failures NOT counted; synthesised AUTH_REQUIRED body excluded from byte_count)
  - specs/001-tor-route/contracts/control-grpc.md §"GetStatus (minimum subset)" (the read surface; no-side-effect row + Tests row 1/4 naming this file)
  - specs/001-tor-route/contracts/socks5-auth.md §"Auth failure response" / §"HTTP CONNECT path" (the two failure framings the burst drives)
  - .specify/memory/constitution.md Principle III (counting failures = token-guessing side channel) + Principle VII (tests-first)
decision_refs:
  - specs/001-tor-route/research.md §11 (v1 GetStatus caller is the contract-test harness only)
  - specs/001-tor-route/plan.md §"Plan-level tensions surfaced for review" #10 (GetStatus ships in v1 proto rationale)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T025c: Contract test for auth-failure counter side-channel resistance (FR-006

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for auth-failure counter side-channel resistance (FR-006, FR-008; data-model.md §3 — "auth failures leave `request_count` unchanged"; counting them would be a side channel for token-guessing attacks since an attacker can submit tokens at will). Establish a baseline `request_count` snapshot for `route='TOR'` via a direct gRPC probe to the data plane's status surface (arch §5.2 `GetStatus`, used here as a test-only probe; this is why the test lives next to the SOCKS5 leak tests rather than under `tests/contract/control-grpc/` — the property under test is at the SOCKS5/auth boundary, not the inter-plane RPC contract). Send N=100 SOCKS5 CONNECTs and N=100 HTTP CONNECTs with malformed bearer tokens to port 8881 — mix of: missing password, all-zero token, wrong-length token, correct-length token absent from current generation. Take a second snapshot. Assert (a) `request_count` delta is exactly zero; (b) `byte_count` delta is exactly zero (the synthesised AUTH_REQUIRED template body is excluded by data-model.md §3); (c) the gRPC probe itself does not increment any counter — verified by a no-traffic sandwich: snapshot, sleep ≥1s, snapshot again, assert no change. File: `tests/contract/socks5/auth_failure_counter_test.go`. Pairs with T049's implementation; T025 gates the log/journal side channel and T025c gates the counter side channel — both must hold or the auth-failure path leaks.

## Analysis

*(Grounded 2026-09-04 against FR-006/FR-008, data-model.md §3,
contracts/control-grpc.md §"GetStatus (minimum subset)", and the landed
DP seams: listener socks5.go/connect.go, auth/token.go,
controlclient/server.go, audit/counters.go.)*

**Ground truth on disk.** Everything the test probes already exists:
the DP hosts `GetStatus` on dp.sock through the §5.3 interceptor chain
(`controlclient.Server.GetStatus` → `audit.Counters.Snapshot()`, which
increments nothing); the auth-failure paths short-circuit BEFORE the
upstream dial on both framings (socks5.go: `01 FF` + close, PLEN=0
included; connect.go: 407 + AUTH_REQUIRED template + close), so the
burst needs no upstream sidecar and no fake CP (T028 precedent).
`cmd/stargate-proxy/main.go` (T050) has NOT landed — `dpharness.Start`
self-skips until it does, so this ticket lands tests-first (Principle
VII) and the test self-lifts at T050.

**Known residue inherited, not owned here.** The shared
`dpharness.ReloadErr` dial carries no §5.3 `x-stargate-proto-*`
metadata, which the landed server interceptor rejects — recorded in
T020a's Notes as residue folded into T022/T050. This test's precondition
(`ReloadTokens` → APPLY_STATUS_OK) rides that shared helper and inherits
the residue; this ticket does NOT fix the shared helper (surgical scope).
The NEW probe surface this ticket adds to the harness (`Status`/`StatusErr`
for GetStatus) attaches the metadata correctly from day one (wireprobe
precedent), because a metadata-less GetStatus is pinned to reject
(wireprobe `nomajor` mode).

- **Must hold:**
  - 200 auth-failure attempts (100 SOCKS5 CONNECT + 100 HTTP CONNECT,
    25 each per framing of: missing password/header, all-zero token,
    wrong-length token, correct-length token absent from the loaded
    generation) leave `request_count` delta EXACTLY zero across the
    whole snapshot (FR-008; data-model.md §3; Principle III side-channel
    rule). The count fires only post-auth (listeners' `AuthPassedRequest`
    call sites), so no failure framing can reach it.
  - `byte_count` delta EXACTLY zero: the synthesised AUTH_REQUIRED
    template body (HTTP path) and the `01 FF` reply (SOCKS5 path) never
    contribute (data-model.md §3 — only client↔upstream forwarded bytes
    count; a failure path dials no upstream, so 0 is the only consistent
    value).
  - `GetStatus` is side-effect-free: snapshot → ≥1 s idle (no port-8881
    traffic) → snapshot → responses identical (contracts/control-grpc.md
    §"GetStatus (minimum subset)" no-side-effect row, Tests row 4).
  - Full-snapshot identity across the burst (proto.Equal of before/after
    `StatusResponse`): no row appears, disappears, or changes — stricter
    than the per-column sums, and robust to hour-boundary rollover
    (nothing increments, so no adjacent row can be born mid-test).
  - Per-attempt precondition: every attempt actually fails auth (SOCKS5
    `01 FF` + close; HTTP `407` status line) — an unexpected success
    masks the counter assertions, so it fails fast with the mode+iteration
    named (T025a precondition-failure precedent).
  - The loaded generation holds one valid 32-hex token (FR-017 format
    gate; T020a r1 follow-up note) so "correct-length token absent from
    current generation" is a near-miss against realistic state.
  - The test performs no journal assertions — the failure-path journal
    surface is T025's scope; this ticket gates only the counter channel
    (the two gates together close the auth-failure leak family).
- **Gated:**
  - `go vet` + `staticcheck` (test file compiles clean) + license-header
    check via scripts/verify.sh.
  - The named test itself (`TestAuthFailureCounterSideChannelResistance`)
    becomes the standing PR-cadence gate for the counter side channel
    once T050 lifts the harness boot gate; dpharness.Start's boot-minimum
    gate (T042/T045/T050) makes the skip/FAIL transition fail-closed.
  - Per-attempt auth-failure shape asserts pin the burst's premise
    (precondition integrity) — each one re-asserts the T028/T027 failure
    shapes as a side effect.
- **Residue:**
  - Until T050 lands, the gate runs as SKIP — a broken counter contract
    is invisible to verify.sh in that window (accepted repo-wide
    tests-first posture; the skip self-lifts and the same gate then
    fails closed).
  - The harness `ReloadErr` metadata residue (above) is inherited: if
    T022/T050 do not fold the fix in, this test's precondition fails
    loudly at first real run — fail-closed, not silent.
  - Timing channel *within* the allowed constant-time comparison loop
    (e.g. generation-size-dependent total auth latency across the 200
    attempts) is NOT gated here — Principle III gates the counter
    channel only; comparison-loop timing is FR-006's
    `crypto/subtle.ConstantTimeCompare` clause, unit-pinned in T044.

## Acceptance

1. **Named test — `TestAuthFailureCounterSideChannelResistance`**
   (`tests/contract/socks5/auth_failure_counter_test.go`): one DP boot
   (dpharness.Start; no upstream, no fake CP — T028 fixture shape), one
   `ReloadTokens` of generation 1 with a single 32-hex verifier
   (APPLY_STATUS_OK asserted), then:
   - baseline `GetStatus` probe via the new `dpharness.Status`;
   - no-traffic sandwich: probe → sleep ≥1.1 s → probe → responses
     proto.Equal (assertion (c): the probe increments nothing);
   - the 200-attempt malformed burst (100 SOCKS5 + 100 HTTP, cycling the
     four malformation modes per framing), each attempt asserted to fail
     auth in its framing's shape;
   - post-burst probe after a 250 ms quiesce: `request_count` delta
     exactly 0 (assertion (a)), `byte_count` delta exactly 0 —
     synthesised AUTH_REQUIRED body excluded (assertion (b)), and the
     full `StatusResponse` proto.Equal to the baseline.
2. **Named helper — `dpharness.Status`/`StatusErr`**
   (`tests/contract/internal/dpharness/status.go`): GetStatus probe over
   `unix://` + dp.sock carrying the §5.3 metadata keys
   (`x-stargate-proto-major: 1`, `-minor: 0`, capabilities) per the
   wireprobe pattern; shared canonical location so T025d/T067b probe
   through the same seam rather than re-dialing ad hoc.
3. **Behavioral assertion**: the four malformation modes are all
   exercised per framing (missing password / all-zero / wrong-length /
   correct-length-absent), 25 attempts each per framing, so no
   special-cased failure mode can silently increment.
4. **Runnable command**: `go test ./socks5/ -run
   TestAuthFailureCounterSideChannelResistance -v` from
   `tests/contract/` (SKIPs until T050; FAIL, not SKIP, once lifted and
   the counter contract breaks), and `scripts/verify.sh` green from the
   repo root.

## Out-of-scope

- **The 407 template's byte shape / body content** (HTTP auth-failure
  response surface) — T027's scope; this test asserts only the `407`
  status line as its per-attempt precondition.
- **Cross-case `01 FF` byte-identity** across AUTH_REQUIRED cases —
  T028's scope; this test asserts the per-attempt failure shape only.
- **Positive increments** (auth-pass: request_count/byte_count deltas) —
  T025d. **Route-failure post-auth increments** — T067b. Together with
  this ticket they close all three angles of the FR-008 counter contract.
- **Journal/log leakage of the auth-failure path** — T025's scope (its
  near-miss-password case); no journal assertions here.
- **Fixing the shared `dpharness.ReloadErr` §5.3 metadata gap** —
  recorded residue owned by T022/T050 (T020a Notes); this ticket only
  documents the inheritance and makes its own new probe correct.
- **Comparison-loop timing channels** across the generation — FR-006's
  constant-time clause, pinned at T044 unit altitude; not a counter
  side channel.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
