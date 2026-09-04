---
id: T025d
title: 'Contract test for **positive** counter increments on the auth-passed f'
status: in-progress
created: 2026-07-04
last_updated: 2026-09-04
source: tasks.md#T025d
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
  - specs/001-tor-route/spec.md §"FR-008" (first half: only auth-passing requests increment `request_count`; only client↔upstream forwarded bytes count)
  - specs/001-tor-route/data-model.md §3 (aggregate counters: per-column update rules; `hour_bucket` = unix-hour at increment time; synthesised error-template body excluded from `byte_count`)
  - specs/001-tor-route/contracts/control-grpc.md §"GetStatus (minimum subset)" (the read surface; Tests row 2 names this file and the 100-CONNECT / `2B` shape; no-side-effect row)
  - specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 path (RFC 1928 + 1929)" / §"HTTP CONNECT path" (the two authenticated framings the burst drives)
  - .specify/memory/constitution.md Principle I (dumb router: a happy-path tunnel carries no DP-synthesised bytes) + Principle III (counter is aggregate-only) + Principle VII (tests-first)
decision_refs:
  - specs/001-tor-route/research.md §11 (v1 `GetStatus` caller is the contract-test harness only)
  - specs/001-tor-route/plan.md §"Plan-level tensions surfaced for review" #10 (`GetStatus` ships in v1 proto rationale)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T025d: Contract test for **positive** counter increments on the auth-passed f

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for **positive** counter increments on the auth-passed forwarding path (FR-008 first half; data-model.md §3 — "`request_count` incremented by 1 on each SOCKS5 or HTTP CONNECT through port 8881 that passes authentication" and "`byte_count` incremented by the total bytes forwarded between client and upstream in both directions at request close"). Uses the same in-feature DP-hosted `GetStatus` RPC from T007 / T045 that T025c uses, on the same `/run/stargate/dp.sock`. Establish a baseline `(route='TOR', hour_bucket)` snapshot. Open N=50 authenticated SOCKS5 CONNECTs and N=50 authenticated HTTP CONNECTs to port 8881 against the `accept-and-relay` mode of `fake_socks5_tor.go` (T019a); for each connection, forward a known payload of exactly `B` bytes in each direction (`2B` bytes round-trip per connection) and then close cleanly. Take a second snapshot. Assert (a) `request_count` delta equals exactly 100; (b) `byte_count` delta equals exactly `100 × 2B` — the synthesised error-template body is excluded by data-model.md §3, but this test never triggers an error so the exclusion is degenerate (asserted for completeness via a side-channel that captures any DP-emitted template bytes and confirms the captured byte count is zero); (c) the `hour_bucket` key matches the wall-clock hour at the time of the run, with an allowance to sum two adjacent rows if the run crosses an hour boundary; (d) the T025a shared log allowlist applies — counter writes emit no per-request log line. File: `tests/contract/socks5/auth_passed_counter_test.go`. Pairs with T049's implementation; together with T025c (must-not-increment on auth-fail) and T067b (must-increment on auth-pass + route-failure), this task gates the FR-008 counter contract from all three angles — see T067b for the complete three-test mapping. Rationale for the v1-proto `GetStatus` declaration that makes this test possible is in plan.md §"Plan-level tensions surfaced for review" #10 / research.md §11.

## Analysis

*(Grounded 2026-09-04 against FR-008, data-model.md §3,
contracts/control-grpc.md §"GetStatus (minimum subset)" Tests row 2, and
the landed DP seams: listener socks5.go/connect.go, auth/token.go,
forward/tor.go, audit/counters.go, controlclient/server.go +
dpharness status.go — the probe seam T025c added and this test shares.)*

**Ground truth on disk.** The full happy-path chain this test drives
exists: port-8881 demux → RFC 1929 / HTTP CONNECT bearer auth (T044) →
`forward/tor.go` dialing `STARGATE_TOR_SOCKS_ADDR` (T047's test-defined
override) → the counting conn wrapping the upstream (which feeds
`audit.Counters.AddForwardedBytes` once at request close) → `GetStatus`
serving `audit.Counters.Snapshot()` on dp.sock. The T019a fake upstream
in `AcceptAndRelay` mode echoes every byte, so writing exactly B and
reading exactly B back per connection books exactly 2B through the DP
(counting conn sees B client→upstream + B upstream→client). The
`dpharness.Status` probe (T025c) already carries the §5.3 metadata the
server interceptor requires.
`cmd/stargate-proxy/main.go` (T050) has NOT landed — `dpharness.Start`
self-skips until it does, so this ticket lands tests-first (Principle
VII) and the test self-lifts at T050 (same posture as T025a/b/c).

**Fixture choices.** Fake CP + single HEALTHY push before the snapshot
window (T025a precedent) keeps control-channel retry noise out of the
journal delta that assertion (d) scans. B is fixed at 4096 (the task
body leaves B free; 100 × 2 × 4096 = 819,200 — far above any
off-by-a-few accounting slip, far below CI cost). 50 SOCKS5 + 50 HTTP
CONNECT = the contract's 100 auth-passing CONNECTs, each transferring
exactly 2B (control-grpc.md Tests row 2).

- **Must hold:**
  - 100 authenticated CONNECTs (50 SOCKS5 + 50 HTTP CONNECT) produce a
    `request_count` delta of EXACTLY 100 summed over the whole
    snapshot — one increment per auth pass, framing-independent
    (FR-008 first half; data-model.md §3).
  - `byte_count` delta EXACTLY 100 × 2B: every connection writes a
    known payload of exactly B bytes and reads exactly B bytes back
    (echo completeness is each attempt's premise — a dropped or
    duplicated byte invalidates the 2B premise and fails fast), and
    only client↔upstream forwarded bytes count (data-model.md §3).
  - The synthesised error-template body contributes zero: this test
    never triggers an error, so the data-model §3 exclusion is
    degenerate — asserted for completeness by a side-channel capture
    of all tunnel-surface bytes the DP emits, scanned for the
    errortpl.Template markers; captured template-byte count must be
    zero (Principle I: a happy-path tunnel carries no DP-synthesised
    bytes).
  - `hour_bucket` wall-clock truth: every row in the after-snapshot has
    route `'TOR'` and hour ∈ {baseline hour, baseline hour + 1}; the
    two-row allowance covers a mid-run hour rollover (a request_count
    increment and its close-time byte flush may land in adjacent
    buckets — summing both keeps the deltas exact) (data-model.md §3
    `hour_bucket` rule).
  - Journal delta across the burst holds the T025a shared allowlist
    (`loginvariants.AssertOnlyAllowedLines`): counter writes emit no
    per-request log line (FR-008; the allowlist is the inverse-form
    gate that catches an unnamed `msg="counted request"` line the
    corpus scan would miss). Plus corpus scan (per-iteration dest,
    UNAME, payload prefix, token plaintext) and no sub-hour timestamp.
  - Per-attempt success precondition: SOCKS5 leg sees `01 00` + `05 00`
    reply; HTTP leg sees `HTTP/1.1 200 Connection Established` — an
    unexpected auth failure means zero increments and masks the delta
    assertions, so it fails fast with the iteration named (T025a
    precedent, mirrored from T025c's failure-precondition).
- **Gated:**
  - `go vet` + `staticcheck` (test file compiles clean) + license-header
    check via scripts/verify.sh.
  - The named test (`TestAuthPassedCounterIncrements`) becomes the
    standing PR-cadence gate for the positive FR-008 counter contract
    once T050 lifts the harness boot gate; dpharness.Start's
    boot-minimum gate (T042/T045/T050) makes the skip/FAIL transition
    fail-closed.
  - Echo byte-equality per connection re-pins the T025b transparency
    property as a side effect of the premise.
- **Residue:**
  - Until T050 lands, the gate runs as SKIP — a broken positive-counter
    contract is invisible to verify.sh in that window (accepted
    repo-wide tests-first posture; the skip self-lifts and the gate
    then fails closed).
  - The harness `ReloadErr` §5.3 metadata residue (T020a Notes, owned
    by T022/T050) is inherited by the precondition reload — loud
    failure, never silent pass, if unfixed at first real run.
  - `byte_count` exactness is asserted at whole-snapshot granularity,
    not per-connection (the counter has no per-request surface by
    design — data-model.md §3; a per-connection byte mis-attribution
    that preserved the total would pass; no gate can catch it without
    adding a per-request counter surface, which FR-008 forbids).
  - Concurrent-tunnel counter accounting (races in the close-flush
    path under parallel CONNECTs) is T079a's scope; this test is
    sequential per the sibling-burst shape.

## Acceptance

1. **Named test — `TestAuthPassedCounterIncrements`**
   (`tests/contract/socks5/auth_passed_counter_test.go`): one DP boot
   (dpharness.Start with `WithUpstream` → AcceptAndRelay fake + fake CP
   HEALTHY, T025a fixture shape), one `ReloadTokens` of generation 1
   with a single 32-hex verifier (APPLY_STATUS_OK asserted), then:
   - baseline: `GetStatus` probe via `dpharness.Status` + wall-clock
     hour h0 = `now.Unix()/3600` + journal snapshot after a 250 ms
     quiesce;
   - the 100-connection burst: 50 authenticated SOCKS5 CONNECTs + 50
     authenticated HTTP CONNECTs, sequential (sibling-burst shape),
     each opening a tunnel to the AcceptAndRelay fake, writing exactly
     B=4096 payload bytes, reading exactly B back, byte-comparing the
     echo, then closing cleanly;
   - post-burst 250 ms quiesce, then the second `GetStatus` probe +
     journal snapshot.
2. **Behavioral assertions** (sub-tests):
   - `RequestCount_Delta100` — summed `request_count` delta across the
     whole snapshot is exactly 100 (assertion (a));
   - `ByteCount_Delta100x2B` — summed `byte_count` delta is exactly
     `100 × 2 × 4096` = 819,200 (assertion (b));
   - `NoTemplateBytesEmitted` — all tunnel-surface bytes captured
     during the burst, scanned for the errortpl.Template markers,
     yield a captured template-byte count of exactly zero (assertion
     (b) completeness side-channel);
   - `HourBucket_WallClock` — every row has route `'TOR'` and
     hour ∈ {h0, h0+1} (assertion (c), two-adjacent-rows allowance);
   - `Journal_T025aAllowlist` — delta passes
     `loginvariants.AssertOnlyAllowedLines` +
     `AssertNoSubHourTimestamp` + corpus scan over per-iteration
     dest / UNAME / payload prefix / token plaintext (assertion (d)).
3. **Runnable command**: `go test ./socks5/ -run
   TestAuthPassedCounterIncrements -v` from `tests/contract/` (SKIPs
   until T050; FAIL, not SKIP, once lifted and the positive-counter
   contract breaks), and `scripts/verify.sh` green from the repo root.

## Out-of-scope

- **Auth-failure must-NOT-increment** — T025c (done); **route-failure
  post-auth increments with `byte_count` 0** — T067b. Together with
  this ticket they close all three angles of the FR-008 counter
  contract (see T067b for the three-test mapping).
- **Byte-pipe transparency / long-lived exchange properties** (stream
  divergence, idle survival) — T025b's scope; this test borrows only
  the round-trip echo as its byte-count premise.
- **Concurrent-CONNECT counter accounting** — T079a (SC-005 pool);
  this burst is sequential.
- **Error-template body byte shape** — T019/T029; this test only scans
  for the template's absence on the happy path.
- **The CP-side flush of counters to SQLite** — deferred to the
  admin-UI feature (data-model.md §3); this test asserts the in-memory
  snapshot only.
- **Fixing the shared `dpharness.ReloadErr` §5.3 metadata gap** —
  recorded residue owned by T022/T050 (T020a Notes); inherited, not
  fixed here.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
