---
id: T049
title: 'Implement `data-plane/internal/audit/counters.go`'
status: pending
created: 2026-07-04
last_updated: 2026-09-04
source: tasks.md#T049
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true   # /start 2026-09-04: verified — counts auth-passed requests on the routing hot path (FR-008 aggregate surface); the counter contract is the FR-008 privacy boundary itself. Matches sibling T042/T043/T044/T045/T046/T047.
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md FR-008 (hour-bucketed (request_count, byte_count) only; auth-fail must-not-count, route-fail does; v1 in-memory only)
  - specs/001-tor-route/data-model.md §3 (increment rules verbatim: hour_bucket = Unix()/3600 at increment time; byte_count = client↔upstream forwarded bytes at request close, error-template body excluded; DP never touches SQLite)
  - specs/000-architecture/spec.md §6.4 (aggregate_counters shape: PK (route, hour_bucket); no destination/token/sub-hour data)
  - specs/001-tor-route/contracts/control-grpc.md §"GetStatus (minimum subset)" (DP returns a point-in-time in-memory snapshot; MUST NOT increment as a side-effect of serving)
decision_refs:
  - research.md §11 (minimum-subset GetStatus in v1 proto; test-harness-only caller in v1)
  - plan.md §"Plan-level tensions surfaced for review" #10 (same rationale, plan side)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T049: Implement `data-plane/internal/audit/counters.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/audit/counters.go` — in-memory `(route, hour_bucket) → (request_count, byte_count)` aggregates counted per data-model.md §3 (auth-passed requests increment `request_count`; only bytes forwarded between client and upstream contribute to `byte_count`, not the synthesised error-template body). The DP-hosted `GetStatus` RPC (T007 / T045; contract at `contracts/control-grpc.md` §"GetStatus (minimum subset)") reads from this in-memory map; the **production CP-side caller** that would flush counters to SQLite is **deferred to the admin-UI feature** per data-model.md §3, so in v1 the counters are process-memory only and are lost on DP restart. T025c (auth-fail: must-not-increment), T025d (auth-pass + happy relay: must-increment with `byte_count` accumulating forwarded bytes), and T067b (auth-pass + route-failure: must-increment with `byte_count = 0`) together gate the FR-008 counter contract from all three angles, all probing via the DP-hosted `GetStatus` RPC (rationale in plan.md tension #10 / research.md §11).

## Analysis

*(Grounded 2026-09-04 against data-model.md §3, contracts/control-grpc.md
§"GetStatus (minimum subset)", arch §6.4, FR-008, and the landed DP seams.)*

**Ground truth on disk.** The seams this ticket fills already exist:
`listener.Audit` (`AuthPassedRequest()`, socks5.go/connect.go) is already
called post-auth at exactly two sites and never on auth-failure paths;
`controlclient.StatusFunc` (`func() *grpcpb.StatusResponse`) is served
verbatim and side-effect-free by `Server.GetStatus`; the proto carries
`RouteCounter{route, hour_bucket, request_count, byte_count}` (T007).
`data-plane/internal/audit/` does not exist yet. **No byte-counting hook
exists anywhere in the DP** — `forward.bridge` uses plain `io.Copy` — and
no other ticket owns relay-path byte wiring (T050's body never mentions
counters), so the upstream-counting seam is *this* ticket's deliverable:
without it T025d's `byte_count` delta can never hold.

**Where byte counting must live.** Counting must wrap the **upstream** conn,
born inside `forward.dialUpstream`, because DP-synthesised bytes (SOCKS5
success reply, HTTP `200` line, error templates) cross the *client* conn
but never the upstream conn — T025d asserts `byte_count` delta is EXACTLY
`100 × 2B`, so any client-side wrapper that also sees the synthesised bytes
breaks exactness. Wrapping post-handshake also excludes SOCKS5 handshake
bytes. `forward` therefore grows a consumer-side `ByteCounter` seam
(required constructor param — T050 wires it; no nil checks inside the trust
boundary), with the flush landing **at request close** per data-model.md §3.

- **Must hold:**
  - `request_count` increments by exactly 1 per auth-passed CONNECT (either
    framing); no API path increments on auth failure (FR-008 first half,
    Principle III side-channel rule; data-model.md §3). Route failures
    still count because the count fires before the request phase (already
    the listeners' behaviour; the counter must not re-derive outcome).
  - `byte_count` accumulates exactly the bytes forwarded client↔upstream in
    both directions, flushed at request close; the synthesised error-template
    body, SOCKS5 success reply, and HTTP `200` line contribute 0 (data-model.md §3).
  - Bucket key is `(route='TOR', hour_bucket = time.Now().Unix()/3600)`
    computed at increment time (arch §6.4 / data-model.md §3); an increment
    that lands in a later hour creates the adjacent row (T025d's two-row allowance).
  - The counter stores **no destination, token, or sub-hour data** (arch §6.4
    invariant) — structurally: no such field exists on the aggregate.
  - `Snapshot()` returns a point-in-time copy (never aliases internal state)
    and increments nothing — the T025c no-traffic-sandwich property
    (contracts/control-grpc.md §"GetStatus (minimum subset)").
  - The DP holds counters in process memory only; nothing in the package
    touches SQLite, the filesystem, or the network (data-model.md §3
    invariant; Principle I dumb-router residue of "no storage side effects").
  - Counter writes emit no log line of any granularity (FR-008; T025a allowlist
    extension (d) in T025d).
  - Concurrent relays are safe: `bridge` runs two copying goroutines, so
    per-op accumulation is atomic and the close-flush happens exactly once.
- **Gated:**
  - `go vet` + `staticcheck` + `gosec` cover the syntactic/concurrency-lint
    surface; the license-header check gates the SPDX header.
  - Compile-time asserts `var _ listener.Audit = (*Counters)(nil)` and the
    `StatusFunc` signature match pin the two seams fail-closed at build time.
  - Unit tests added in this ticket (Principle VII, in-ticket tests-first):
    `TestSnapshotIsPureRead` (sandwich), `TestAuthPassedIncrementsCurrentHour`,
    `TestByteFlushAtCloseBothDirections`, `TestHourRolloverCreatesAdjacentRow`,
    `TestSnapshotDeterministicOrder`, and the forward-side
    `TestUpstreamRelayCountsTunnelBytesExactly` (drives the real x/net client
    against the stub and asserts the counted total equals the relayed payload
    bytes in both directions, handshake/reply bytes excluded).
  - The end-to-end FR-008 counter contract is gated later by the pairing
    contract tests T025c / T025d / T067b over the real DP gRPC surface
    (per the ticket dependency graph they follow this implementation).
- **Residue:**
  - Real-Tor end-to-end counter behaviour (UDP-adjacent paths, real sidecar
    framing) is not exercisable at unit level — residue carried by the
    pending pairing tests T025c/T025d/T067b (same pattern as T047's
    real-Tor residue carried by T058/T032/T033).
  - "No counter increment leaks request-derived data" is structural (the
    aggregate has no field for it) but no static check pins it — in scope
    for the stargate-redteam pass on this ticket.

## Acceptance

1. **Named test — `TestAuthPassedIncrementsCurrentHour`**
   (`data-plane/internal/audit/counters_test.go`): one `AuthPassedRequest()`
   yields exactly one row `(route="TOR", hour_bucket=now/3600)` with
   `request_count=1, byte_count=0`; N calls yield `request_count=N`.
2. **Named test — `TestByteFlushAtCloseBothDirections`**: bytes counted via
   the upstream-counting seam appear in `byte_count` only after the counting
   conn closes (flush-at-request-close per data-model.md §3), with the total
   equal to reads+writes in both directions, counted exactly once.
3. **Named test — `TestHourRolloverCreatesAdjacentRow`**: an increment with
   the clock advanced past the hour boundary lands in a second
   `(route, hour)` row; both rows survive in the snapshot.
4. **Named test — `TestSnapshotIsPureRead`**: snapshot → N ≥1 s-idle →
   snapshot again (the T025c sandwich at unit altitude): both responses are
   equal, and `Snapshot()` returns a copy — mutating the returned proto
   leaves the next snapshot unchanged.
5. **Named test — `TestSnapshotDeterministicOrder`**: rows are ordered
   (route, then hour ascending) so the RPC surface is stable for callers.
6. **Named test — `TestUpstreamRelayCountsTunnelBytesExactly`**
   (`data-plane/internal/forward/tor_test.go`): drive the real x/net client
   against the stub, relay a known payload of `B` bytes in each direction;
   the counter observes exactly `2B` — handshake, SOCKS5 success reply, and
   stub-side handshake bytes are excluded.
7. **Behavioral assertion**: auth-failure paths cannot increment — the
   package exposes no increment API other than `AuthPassedRequest()`, and
   the two existing listener call sites (socks5.go, connect.go) remain the
   only callers, both strictly post-auth (unchanged in this diff).
8. **Behavioral assertion**: the package contains no SQLite, filesystem, or
   outbound-network access, and emits no log lines (data-model.md §3
   invariants; FR-008).
9. **Runnable command**: `scripts/verify.sh` green from the repo root.

## Out-of-scope

- **The production CP-side `GetStatus` caller and SQLite persistence** —
  deferred to the admin-UI feature per data-model.md §3; this ticket adds
  no control-plane code and no persistence.
- **Wiring `audit.Counters` into `main.go`** (`Deps.Audit`, `ConnectDeps.Audit`,
  the `StatusFunc` argument, the `forward.New` counter argument) — T050 owns
  the boot sequence; this ticket only makes the types fit those seams
  (compile-time asserts pin conformance).
- **The pairing contract tests** `tests/contract/socks5/auth_failure_counter_test.go`
  (T025c), `auth_passed_counter_test.go` (T025d), `route_failure_counter_test.go`
  (T067b) — separate tickets per the dependency graph; not authored here.
- **Listener changes** — the post-auth `AuthPassedRequest()` call sites
  already landed with T042/T043 and are not touched.
- **Route-failure vs auth-failure asymmetry logic** — not implemented anywhere
  in this package; it is an emergent property of the call-site placement
  (count fires pre-dial), owned by the listeners, gated by T067b.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
