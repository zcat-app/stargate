---
id: T060
title: 'Integration test in `tests/integration/same_origin_shared_circuit_test'
status: done
created: 2026-07-04
last_updated: 2026-09-07
source: tasks.md#T060
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062]   # manual edge: circuit IDs are asserted via the T062 control-port helper (derive-deps missed prose deps; tightened 2026-09-07)
parallel: true
files_budget: 5   # test file + integration go.mod + go.sum (tidy demanded: module-graph hashes of the replaced contract module) + this ticket + STATUS.md (derived, driver-regenerated)
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - spec.md §"User Story 2" acceptance scenario 3 (same-origin CONNECTs share one circuit — the design, not a leak)
  - spec.md §Edge Cases "Concurrent requests against the same first-party domain" (same SOCKS5 username → IsolateSOCKSAuth consolidates)
  - FR-002 (username = first-party domain, the isolation key) + FR-007 (SOCKS5h; UNAME forwarded verbatim per T047)
  - FR-011/FR-012 (SocksPort compose-internal; exec/nc is the harness's sanctioned channel)
  - contracts/torrc.md §isolate_socks_auth_effect_test.go (amended 2026-09-07: identical identities share, empirically established on tor 0.4.9)
decision_refs:
  - T062 tests/contract/tor/control_port.go — the cookie-authenticated control-port helper this test reads circuit state through
  - T058a username_less_isolation_test.go — the reviewed live machinery this test mirrors (exec/nc SOCKS sessions, stream-status correlation, BUILT cross-check, per-suite compose project) and its external-calibration control (780aaae doctrine)
  - T058 — the distinct-identities-isolate live gate (this ticket pins the same-credential mirror)
  - T047 TestForwardPassesUNAMEVerbatimAsUpstreamUsername — the hermetic through-8881 UNAME pin T060 composes with, not re-proves
  - T033 — the spec-pinned reference onion constant (duplicated here; separate Go module)
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T060: Integration test in `tests/integration/same_origin_shared_circuit_test

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test in `tests/integration/same_origin_shared_circuit_test.go` — two parallel CONNECTs to the same first-party `.onion` (different resources) attach to the **same** circuit ID. (Spec US2 acceptance scenario 3 — this is the design, not a leak.)

## Analysis

Grounded 2026-09-07 (worktree `t060`) against spec.md US2 scenario 3 +
Edge Cases, contracts/torrc.md (amended §isolate_socks_auth_effect_
test.go), the landed T062 helper, and the reviewed T058a live suite.

### Transport grounding (the load-bearing decision)

The ticket body (and scenario 3) name no transport, unlike T059's
"through port 8881 (not directly against the sidecar)". The observable
scenario 3 pins is the circuit PAIRING at the control port, and the
mechanism is tor-side: `IsolateSOCKSAuth` consolidates streams that
present the SAME SOCKS5 credential (torrc.md, amended: identical
identities share, established live on tor 0.4.9 during T058's mutation
battery). The through-8881 leg adds only the DP's verbatim UNAME
forwarding — already pinned hermetically by T047's
`TestForwardPassesUNAMEVerbatimAsUpstreamUsername` against the fake
tor. Re-proving it live would require manufacturing a host→9050 path,
which FR-012 forbids publishing and no suite may fabricate; the
harness's only sanctioned channel into the compose-internal sidecar is
the exec/nc transport T032/T058a/T062 established. T060 therefore pins
the tor-side consolidation at the same interface the DP dials in
production (9050), with the username set to the exact value the DP
forwards (the first-party domain, FR-002). The end-to-end composition
(extension → DP → tor) stays covered by composition: T047 hermetic +
T058 distinct-isolate live + T060 same-share live, with T033 the
release-cadence full-vertical load and T059 the scenario-1 through-8881
sibling. T058/T058a made the same call for US2 scenario 1's tor-level
gates.

### Property map

**Must hold**

- Two SOCKS5 sessions presenting the SAME username (the reference
  onion — FR-002's first-party key, exactly what the DP forwards
  verbatim) to the sidecar SocksPort attach to ONE AND THE SAME,
  non-zero circuit ID at the control port (US2 scenario 3 — the
  design, not a leak).
- The shared circuit is real on tor's circuit-level surface: found
  BUILT in `GETINFO circuit-status` (T058a's stream/circuit
  cross-check).
- The share is attributable to the identity, not to environmental
  blindness: the SAME reading machinery, on distinct usernames,
  observes DISTINCT circuits (external-calibration doctrine, 780aaae).
  Without this control, "shared" is indistinguishable from "cannot
  detect isolation".
- Resource paths never appear: CONNECT carries only host:port, so
  "different resources on the same origin" is modelled as two
  independent concurrent CONNECT sessions to the same origin — the
  isolation key (username) is resource-invariant by design.
- The harness never becomes the leak: no bearer material anywhere
  (the SOCKS username is the public first-party domain; the RFC 1929
  password is the T058a dummy — tor does not verify it); T062's
  M4/M5 discipline (bounded reads, no cookie bytes in errors) applies
  to every control-port exchange; tor log tails are SafeLogging'd
  notice lines (torrc invariants #8–#9).

**Gated (standing gates T060 must not duplicate)**

- Directive presence: T029 byte-match + T030 invariants + T032 live
  GETCONF.
- Distinct identities ISOLATE (scenario 1's tor-level effect): T058.
- NO-username fallback + NO_AUTH share: T058a.
- DP verbatim UNAME forwarding (the through-8881 link): T047 hermetic
  named test.
- Control-port parser/error discipline: T062 hermetic suite.

**Residue**

- tor drift: a future tor that isolates same-identity streams breaks
  the design pin — this test fails at the digest-bump PR's live run
  (Principle IV), renegotiating FR-002's consolidation semantics with
  a SECURITY-DECISIONS.md entry, same consumption path as
  T058/T058a.
- The through-8881 composition is never exercised live as one unit in
  THIS test; accepted because each link is separately pinned (above)
  and the live composition owner is T033 (release cadence) / T059
  (scenario 1 sibling).
- Real-network environment: bootstrap and rendezvous latency, onion
  availability, partition flakes — environmental, bounded by the
  docker-tagged cadence and the retry windows T058a calibrated.

## Acceptance

**File**: `tests/integration/same_origin_shared_circuit_test.go`
(package `integration`; `//go:build docker` cadence like dns_leak_
test.go's docker tier; consumes the T062 helper via a require+replace
added to `tests/integration/go.mod`).

**Named test**: `TestSameOriginSharedCircuit`, subtests sequential,
each owning its sessions (T058a's subtest-hygiene rule):

1. `SameOriginStreamsShareCircuit` — bring up the tor service under
   compose project `stargate-t060-test` (own per-suite runner const —
   the T058a mis-project lesson); poll ReadCookie + Connect +
   Authenticate through the startup window (T062 live bootstrap
   shape); hold until `GETINFO status/bootstrap-phase` reports
   `PROGRESS=100`; open two SOCKS5 exec/nc sessions, both greeting
   RFC 1929 with username = the reference onion (T033's spec-pinned
   address; port 80); CONNECT both to `onion:80` with both sessions
   open; poll `GETINFO stream-status` until EXACTLY 2 live streams
   match the target; assert both circuit IDs are non-zero and EQUAL;
   cross-check the shared circuit appears BUILT in
   `GETINFO circuit-status`.
2. `CalibrationDistinctUsernamesDiverge` — wait for the previous
   subtest's streams to drain to 0; repeat with two DISTINCT
   usernames; assert both circuit IDs are non-zero and DISTINCT. If
   this control fails, the environment cannot distinguish share from
   isolate and subtest 1 is unproven, not green.

**Runnable command** (docker cadence; not in the hermetic PR gate —
needs the live Tor network; run via the named docker job or
manually):

```
cd tests/integration && go test -tags docker -run TestSameOriginSharedCircuit -v -timeout 25m
# or: STARGATE_TEST_TAGS=docker scripts/verify.sh
```

**Skip guards** (mirror T058a): docker CLI absent → skip; docker
daemon unreachable → skip. The hermetic gate vet-compiles the file
(`go vet -tags 'docker live release'`) and accounts the package
SKIP[docker] contribution per go-workspace-gate.py.

**Verify gate**: `bash scripts/verify.sh` GREEN hermetically (the new
file is tag-excluded from execution but must compile; go.mod/go.sum
changes must leave all modules resolvable, including GOWORK=off).

## Out-of-scope

- T059 (`tests/integration/stream_isolation_test.go`, scenario 1
  through port 8881) and T061 (`circuit_isolation_corpus_test.go`,
  SC-002 100-CONNECT sweep) — sibling tickets, possibly landing in
  parallel; no shared helper files are created for them here.
- `tests/contract/tor/control_port.go` (T062) — consumed as landed,
  read-only; exported surface only (composeArgs stays package-
  private to tests/contract/tor).
- T058/T058a test files, torrc/image/compose config, any data-plane
  change — the behavior under test is pinned, not modified.
- HTTP-level content fetch through the onion (T033's surface); this
  test asserts circuit pairing only, no payload exchange beyond the
  CONNECT handshake.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

Implement-time record (2026-09-07, worktree `t060`):

1. First live run PASSED in 56.8 s warm: both same-username streams shared
   circuit 12 (BUILT cross-check green) — the same circuit number the T058
   session's same-identity control probe observed, independently
   reproducing its observation as a committed pin; calibration subtest saw
   distinct usernames on circuits 19 vs 16.
2. `GOWORK=off go mod tidy` forced `golang.org/x/net` v0.54.0 → v0.55.0
   and `golang.org/x/sys` v0.44.0 → v0.45.0: MVS selection — the replaced
   `tests/contract` module's graph already requires those versions (its
   go.mod carries them as indirect). Not a drive-by upgrade; the module's
   own direct code is untouched by it.
