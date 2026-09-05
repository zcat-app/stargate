---
id: T074
title: 'Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (fro'
status: pending
created: 2026-07-04
last_updated: 2026-09-05
source: tasks.md#T074
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: [T009, T094a, T039]
parallel: false
files_budget: 8   # counted set: SidecarMonitor.java + SidecarMonitorTest.java (specs/ exempt per T039 r2 precedent)
privacy_critical: true
complexity: low   # refined at /start 2026-09-05: state-machine extension of an existing, fully-harnessed class
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §FR-014 (six kinds; fixed vocabulary; advisory)
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents · Contract" (v1 (kind, detail) pairing table + closed set)
  - specs/001-tor-route/data-model.md §4 (sidecar_unhealthy row shape; actor system; RESTARTED excluded) + §2 (advisory consumption)
  - THREAT-MODEL.md §5.8 (three-command allowlist residue 20260727-001 — unchanged by this ticket)
decision_refs: []   # no Blocker/Major finding accepted by this ticket
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T074: Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (fro

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (from T039) to emit `UNHEALTHY`, `STOPPED`, `CRASHED`, `RESTARTED` `SidecarEvent`s for the Tor sidecar; `detail` is drawn from the fixed vocabulary per `contracts/control-grpc.md` §"WatchEvents · Contract", with the v1 pairings `UNHEALTHY → healthcheck_fail`, `STOPPED → container_exit`, `CRASHED → container_exit`, `RESTARTED → container_start` (the same token used for STARTED; the contract rationale records why `detail` reuse across STARTED/RESTARTED is correct). On every transition to `UNHEALTHY`/`STOPPED`/`CRASHED`, write a `sidecar_unhealthy` row to `audit_log` via `AuditLogService` (T036) with `detail_json.kind` set to the matching state (data-model.md §4). `RESTARTED` is event-only and does **not** write an audit-log row — §4's `sidecar_unhealthy` vocabulary excludes it, and the next transition into HEALTHY emits the `sidecar_healthy` row via T039. Verified by T070b (failure-transition contract test in Phase 5) and T070 (integration test).
>
> **T094a amendment:** the observation channel inherited from T039 is now Tor's cookie-authenticated ControlPort (`tor:9051`), not a Docker Engine observer (the `docker-socket-proxy` that previously fed these transitions was removed). Under control-port observation, `UNHEALTHY` maps to a bootstrap/circuit stall (the `healthcheck_fail` pairing stands); `STOPPED`/`CRASHED` are detected via control-port-connection drop, and `RESTARTED` via reconnect. The v1 detail pairings (`container_exit`, `container_start`) MUST therefore be re-derived against the control-port signal at `/start` grounding. The `detail` vocabulary itself is owned by `contracts/control-grpc.md` §"WatchEvents · Contract" (unchanged by T094a); only the signal-to-detail derivation changes.

## Analysis

Property map (analysis gate; `privacy_critical: true`), grounded 2026-09-05
against `SidecarMonitor.java` (T039), `AuditLogService.java` (T036),
`contracts/control-grpc.md`, `data-model.md §4`, and the T094a amendment.

### Grounding decision 1 — signal-to-detail derivation (the amendment's mandate)

The contract's pairing table is **unchanged** (T094a: "the `detail`
vocabulary itself is owned by `contracts/control-grpc.md`… only the
signal-to-detail derivation changes"). The v1 tokens
(`healthcheck_fail`, `container_exit`, `container_start`) are retained
verbatim; what T074 re-derives is *which control-port signal drives which
kind*:

| Kind | Control-port signal (per poll cycle) | detail | §4 audit row |
|---|---|---|---|
| `STARTED` | edge into the **first-ever** authenticated session | `container_start` | no |
| `RESTARTED` | edge into a re-established session after an **observed** drop | `container_start` | **no** (event-only; §4 vocabulary excludes it) |
| `UNHEALTHY` | session up, bootstrap **regression**: was `PROGRESS=100`, now `< 100` (bootstrap/circuit stall) | `healthcheck_fail` | yes, `{"kind":"UNHEALTHY"}` |
| `CRASHED` | established session died **mid-exchange** (reset / EOF / malformed reply after connect) | `container_exit` | yes, `{"kind":"CRASHED"}` |
| `STOPPED` | next-cycle **connect refused** (no listener) after a previously-observed session | `container_exit` | yes, `{"kind":"STOPPED"}` |

Rationale: the control port exposes no exit codes. The abrupt-death shape
(protocol exchange in flight, then gone) is the honest `CRASHED` analog; a
quiet listener-less dial is the honest `STOPPED` analog. A tor that accepts
TCP but wedges mid-exchange reports `CRASHED` — accepted v1 fidelity gap
(residue below; events are advisory and the upstream dial is ground truth).
The existing T039 semantics refine, not break: STARTED was "per session,
re-armed by failed cycles"; under T074 the *re-arm* becomes `RESTARTED`
(`STARTED` = first observation ever, `RESTARTED` = a restart we observed).
No T039 test pins reconnect→`STARTED` (verified: the only STARTED-count
assertion covers one continuous session), so the suite stays green by
design, and the class javadoc is updated to the refined semantics.

### Grounding decision 2 — the T070b pairing constraint

tasks.md: "T070b MUST be authored and failing before T074 lands."
Grounding falsifies the constraint's original shape: T070b's task prose
still drives the monitor "via the mocked `docker-socket-proxy` surface"
(removed by T094a), and its (a)–(d) audit-row assertions observe
CP-internal state (`audit_log` rows, SidecarMonitor emission) that the Go
contract harness cannot see — the harness **fakes the CP**
(`tests/contract/control-grpc/watch_events_test.go`); the real CP never
runs there. T021 already pins the DP-side advisory consumption of
`STOPPED`/`CRASHED` with reachable upstream. Disposition:

- The tests-first gate for THIS ticket is the extended
  `SidecarMonitorTest` fake-ControlPort suite (Java) — authored first,
  red (new kinds do not exist), then driven green. That is the "authored
  and failing before lands" property for the code T074 actually changes.
- T070b remains its own ticket: its live scope is the Go-side
  failure-transition pairings + the shared `assertDetailRejected`
  invariant against the fake CP — DP-consumer surface, independent of
  T074's CP logic, so it cannot go red *because of* T074's absence.
  T070b's task prose gets its T094a-era refinement at its own `/start`
  (the same amend-siblings move T094a acceptance #11 made for T039/T074).
  T074's ticket body is NOT the place to rewrite T070b's.

### Property map

- **Must hold:**
  - FR-014: the CP emits all six kinds for `tor`; `detail` is always a
    token from the closed set; the four new pairings are exactly the
    contract table (must-hold 1).
  - data-model.md §4: every transition into `UNHEALTHY`/`STOPPED`/
    `CRASHED` writes exactly one `sidecar_unhealthy` row
    (`target=tor`, `detail_json={"kind":…}`; actor `system` comes from
    `AuditLogService`'s fixed vocabulary, already live); `RESTARTED`
    writes none (must-hold 2; edges — never levels — and a sink throw
    is contained + logged, mirroring T039's containment).
  - Each lost session is reported at most once: the drop edge is
    consumed by the first report; subsequent failed cycles stay silent
    until a session re-establishes (must-hold 3).
  - Pre-first-session failures (refused dial, auth reject, absent
    cookie) emit nothing — a monitor that never saw a session has no
    stop/crash to report (must-hold 4).
  - Advisory survivability (Principle II): no new path throws out of
    `runOnce`; sink/generation failures are contained exactly like the
    T039 paths (must-hold 5).
  - The wire surface does not grow: still exactly `AUTHENTICATE`,
    `GETINFO status/bootstrap-phase`, `QUIT` (THREAT-MODEL §5.8; open
    finding 20260727-001's residue is unchanged — must-hold 6).
  - No free text: bootstrap strings never enter events, rows, or logs
    (FR-014 / arch §5.2; must-hold 7).
  - Principle VII: every new behavior has a named test in
    `SidecarMonitorTest`, authored before the implementation lands
    (must-hold 8).
- **Gated:**
  - The whole `SidecarMonitorTest` suite runs fail-closed under
    `scripts/verify.sh` (Maven test gate) — pairings, row shapes,
    exactly-once edges, allowlist, containment.
  - `AuditLogService`'s five-action vocabulary gate (persistence tests,
    already green) rejects a malformed action before any row persists.
  - T021's Go suite pins the DP consumer's advisory handling of the
    failure kinds (`contracts/control-grpc.md` rows 1–3) — unchanged.
  - License-header + `lint-ticket.py` cover mechanical shape.
- **Residue:**
  - STOPPED-vs-CRASHED fidelity over a channel with no exit codes is a
    documented heuristic, not a verifiable property — redteam scope.
    Mitigation: advisory-only consumption (§2) caps the blast radius of
    a mis-derived kind.
  - Wedged-but-alive tor reported as `CRASHED` (fidelity gap above) —
    redteam scope; same mitigation.
  - Detection latency is bounded by the 10 s poll cadence, unasserted —
    advisory only, accepted.
  - The Go-side `watch_events_failure_transitions_test.go` (T070b) does
    not exist yet — its scope is DP-consumer behavior independent of
    this change (Grounding decision 2); tracked as T070b, not here.

## Acceptance

All in `control-plane/core/src/test/java/app/zcat/stargate/sidecar/SidecarMonitorTest.java`
(fake-ControlPort harness, extended); run via `scripts/verify.sh` (Maven
test gate) from the repo root. Tests are authored FIRST and observed red
before the implementation lands (Constitution VII; must-hold 8).

1. `emitsUnhealthyOnBootstrapRegression` — session healthy at
   `PROGRESS=100`, reply regresses to `PROGRESS<100`: exactly one
   `UNHEALTHY` event with `detail=healthcheck_fail` and exactly one row
   `("sidecar_unhealthy","tor","{\"kind\":\"UNHEALTHY\"}")`; a second
   stalled cycle (level, not edge) emits nothing; recovery to
   `PROGRESS=100` re-emits `HEALTHY` + the `sidecar_healthy` row.
2. `emitsStoppedWhenListenerVanishesAfterObservedSession` — established
   session, then connect-refused on a later cycle: one `STOPPED` event
   with `detail=container_exit` + one row `{"kind":"STOPPED"}`;
   subsequent refused cycles are silent (must-hold 3); the reconnecting
   cycle emits `RESTARTED` (`container_start`) with **no** unhealthy row
   for it, and the next `PROGRESS=100` cycle emits `HEALTHY` +
   `sidecar_healthy` (§4 edge re-armed by the drop).
3. `emitsCrashedOnMidSessionDrop` — established session, then the fake
   aborts the exchange mid-reply (EOF / reset shape): one `CRASHED`
   event with `detail=container_exit` + one row `{"kind":"CRASHED"}`; a
   following refused cycle adds no second drop report.
4. `coldFailuresBeforeFirstSessionEmitNoLifecycleEvents` — refused dial
   and auth-reject cycles before the first-ever successful session
   produce zero events and zero rows (must-hold 4).
5. `restartedIsEventOnly` — across a stop/restart sequence, `RESTARTED`
   appears with `container_start` and no `sidecar_unhealthy` row names
   `RESTARTED` (data-model.md §4 vocabulary exclusion; must-hold 2).
6. `unhealthyAuditSinkThrowIsContained` — an `AuditSink` that throws on
   the unhealthy edge: no throw escapes `runOnce()`, the event still
   emits, the failure is contained exactly like the T039 paths
   (must-hold 5).
7. All existing T039 tests stay green unchanged (the refined
   STARTED/RESTARTED split is designed against them — Grounding
   decision 1), and the wire-allowlist test (`c`) still passes with the
   new cycle shapes in play (must-hold 6).

## Out-of-scope

- The Go-side `tests/contract/control-grpc/watch_events_failure_transitions_test.go`
  (T070b) — DP-consumer surface, independent of this CP-side change;
  its stale docker-socket-proxy prose is refined at its own `/start`
  (Grounding decision 2).
- The `Event`→proto mapping of the four new kinds — T041's runtime
  adapter (pending; nothing production consumes `Kind` today except the
  monitor itself, verified by grep).
- Any new ControlPort command or cookie-path change — the three-command
  allowlist and the single-file subpath mount are frozen surface
  (THREAT-MODEL §5.8; T039/M14).
- DP behavior on failure events (advisory consumption, no dial
  short-circuit) — already pinned by T021 + T073's scope.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
