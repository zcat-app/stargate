---
id: T073
title: 'In `data-plane/internal/controlclient/client.go` (from T045), wire the'
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T073
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T090", "T155", "T070b", "T156"]
parallel: false
files_budget: 9
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md FR-009, FR-014, and US3 privacy-safe Tor failure behavior'
  - 'specs/001-tor-route/data-model.md §2 advisory event handling and §4 operational aggregates'
  - 'specs/001-tor-route/contracts/control-grpc.md §WatchEvents'
  - 'specs/001-tor-route/contracts/foundation-boundaries.md §Aggregate data policy'
  - '.specify/memory/constitution.md Principles II, III, and VII'
decision_refs:
  - 'T070b: failure/stale WatchEvents inputs cannot suppress an authenticated SOCKS5 dial'
  - 'T090: CP sidecar status does not gate route admission'
  - 'T152: AuditLogService is the sole operational aggregate writer; no per-event journals'
  - 'T172 selected acceptance: authenticated SOCKS5 behavior, advisory events, no HTTP CONNECT admission'
  - 'T203: WatchEvents health emissions are limited to substantiated source observations'
tests_first: ["T070b"]
reviews:
  round: 2
  date: 2026-10-09
  verdict: APPROVE
  candidate: 5817bb75fe6d2873e60f9ab48e0e05fb5f909e245438b47b69c43a1332850062
  base: 82b16f135b62c74dc4fe62c42d14f44df2e3b8ea
  reviewers:
    - identity: Astra
      model: gpt-6-astra
      effort: high
      verdict: APPROVE
    - identity: Luna
      model: gpt-6-luna
      effort: high
      verdict: APPROVE
  findings: none
overrides: [{"date": "2026-10-09", "by": "user", "decision": "Use the three focused Go selectors for T073 verification; do not run Java or repository-wide verify.sh", "reason": "The scoped T073 instruction authorizes the named affected-part checks and expressly excludes Java and the full gate."}]
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T073: In `data-plane/internal/controlclient/client.go` (from T045), wire the

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> In `data-plane/internal/controlclient/client.go` (from T045), wire the `SidecarEvent` consumer to treat all events as **advisory** status per data-model.md §2 (Principle II — events MUST NOT gate admission and MUST NOT short-circuit the dial). The forwarding path ALWAYS dials the upstream; events feed the audit journal (`sidecar_healthy` / `sidecar_unhealthy` rows per §4) and status reporting only. A `STOPPED`/`CRASHED` event is recorded in the audit log but the DP still dials `tor:9050` — a stale or forged event cannot suppress a dial that would succeed. `HEALTHY`/`STARTED`/`RESTARTED` update advisory status only.

## Analysis

- **Must hold:** matching Tor `SidecarEvent`s are validated and delivered to an
  advisory sink. Event kind, age, arrival order, and `WatchEvents` connectivity
  cannot gate admission or suppress an otherwise successful fixed upstream
  dial. The DP does not persist or log event receipts, event details, request
  metadata, destinations, or credentials. Its `GetStatus` reports traffic route
  counters only. The CP records its own observed `HEALTHY` / `UNHEALTHY`
  transitions through `SidecarMonitor` and the sole `AuditLogService` writer;
  those counts describe observations made by the running CP, not DP event
  receipts or a durable lifecycle journal.
- **Source boundary:** `client.go` checks the Tor selector and closed detail
  vocabulary, retains only volatile channel-degraded state, and sends matching
  events to `EventSink`; it does not validate kind/detail pairings and its state
  is not consulted by forwarding. `main.go` wires an empty `advisorySink`.
  The CP monitor owns the fixed operational health categories. The `GetStatus`
  proto exposes route counters only. The §2 data-model replacement removes the
  conflicting DP counter/status permission while preserving the fixed-dial and
  privacy requirements.
- **Evidence ownership:** T070b owns the stale/failure event matrix and
  disconnect/reconnect regression. `TestWatchEvents` probes successful
  forwarding around event transitions and after reconnect; this T073
  extension establishes a server-side stream gap by rejecting a replacement
  WatchEvents RPC, then proves forwarding before a replacement stream is
  accepted. `TestColdStartSnapshotRestore`'s
  `ForwardsWithoutHealthyEvent` subtest independently proves authenticated
  forwarding to a reachable fake upstream with no reachable CP. The T045
  client test proves delivery to a recording sink and absence of a diagnostic
  record. These local fake-upstream checks establish routing behavior, not live
  Tor health or CP aggregate persistence.
- **Residue:** deployment and live Tor claims remain with T070/T155. CP
  aggregate behavior remains with T039/T074/T152. This ticket makes no new
  deployment or persistence claim.

## Acceptance

1. **Contract reconciliation:** FR-014, `data-model.md` §2, and
   `contracts/control-grpc.md` §WatchEvents assign operational aggregates to
   the CP's source-observed Tor health transitions through the §4 sole writer.
   Receiving any `SidecarEvent` does not create a DP aggregate
   or sidecar status. The DP delivers matching Tor events to its advisory sink,
   exposes traffic counters only through `GetStatus`, and attempts the fixed
   upstream dial for every admitted request; only that dial result selects
   `ROUTE_DOWN`, `ROUTE_REFUSED`, or `ROUTE_TIMEOUT`. Event handling retains
   the Principle III logging prohibition.
2. **Client sink:** from `data-plane/`, run:

   ```sh
   go test ./internal/controlclient -run '^TestClientConsumesEventsAdvisory$' -count=1
   ```

   This proves validated event delivery to the test sink without an event
   diagnostic record; it does not exercise production aggregate persistence.
3. **Failure/stale-event regression:** from `tests/contract/`, run:

   ```sh
   go test ./control-grpc -run '^TestWatchEvents$' -count=1
   ```

   T070b owns the failure/stale event matrix. This selector additionally
   proves authenticated forwarding during a confirmed stream outage while
   the fake server rejects replacement RPCs, then after reconnection.
4. **Control-plane outage route control:** from `tests/contract/`, run:

   ```sh
   go test ./control-grpc -run '^TestColdStartSnapshotRestore$/^ForwardsWithoutHealthyEvent$' -count=1
   ```

   This separately proves authenticated byte forwarding with no reachable CP
   and no healthy event. Together with the live-disconnect probe and T070b
   stale/failure matrix, it covers the selected T172 behavior without a
   duplicate event-matrix regression.
5. **Review state:** the implementation plan at SHA-256
   `755252ac183e73f6ad8d3efbc0e759f0f3c88825ceea26c85a2b406d81f6e21e` was
   independently approved by Astra and Luna as a planning decision. Round-1
   Luna's Major consistency finding was accepted and resolved in that plan by
   expanding reconciliation to FR-014, both §2 event paragraphs, the
   WatchEvents contract, and stale source comments. Separately, Astra
   (`gpt-6-astra`, high) and Luna (`gpt-6-luna`, high) approved the exact
   implementation candidate at SHA-256
   `5817bb75fe6d2873e60f9ab48e0e05fb5f909e245438b47b69c43a1332850062` in
   round 2 with no findings; reviewer approvals are recorded in frontmatter.

## Verification — 2026-10-09

- `tests/contract/`: `go test ./control-grpc -run '^TestWatchEvents$' -count=1` passed.
- `data-plane/`: `go test ./internal/controlclient -run '^TestClientConsumesEventsAdvisory$' -count=1` passed.
- `tests/contract/`: `go test ./control-grpc -run '^TestColdStartSnapshotRestore$/^ForwardsWithoutHealthyEvent$' -count=1` passed.
- The WatchEvents selector observes a rejected `Unavailable` replacement RPC,
  confirms only the first stream was accepted during the outage, and proves
  successful forwarding both during that outage and after reconnection.
- The authorized scope is limited to those three Go selectors, ticket lint, and
  diff/status checks. Java and repository-wide `scripts/verify.sh` were not run.

### Required planning refinement (resolved)

T070b supplies the event-matrix negative regression for the consumer: successful
authenticated SOCKS5 dials remain possible around STOPPED/CRASHED/stale inputs
and stream disconnect/reconnect. T073 adds the missing successful dial during
the confirmed server-side stream gap, before a replacement stream is accepted,
and runs the existing cold-start `ForwardsWithoutHealthyEvent` subtest to
establish routing with no reachable CP from startup. T152 assigns operational
aggregate writes solely to the CP; T073 reconciles the obsolete historical
journal and status wording in FR-014, §2, and the WatchEvents contract without
adding DP event persistence or a duplicate event-matrix test.

## Out-of-scope

No Go production behavior change; no duplicate event-matrix test; no DP event
counters, sidecar status, or event persistence; no CP aggregate change; no live
Tor, Docker, or VM check; no Java or repository-wide `scripts/verify.sh`.
The exact reviewed candidate is complete.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Keep SidecarEvent handling advisory under Principle II. Verify with authenticated SOCKS5 that STOPPED/CRASHED/stale events and CP outage do not suppress a reachable Tor dial; no HTTP CONNECT admission is relied upon. T070b owns the event matrix; T073 runs its focused selector plus the separate no-CP forwarding control.
