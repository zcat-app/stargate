---
id: T034f
title: 'Integration test for US1 acceptance-scenario 3 second assertion (no TC'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: review/sol-review.md#A5
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T094]
parallel: false
files_budget: 8
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §"US1 Acceptance Scenario 3"
  - .specify/memory/constitution.md §III
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T034f: Integration test for US1 acceptance-scenario 3 second assertion (no TC

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test for US1 acceptance-scenario 3 second assertion (no TCP connect to a destination outside the current Tor consensus during the routed request window) — `tests/integration/egress_consensus_test.go`. Brings up the local-profile stack, fetches the **live Tor network consensus** (HTTPS GET to `https://collector.torproject.org/recent/relay-descriptors/consensuses/` for the most recent consensus, or via the in-network sidecar's `GETINFO ns/all` over the cookie-authenticated control port from T062 — whichever is reproducible in CI / release-tag run conditions; the chosen path is recorded in the markdown artefact for the run) and parses the set of `(IPv4, OR-port)` guard+relay endpoints. Then opens a Go-driven `.onion` session through port 8881 against the reference target onion for ≥120 s, with `gopacket` capturing **only the host egress NIC** (loopback is exempt because Tor's `tor:9050` is compose-internal and loopback is the inter-container bridge here). Asserts: (a) every TCP SYN observed on the egress NIC during the routed request window has a `(dst_ip, dst_port)` present in the consensus snapshot; (b) zero SYNs to any destination not in the consensus; (c) the leak-corpus scan from `tests/contract/error-template/leak-corpus.txt` (T064) returns zero hits over the captured packet metadata. This gates Constitution Principle III bullet 6 ("Stargate makes no outbound network connections except those a request explicitly routes through") against silent regressions in the data plane or any future component that opens an outbound socket from a Stargate container. Run before each release tag, not on every PR (consensus fetch + Tor reachability + packet-capture privileges make this unsuitable as a per-PR gate; same cadence as T034a and T070a). Result recorded in `tests/integration/sc_us1_egress_consensus.md` (markdown artefact alongside T034a's record). The data-plane source-level review (no outbound `net.Dial`/`http.Get` to non-`tor:9050` destinations) is the redteam-pass gate at T078; this task is the runtime regression gate.

## Analysis

- **Must hold** — Tor egress reaches only consensus endpoints while DP and CP
  have no non-internal egress at all.
- **Gated** — captures are attributed to container namespaces/veths or source
  identities, never to unrelated host traffic.
- **Residue** — the live consensus can change during the window; the test
  records both the snapshot time and bounded reconciliation rule.

## Acceptance

1. Capture Tor's container network namespace/veth (or filter by its exact
   container source identity), not the whole host egress NIC.
2. Assert each Tor TCP SYN during the request window targets an endpoint in
   the recorded live consensus snapshot.
3. Run separate DP and CP namespace captures and assert zero non-internal DNS,
   TCP, or UDP egress. A zero-packet assertion includes a capture-sanity probe
   so it cannot pass vacuously.
4. Ignore unrelated host traffic by construction; do not allowlist it.
5. Record namespace IDs, consensus digest/time, capture filters, and results in
   the release artefact. Leak-corpus diagnostics must not print captured secret
   content.
6. The release-cadence test passes against the T094-hardened topology.

## Out-of-scope

Host-wide traffic attribution and unrelated workstation processes are outside
the assertion surface. This ticket observes; T094 enforces the topology.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
