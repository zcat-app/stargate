---
id: T090
title: 'Remove control-plane route admission gating'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#B3
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: false
files_budget: 8
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for routing decisions"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §FR-009
  - specs/001-tor-route/spec.md §FR-013
  - specs/001-tor-route/data-model.md §2
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents"
decision_refs: []
spec_amend_for: specs/001-tor-route/data-model.md §2
remediates: T021
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T090: Remove control-plane route admission gating

## Context

Cold start currently leaves the Tor route disabled until a control-plane
`HEALTHY` event arrives. That makes routing availability depend on the advisor
plane and contradicts binding Constitution Principle II.

## Analysis

- **Must hold** — with a valid snapshot and no control plane, the data plane
  attempts the fixed `tor:9050` upstream; only the upstream dial/handshake
  result decides success or the privacy-safe route error.
- **Gated** — contract tests boot the DP without CP, exercise a healthy fake
  Tor and an unreachable Tor, and assert both outcomes byte-for-byte.
- **Residue** — advisory health may optimize status or avoid a known-doomed
  dial, but absence/staleness of an event can never deny admission.

## Acceptance

1. Amend architecture §5.5, feature FR-009/FR-013/FR-014, data-model §2,
   plan/research, and the control-gRPC contract to remove `routeEnableMask`
   from request admission.
2. Add/repair regression tests so cold start with no CP forwards through a
   reachable fixed Tor upstream, while an actual upstream failure returns the
   protocol-appropriate `ROUTE_DOWN` response without leaked reason text.
3. Remediate stale mask assertions introduced by T020/T021 and refine pending
   T020a, T045, T050, and T073 before they are reopened.
4. Sidecar events remain local status/audit hints and cannot be a mandatory
   precondition for listening, authenticating, dialing, or forwarding.
5. `scripts/verify.sh` passes and the amended Constitution Check explicitly
   cites Principle II.

## Out-of-scope

Changing the fixed port-to-upstream mapping or adding retries after a request
has entered the byte-pipe phase.
