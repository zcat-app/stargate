---
id: T089
title: 'Amend the Tor startup configuration contract'
status: done
created: 2026-07-11
last_updated: 2026-07-13
source: review/sol-review.md#B2
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: false
files_budget: 4
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for sidecar contracts"
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §FR-011
  - specs/001-tor-route/contracts/torrc.md §"Rendered file"
  - specs/001-tor-route/data-model.md §6
decision_refs: []
spec_amend_for: specs/001-tor-route/spec.md §FR-011
spec_amend_parent: T087
reviews: { round: 2, date: 2026-07-13, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T089: Amend the Tor startup configuration contract

## Context

Compose currently starts Tor before the control plane can render `torrc`.
For this static Tor-only slice, the safe configuration must exist in the Tor
image before its entrypoint runs; a control-plane dependency creates the
failure coupling forbidden by Principle II.

## Analysis

- **Must hold** — a cold, empty volume boot loads the exact byte-pinned safe
  `torrc`; `DataDirectory /var/lib/tor` is explicit; Tor startup never waits
  for the control plane.
- **Gated** — a cold-volume image test checks both loaded configuration and
  Docker `State.Health.Status == healthy` without harness seeding.
- **Residue** — future dynamic bridge configuration is deliberately deferred
  to its own feature and must re-open the ownership decision.

## Acceptance

1. Amend FR-011, plan, data model, Tor contract, and threat-model wording so
   the Tor-only slice bakes the exact safe `torrc` into the image and does not
   claim the control plane renders it at boot.
2. Add `DataDirectory /var/lib/tor` to the authoritative byte template and
   record the contract change in `SECURITY-DECISIONS.md`.
3. Refine T037 and T041 so they do not own Tor configuration in this slice;
   dynamic configuration remains future work.
4. Refine T087 to implement the amended image, healthcheck, and cold-volume
   regression test.
5. Re-run the plan Constitution Check; Principles II and III must pass without
   relying on Compose timing.

## Out-of-scope

Bridge toggles, runtime `torrc` reload, and any configuration surface not used
by feature 001.
