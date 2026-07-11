---
id: T076
title: 'Run every test module in the single green gate'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: review/sol-review.md#M4
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: true
files_budget: 8
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §FR-016
  - .specify/memory/constitution.md §VII
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T076: Run every test module in the single green gate

## Context

The documented single green gate currently runs only the data-plane Go module
and shell tests. Completed Go contract, integration, proto, and shared-helper
modules can therefore regress while `scripts/verify.sh` remains green.

## Analysis

- **Must hold** — every workspace module is discovered automatically and
  accounted as PASS/SKIP/FAIL; required tests that all skip cannot report PASS.
- **Gated** — a self-test fixture proves module discovery and JSON skip
  accounting; CI invokes exactly the same `scripts/verify.sh` entrypoint.
- **Residue** — live/release-only tests remain explicit SKIP with a named
  cadence and cannot disappear from the inventory.

## Acceptance

1. Move this ticket to Foundational and run every Go module currently present:
   data plane, proto, contract, integration, and shared log invariants.
2. Use `go test -json` accounting so a required package/test set with only
   skipped tests is reported SKIP (or FAIL when required), never PASS.
3. Discover modules and extension tests rather than enumerating six fixed
   directories; new modules cannot silently fall outside the gate.
4. Keep hermetic PR tests separate from named Docker/live/release jobs, but
   make the inventory exhaustive and machine-auditable.
5. Add a CI workflow that runs `scripts/verify.sh`; do not create a second,
   divergent list of commands.
6. Add a regression test for discovery/skip accounting and make verify green.

## Out-of-scope

Live Tor/browser/packet-capture tests keep their release cadence. This ticket
accounts for them but does not make them hermetic.

## Notes

Refined from tasks.md#T076 for review finding M4. This blocker must land before
completed contract tickets can be treated as standing regression gates.
