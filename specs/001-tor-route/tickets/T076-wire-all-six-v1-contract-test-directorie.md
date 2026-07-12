---
id: T076
title: 'Run every test module in the single green gate'
status: done
created: 2026-07-04
last_updated: 2026-07-12
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
reviews: { round: 2, date: 2026-07-12, verdict: APPROVE }
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

### Follow-ups surfaced on landing (out of this ticket's files_budget)

- **gofmt drift (7 files in `tests/contract`).** Surfacing every module under
  `gofmt` exposed pre-existing tab-alignment drift the old data-plane-only
  gate never checked. gofmt is ADVISORY (WARN) in the new gate until this is
  cleaned; flip it to FAIL in a follow-up that runs `gofmt -w` on the 7 files.
- **Go toolchain pin 1.26.3 → 1.26.4.** Mechanical (`toolchain` directives in
  `go.work` + each `go.mod`); unrelated to T076, kept separate per the
  surgical-changes doctrine.
- **staticcheck / gosec uniform wiring.** The old data-plane gate ran these
  when installed; the new uniform gate does not yet. Re-add them across all
  discovered modules in a follow-up (optional advisories, SKIP in CI).
- **Named Docker CI job.** The cadence-separation mechanism (`//go:build
  docker` + `STARGATE_TEST_TAGS`) lands here; the CI workflow that actually
  runs the docker suites under `STARGATE_TEST_TAGS=docker scripts/verify.sh`
  is a separate ticket (same entrypoint, no divergent command list).
