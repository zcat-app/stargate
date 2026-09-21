---
id: "T171"
title: "Separate topology probe launch and fixture timing"
status: pending
created: "2026-09-21"
last_updated: "2026-09-21"
source: "T163 full Ubuntu VM probe startup timeouts"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T169", "T170"]
parallel: false
files_budget: 6
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
decision_refs:
  - "specs/001-tor-route/tickets/T163-verify-packet-level-topology-boundaries.md"
remediates: "T169"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T171: Separate topology probe launch and fixture timing

## Context

T163's independently booted Ubuntu VM runs `T163-20260921-010358`,
`T163-20260921-011622` and `T163-20260921-013220` failed because an ordinary
Python probe exceeded its combined 2.8-second interpreter-start/socket budget.
The middle run passed the initial IPv4 capture matrix (all positive controls,
zero DP packets, DROP delta 3) before its forwarder probe timed out. Four VM
CPUs and higher test-process scheduling priority did not eliminate the startup
timeout. These remain failed runs, not denial evidence.

The fixture also starts its short accept/receive deadline before the recorders
are ready and before the child interpreter starts. A valid slow startup can
therefore lose the positive control even when packet policy is correct. This
ticket repairs test orchestration without changing production permissions or
using any timeout as an isolation verdict (Constitution III/V/VII).

## Analysis

- **Must hold:** helper startup has a separate finite process budget; the
  existing 0.8-second socket operation limit remains. Expired processes,
  missing completion markers, crashes and unknown confinement exits fail.
- **Gated:** spec-derived regressions inject real child-start delay and exercise
  real loopback fixture exchanges after slow recorder/probe startup. A hanging
  child still fails. Fixture workers end explicitly after the probes, with
  bounded cleanup; each negative retains its positive control and captures.
- **Residue:** the actual complete VM packet sweep, physical-host wording
  decision, and DNS-side-channel retirement remain T163's obligations.

## Acceptance

1. Preserve failing-before-fix tests for a delayed but valid helper and delayed
   forwarder/resolver setup, plus the actual VM timeout results above.
2. Give both ordinary and confined helper processes a finite 30-second default
   budget, separate from the unchanged socket-operation deadlines. Timeout is
   an error, never a successful denial. Retain exact ordinary completion-marker
   and confined exit-code requirements.
3. Start fixture workers after recorder readiness. Keep their real loopback
   services available until the bounded probes finish; then stop and join them
   with bounded cleanup, including on setup/probe failure. Do not manufacture
   packets or skip any capture/positive-control/denial assertion.
4. Document the timing distinction and failure semantics. Run the focused
   regressions, the full live suite on the VM, and `scripts/verify.sh`; both
   native reviewers and the driver-controlled commit must pass. The live suite
   must satisfy its existing assertions; a new production defect gets its own
   ticket, not a relaxed assertion here.

## Out-of-scope

Production code/topology/permissions, packet classification, recorder validity,
socket-operation deadlines, T163's host-evidence scope, DNS-channel closure,
browser/Tor-circuit or release guarantees.
