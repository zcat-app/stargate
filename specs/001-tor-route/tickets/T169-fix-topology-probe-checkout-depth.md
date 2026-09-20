---
id: "T169"
title: "Make topology probe launch independent of checkout depth"
status: done
created: "2026-09-20"
last_updated: 2026-09-20
source: "T168 finalization: shallow-working-directory falsifier"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T168"]
parallel: false
files_budget: 4
privacy_critical: true
complexity: "low"
risk: "low"
round_cap: 2
spec_refs:
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
decision_refs:
  - "specs/001-tor-route/tickets/T163-verify-packet-level-topology-boundaries.md"
  - "specs/001-tor-route/tickets/T168-fail-closed-on-owner-rule-loss.md"
remediates: "T168"
tests_first: []
reviews: { round: 1, date: 2026-09-20, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T169: Make topology probe launch independent of checkout depth

## Context

After T168's reviewed implementation was committed, a further harness portability
check found that its Python stdin probe transport inherits `__file__ = '<stdin>'`.
The runner initializes ROOT with `Path(__file__).resolve().parents[3]` before
handling `--probe`. A shallow working directory such as `/tmp` raises
`IndexError: 3` before the socket attempt. A checkout under `/root/stargate` has
this same depth problem. The T168 measured checkout under
`/home/claudia/stargate-t168` has sufficient depth and completed its full live
sequence; its saved packet results remain valid. On a shallow checkout the
positive control fails, so the suite fails closed instead of claiming isolation.

Local reproduction is recorded in `target/runs/T168-probe-depth-check.log` in
the implementation checkout: execute the checked-in runner source through
`python3 - --probe udp 4 127.0.0.1 9`, supplying its bytes on stdin and setting
cwd to `/tmp`. Observed exit 1, `IndexError: 3`, before any probe traffic.

This follow-up is filed under CONTRIBUTING's surgical-change doctrine and the
workflow's rule that defects found after an approved commit receive a new
remediation ticket. T168's production confinement and completed scoped evidence
are unchanged. T163 should include this portability repair before its next
cumulative live sweep.

## Analysis

- **Must hold:** Python probe launch must preserve a meaningful source location
  or avoid root-path derivation in probe mode, independent of cwd depth and
  without requiring the selected UID to traverse the checkout's private parent.
- **Gated:** a real subprocess regression from a shallow cwd must first fail,
  then complete a controlled local socket exchange after the repair. Keep the
  existing helper-error and capture-positive-control obligations.
- **Residue:** routed IPv6, physical-host and other cumulative T163 evidence
  retain their existing owners and requirements.

## Acceptance

1. Add a failing real-subprocess regression for stdin probe launch from a shallow
   cwd. Its positive control must observe the local socket exchange, rather than
   infer success solely from process startup. Preserve coverage of private-parent
   launch behavior without requiring root for the deterministic selftests.
2. Repair the runner's source-location handling while retaining the exact probe
   argument contract, selected identities and failure classification. Cover both
   shallow and ordinary checkout paths; setup errors must not become denial proof.
3. Run the recorder/probe selftests and `bash scripts/verify.sh` GREEN, then the
   native review gate and driver-controlled commit. No production confinement,
   firewall or protocol behavior changes are needed.

## Out-of-scope

Production confinement or routing changes, new operator prerequisites, and
closing T163's remaining physical-host or release evidence.

## Execution record (2026-09-20)

Against pre-fix source `ac66f69`, the new subprocess and launcher-classification
tests ran first: `bash tests/contract/compose/topology_capture_test.sh` exited 1
with three failures. The shallow-cwd UDP control exited 1 with
`IndexError: 3` before sending a packet; the ordinary-cwd process did not
emit a completion marker; and a simulated Python launch error was accepted
as network denial. The source is now fed from a mode-000 fixture parent in
the real subprocess test, so the child cannot rely on traversing its source
path. Both shallow and normal cwd controls receive the UDP marker.

The runner now avoids checkout-root derivation in stdin probe mode and emits
a fixed completion marker only after `probe_main` returns. The caller
requires that marker for both success and denial exits; a traceback or setup
failure invalidates the result. The 11-test contract gate passed after the
repair. T163's live deployment and physical-host evidence remain pending.
