---
id: T196
title: 'Repair live-evidence harness defects found by the T155 pass'
status: pending
created: 2026-10-01
last_updated: 2026-10-01
source: "T155 attempt 3 live pass and cumulative redteam (candidate 989b8f9); harness defects reproduced by the T155 developer, confirmed by both T155 reviewers"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 8   # ticket + generated STATUS.md + inter_plane_wire_test.sh (+ fixture test) + observer.py + test_observer.py + run.py (+ test_run.py); extend with a stated reason if a fix needs more
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "VII: Tests First for Privacy-Critical Paths"
  - "VI: Open and Auditable"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/live-e2e/README.md
  - specs/001-tor-route/contracts/control-grpc.md
decision_refs:
  - "T155 live-e2e README D-live-7: a harness defect is fixed by a ticket, not reported as a pass"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T196: Repair live-evidence harness defects found by the T155 pass

## Context

T155 attempt 3 ran the live Local checks on candidate `989b8f9` and found harness
defects. They do not change shipped behaviour; they make evidence unreliable.

## Analysis

- Must hold: a live check prints PASS only if its assertion ran and could have failed,
  and a defective row never reports success.
- Gated: `scripts/verify.sh` (hermetic fixtures for each repaired decision rule); live
  re-runs on the disposable guest.
- Residue: the CP-event window length must stay below the inter-plane channel lifetime
  (T148), so headroom is gained by restructuring what the window contains, not by
  lengthening it; that design choice is for this ticket's planning round.

## Acceptance

1. `tests/contract/compose/inter_plane_wire_test.sh` runtime tier (never run live since
   T045): R2 and R3 open the Unix sockets with bash `exec 3<>socket`, which always fails
   with ENXIO (so R3's refusal check can never fail and R2 can never pass); R5 treats
   `wireprobe` exit 0 (the bad protocol major was rejected) as "accepted"; R7 reads
   `/proc/<pid>/net/tcp` of the host-network-namespace DP and sees host listeners; and every
   row prints `PASS` even after `bail` recorded a finding. Repair each with a real dialer as
   the named UID, correct exit semantics, DP listeners attributed by process, and a row that
   prints PASS only when its assertion succeeded. Add fixtures with discriminating negative
   controls (for example a 0666-mode socket must fail R3; a rejected major must pass R5).
2. `tests/live-e2e/local-topology/observer.py` CP-event windows are fixed 35 s subscriber
   lifetimes with a few seconds of headroom under emulation: `run.py` failed in 3 of 4
   identical attempts at the `initial-not-ready-and-repeat` and `observer-down-and-repeat`
   windows. Make the window robust (for example start counting after the triggering action
   returns and drop avoidable fixed sleeps) without lengthening it past the T148 lifetime,
   keeping early-closure failure loud and no reconnect.
3. `run.py` refuses a guest with a `fec0::` route (QEMU user network): document the
   disposable-host prerequisite or handle it in the runner with the same IPv6 refusal
   checks retained.
4. Re-run the live Local suite on the guest and record that the repaired checks pass and
   that each repaired decision rule fails against its mutant.

## Out-of-scope

Product code, Compose, the extension, and weakening any assertion.
