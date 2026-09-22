---
id: "T149"
title: "Finalize byte accounting after both forwarding pumps"
status: in-review
created: "2026-09-12"
last_updated: 2026-09-22
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T047", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T047"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T149: Finalize byte accounting after both forwarding pumps

## Context

Transport Minor m2: a net.Pipe scheduling probe delivered five bytes while final byte_count remained zero because Close flushed before the opposite increment.

## Analysis

- Must hold: all completed upstream Read/Write results contribute exactly once to the
  request-close byte total (data-model.md §3); shutdown cancels blocked I/O before joining
  both pumps. Client Close ownership stays with the listener. No live-tunnel idle timeout,
  payload interpretation, logging or counter-schema change (Constitution I/III).
- Gated: existing forward/audit and SOCKS counter contracts cover ordinary bidirectional
  totals, handshake exclusion, hourly shape and byte/log invariants. They did not force
  successful I/O to race the final accounting flush.
- Residue: `TestConcurrentCloseWaitsForAccounting` forces that interleaving for both reads
  and writes and checks one exact final flush (Acceptance 1).
  `TestBridgeCancelsBlockedIOBeforeJoining` covers blocked reads and writes on both
  endpoints (Acceptance 2). Real-socket forward and SOCKS contracts retain Acceptance 3
  coverage. Completed-hour publication remains the separately assigned T158 gap.

## Acceptance

1. Add a deterministic concurrent-close regression pausing after underlying successful I/O but before wrapper accounting; require exact byte totals and one final flush.
2. Ensure blocked reads/writes still cancel promptly; test that waiting for pump completion cannot deadlock socket shutdown.
3. Preserve byte-pipe semantics, hourly aggregate shape and absence of per-request logs.
4. Run forward/counter contract suites, scripts/verify.sh and required independent reviews.

## Out-of-scope

Performance redesign, idle timeouts, or changing what bytes the counters are specified to count.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

Tests-first evidence and scope limits: [T149 evidence](../analysis/T149-accounting-evidence.md).
