---
id: "T152"
title: "Replace detailed operational journals with hourly aggregates"
status: done
created: "2026-09-12"
last_updated: 2026-09-22
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T036", "T139", "T156"]
parallel: false
files_budget: 64
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T036"
tests_first: []
reviews: { round: 2, date: 2026-09-22, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T152: Replace detailed operational journals with hourly aggregates

## Context

Browser/control audit C1: lower-level contracts require Unix-second lifecycle/token rows while Constitution III literally permits only hourly aggregate logs.

## Analysis

- Must hold: persistent operational records contain only completed UTC-hour buckets,
  the five allowlisted categories and counts. Current-hour events remain volatile; finalized
  records cannot change. Retention is at most seven days, with an option to disable it.
- Must hold: migration removes legacy journals and unnecessary token lifecycle history while
  preserving current authentication state. Java/Go diagnostics and Tor/container output cannot
  bypass the aggregate boundary. No destination, credential, actor, label or arbitrary detail.
- Gated: existing tests currently require detailed rows and journal messages; those assertions
  are superseded by the aggregate contract, while their auth/socket/state coverage remains.
- Residue: transaction rollback, clock/restart finalization, WAL/backup cleanup and runtime
  output require new regressions and real storage/process/container probes before fixes.

## Acceptance

1. Apply Constitution III and foundation-boundaries.md aggregate-only policy; there is no
   administrative timestamp exception. Inventory Java/Go/sidecar diagnostic writers and stdout/
   stderr/container retention. Derive failing tests for forbidden fields and per-event records.
2. Implement fixed-category completed-hour operational aggregates, retention and no per-user
   labels/details. Current finite health/static error responses must not become historical logs.
3. Specify and test legacy-row cleanup including WAL/backup guidance; do not claim forensic host
   erasure. Update schemas/contracts/threat model in the same reviewed implementation.
4. Demonstrate all relevant writers obey the rule, run scripts/verify.sh and independent reviews.
   If the work exceeds the budget, decompose and add every child to T155 and affected consumers.

### Required evidence

Record red-before-green results for `operationalEventsDoNotPersistPerEventRows`,
legacy V001 migration/cleanup, clock-controlled completed-hour aggregation/retention,
`TestOperationalSnapshotWritesAreSilent`, and the deployed operational-output contract.
Retain authentication, transaction and socket assertions when replacing old log-based waits.

## Out-of-scope

Constitution amendments, silently rewriting the threat model to match code, or claiming a browsing log leak from administrative timestamps alone.

Existing tests asserting detailed audit rows, auth-history timestamps, event journals or
Tor stdout are explicitly superseded by Acceptance 1–3. Update those expectations while
preserving their underlying auth, schema, sidecar and connection-state coverage.

## Notes

2026-09-22: maintainer authorized one T152 with files_budget 64 following the T148 comparison
and the grounded 60-path candidate inventory. Existing acceptance and independent review gates
remain binding; no decomposition or constitutional exception is authorized by this extension.

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
