---
id: T108
title: 'verify.sh must record repro-test SKIP as SKIP, not PASS'
status: in-progress
created: 2026-09-02
last_updated: 2026-09-02
source: T098 review round 2 (APPROVE) RECOMMENDED-FOLLOW-UP #1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: true
files_budget: 5
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §12.2
decision_refs: []
constitution_refs:
  - "VI: Open and auditable"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T108: verify.sh must record repro-test SKIP as SKIP, not PASS

## Context

`run_cmd` (scripts/verify.sh) records PASS on bare exit 0. The three
reproducibility tests under `tests/reproducibility/` each exit 0 with a
"SKIP:" line when a tool is missing — the convention pre-exists T098 in
the extension and tor-image manifest tests. On a
host with go+java but no python3 (or no docker),
`STARGATE_VERIFY_REPRO=1 scripts/verify.sh` would summarize
`repro:jvm_test.sh` / `repro:extension_test.sh` as **PASS while zero
bytes were compared** — a false-green summary for exactly the gates
whose entire value is the byte comparison. Flagged at T098's round-2
review (2026-09-02); framework-level, not a defect in any single
ticket's diff.

## Acceptance

1. verify.sh gains a SKIP convention (sentinel output line or exit
   code, e.g. 2 = SKIP) that `run_cmd` records as SKIP — shown in the
   per-gate output and counted separately in the summary; the PASS
   count must not include skipped gates.
2. The three reproducibility scripts' tool-absence paths adopt the
   convention.
3. A regression probe demonstrates the fix: with python3 (or docker)
   hidden from PATH, the affected repro gates record SKIP — never
   PASS — and the run summary reflects it.
4. scripts/verify.sh is green; the existing tests covering verify.sh
   discovery/quality stay green.

## Out-of-scope

Which gates run or their ordering; CI wiring (T076 done; T081 owns
release cadence); any repro-test comparison logic.
