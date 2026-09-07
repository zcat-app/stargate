---
id: T061
title: 'Integration test in `tests/integration/circuit_isolation_corpus_test.g'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T061
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062, T063]   # manual edges: circuit IDs via the T062 control-port helper; CONNECT targets come from the T063 synthetic corpus (derive-deps missed prose deps; tightened 2026-09-07)
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: false
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T061: Integration test in `tests/integration/circuit_isolation_corpus_test.g

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test in `tests/integration/circuit_isolation_corpus_test.go` — SC-002 measurement: 100 sequential CONNECTs to 100 distinct first-party `.onion` strings from a synthetic corpus, assert ≥95 distinct circuit IDs. (Spec SC-002.)

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**Refinement (2026-09-07, post-T063).** The corpus this test consumes is
`tests/integration/synthetic_onion_corpus.txt` (T063, done). On load,
assert corpus validity per T063 §Acceptance A5 — exactly 100 lines, LF-only
with a single trailing newline, pairwise distinct, every line
`^[a-z2-7]{56}\.onion$` decoding as key(32)‖checksum(2)‖version(1) with
version byte `0x03` and `checksum == SHA3-256(".onion checksum" ‖ key ‖
0x03)[:2]`, reference target absent — and FAIL with the offending line
number on any violation, before any CONNECT is issued. Rationale: no
`verify.sh` gate inspects a `.txt` corpus, so a post-hoc hand edit would
otherwise pass every gate green and surface only as a confusing
circuit-isolation measurement failure. (T063 round-1/2 verdict follow-up;
recorded here because `target/runs/*.verdict` is gitignored.)
