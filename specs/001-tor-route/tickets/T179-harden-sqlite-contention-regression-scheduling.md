---
id: T179
title: 'Harden SQLite contention regression scheduling'
status: done
created: 2026-09-27
last_updated: 2026-09-27
source: T178 round-1 GLM Minor finding
phase: 'Foundational'
story: 'US2'
blocked_by: ["T178"]
parallel: false
files_budget: 4
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/data-model.md §1.7–1.9
  - specs/001-tor-route/data-model.md §4
  - specs/001-tor-route/contracts/control-grpc.md ReloadTokens
decision_refs: []
reviews: { round: 2, date: 2026-09-27, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T179: Harden SQLite contention regression scheduling

## Context

T178's independent GLM reviewer approved the repair with a Minor finding in
`SqliteTokenStateTest.aggregateWriterCannotAbortInitialCredentialCommit`.
The test waits two seconds for the competing writer while holding the token
transaction's reservation. The synthetic connection inherits its SQLite
busy timeout; a sufficiently delayed runner may exhaust that timeout before
the correct token transaction commits. The acquisition latch's return value
is also ignored, reducing the regression's discrimination if the competing
writer is scheduled late on an unfixed build.

T178's recorded red/green evidence and enforcing-VM acceptance passed. This
follow-up concerns regression scheduling, not a demonstrated production
failure or a requirement to change the production SQLite timeout. Both T178
reviewers approved; no security finding is being accepted or overridden.
The full Minor finding is retained in `target/runs/T178-delivery/T178-r1.verdict`.

## Analysis

- **Must hold:** the regression exercises the conflicting transaction order
  before repair and passes the repaired writer-reservation behavior without
  depending on a narrow default timeout margin.
- **Gated:** test-only controlled scheduling/delay probes must distinguish the
  unfixed and repaired transaction implementations; retain bounded waits.
- **Residue:** finite timeouts cannot guarantee success under arbitrary runner
  suspension. Document the tested scheduling allowance and fail clearly if
  the fixture cannot establish its intended interleaving.

## Acceptance

1. Reproduce the reviewer's synthetic-writer timeout or missed-interleaving
   condition with a controlled test fixture before repairing that fixture.
2. Give the synthetic connection an explicit bounded wait budget and/or
   coordinate transaction scheduling so the exercised interleaving is
   established. A missing fixture precondition must not silently pass.
3. Demonstrate that the revised regression fails when T178's writer
   reservation is removed and passes with it, including a controlled delayed
   runner case within the documented fixture budget.
4. Preserve the existing atomicity and operational-count assertions, run the
   full repository gate, and obtain the required independent review.

## Out-of-scope

- Production timeout, journal mode, schema, authentication, confinement or
  operational-data policy changes.
- Reopening T178's successful live acceptance or completing T132.

## Verification evidence

`SqliteTokenStateTest.aggregateWriterCannotAbortInitialCredentialCommit` holds
the token writer for 3.5 seconds after the aggregate writer reaches SQLite.
The fixture gives that connection a 12-second busy-handler budget and fails
within five seconds if neither contention nor early acquisition occurs. Its
first busy callback proves the fixed path reached the held writer lock; early
acquisition exposes the unfixed path. The 12-second budget covers the controlled
delay and up to 8.5 seconds of additional scheduling/commit time; longer
suspension remains outside this finite fixture allowance.

The staged pre-fix test reproduced `SQLITE_BUSY` on the synthetic aggregate
writer with the inherited timeout (T179 red evidence). The revised test passed
with the production reservation. Removing only `SqliteTokenState.begin()`'s
no-op `UPDATE token_generation` then made that same revised test fail with
`SQLITE_BUSY` during the credential commit; the reservation was restored before
the green gate. Both probes used the Maven command recorded in
`evidence/T179-tests-first.json`; its committed `mutation` block retains the
production-only patch and failing credential-commit output.

Round-two cleanup evidence records the inherited busy timeout of the pooled
SQLite connection before installing the custom handler. The added test
assertion failed with effective `PRAGMA busy_timeout=0` after the old
`clearHandler` cleanup, despite an inherited 3000 ms setting. Restoring that
setting with `setBusyTimeout` passed the delayed regression; the reservation
mutation still failed at the credential commit. A same-connection SQLite
calibration then waited 230 ms through a competing 200 ms writer lock, within
the restored 3000 ms budget. The red/green and mutation outputs are retained
in `evidence/T179-tests-first.json`.
