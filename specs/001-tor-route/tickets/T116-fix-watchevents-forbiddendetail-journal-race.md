---
id: T116
title: 'Fix ForbiddenDetailRejected journal-read race (poll the marker)'
status: done
created: 2026-09-05
last_updated: 2026-09-06
source: hand-filed follow-up (surfaced during T039 /start verify; not a tasks.md entry)
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: []
parallel: true
files_budget: 3   # raw-diff-path counting (run-task.sh): 1 code file +
                  # this ticket + STATUS.md regen — the filing value of 2
                  # forgot the regen path (corrected pre-review, 2026-09-06;
                  # ticket-template.md excludes specs/ paths from the budget)
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/control-grpc.md §"WatchEvents · Contract" (Tests row 2: forbidden detail)
decision_refs: []
reviews: { round: 1, date: 2026-09-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T116: Fix ForbiddenDetailRejected journal-read race

## Context

`tests/contract/control-grpc/watch_events_test.go`
`TestWatchEvents/ForbiddenDetailRejected` (via the shared
`assertDetailRejected` helper) is flaky: ~2 failures observed across ~10
full-suite runs on 2026-09-05 (two during T039's verify runs, two during a
10-iteration hunt), failing as:

```
watch_events_test.go:522: journal has no contract-violation marker for
forbidden detail "could not bind 0.0.0.0:9050" — contract requires the
violation to be journaled
dpharness_test.go:202: data-plane journal:
    level=ERROR msg="sidecar event rejected" kind=EVENT_KIND_STARTED
    err="detail outside closed vocabulary"
```

— i.e. the failure dump itself contains the marker the assertion claims is
missing. Race: after the DP closes the stream (`<-cs.done`), the helper
checks `h.journalHasDetailViolation()` **once**. The DP's journal line
still has to travel child stdout → pipe → the harness's pump goroutine →
`lockedBuffer`; under scheduler delay the one-shot check reads the buffer
before the pump delivers the line. The subsequent pass/fail is timing
luck, and the flake intermittently blocks the `verify.sh` green gate for
every ticket in the loop.

## Analysis

Quick pass (not privacy-critical — test-harness polling mechanics only, no
production code, no observation surface change). The privacy surface this
suite guards — the DP's closed-vocabulary gate and its no-free-text
journaling (Constitution Principle III) — is working correctly and is NOT
modified: the failure dump proves the DP behaves per contract; only the
test's read of the journal races:

- **Must hold:** the contract assertion itself does not weaken — the test
  must still prove (a) the DP closes the stream on an out-of-vocabulary
  detail, (b) the violation is journaled, (c) the journal does not echo the
  offending value (`loginvariants` scan stays, and still runs only after
  the marker is confirmed present, so a timeout failure cannot mask a
  leak).
- **Fix shape:** replace the one-shot
  `if !h.journalHasDetailViolation() { t.Errorf(...) }` with a bounded poll
  on the same marker predicate (reuse the `waitFor` helper /
  `journalContains` in a deadline loop — same 10 s budget the stream-close
  wait uses). No new markers, no loosened vocabulary.
- **Residue:** the pipe-pump latency itself is inherent to the
  child-process journal design; polling bounds it. If a 10 s poll is ever
  observed to time out with the marker still absent from the dump, that is
  a REAL regression (the DP stopped journaling violations) and must fail.

## Acceptance

1. `assertDetailRejected`'s marker check polls to a deadline instead of
   reading once; the `loginvariants` leak scan still executes only after
   the marker check has succeeded (order preserved: close-stream wait →
   marker poll → leak scan).
2. Repetition gate: `go test -count=10
   ./tests/contract/control-grpc/...` (from the workspace root:
   `go test -count=10 ./control-grpc/...`) is clean — the observed
   signature ("marker absent at check time, present in the dump") never
   reproduces.
3. `bash scripts/verify.sh` green.

## Out-of-scope

- Any production Go change (the DP's journaling/vocabulary gate is correct
  — the failure dump proves the DP behaves per contract).
- Changing the marker set / violation line phrasings.
- The T070b failure-transition suite beyond what the shared helper's fix
  gives it for free.

**Round-1 review record (2026-09-06).** APPROVE, 0 findings. The reviewer
independently re-ran `go test -count=10 ./tests/contract/control-grpc/`
(ok, 60.3s) and added `go test -race -run TestWatchEvents` (ok) — the flake
signature is structurally removed: the poll bounds pump latency instead of
racing it. All four must-holds verified intact (close-stream assertion
untouched; poll uses the SAME `journalHasDetailViolation` marker predicate,
not a loosened substring; leak scan now strictly after marker success since
waitFor Fatalfs; timeout stays loud with the journal dump in the failure).
Five falsified-and-dropped candidates each carried a defeating citation
(method-value closure re-evaluates per call; timeout-Fatal cannot mask a
leak; the pre-existing close-wait Errorf is not an escape this diff
introduces; STATUS regen byte-equivalent; budget correction 2→3 judged
LEGITIMATE — the raw-path counter would have false-triggered the over-
budget bright-line stop on a 1-counted-code-file change). Verify GREEN
PASS=20 at the APPROVE freshness gate. STATUS regen.
