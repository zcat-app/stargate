---
id: T119
title: 'Gate invalid-path field preservation in options.save.test.js'
status: pending
created: 2026-09-06
last_updated: 2026-09-06
source: target/runs/T118.verdict finding 1 (round-1 APPROVE-WITH-FIXES, 1 Minor)
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: []   # T118 is done
parallel: true
files_budget: 3   # raw-diff-path counting (run-task.sh, T116 convention):
                  # options.save.test.js + this ticket + STATUS.md regen
privacy_critical: true   # the suite IS the machine side of the credential
                         # edge (T118 §spec_refs); Constitution VII applies
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §FR-019 (the options-page UX; spec-SILENT
    on field clearing AND on invalid-path field preservation — the suite
    stays the machine side of the coupling, T034c label precedent)"
  - "specs/001-tor-route/data-model.md §5 (validation shape `^[0-9a-f]{32}$`
    before save, in the options page — unchanged by this ticket)"
  - "extension/options/options.save.test.js (the T118 P6 section — this
    ticket ADDs one named case to it; the T118 §Analysis coupling stands)"
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code (a must-hold
    property of the credential edge should not rest on unasserted code
    shape; this ticket closes the gap T118's own AC1(c)/AC4 forbade
    closing in that diff)"
decision_refs:
  - "specs/001-tor-route/tickets/T118-clear-options-token-field-after-save.md
    (§Notes falsification record, corrected post-review: the invalid-path
    field-untouched half holds in shipped code but is NOT gated by any
    existing case; §Analysis must-hold bullet 3)"
  - "target/runs/T118.verdict finding 1 (round-1 APPROVE-WITH-FIXES):
    reviewer mutation M4 — an invalid-branch clear passes the suite 9/9;
    M4 is this ticket's non-vacuity proof"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T119: Gate invalid-path field preservation in options.save.test.js

## Context

T118 clears `#bearer-token` after a RESOLVED save, and its §Analysis
must-holds include "Invalid input: field value unchanged". That property
holds in the shipped code (the clear sits only in the `try`-success
branch of `saveToken`), but NO existing case asserts it: T056 case (b)
(`invalidTokensRenderErrorAndNeverTouchStorage`) asserts the error
status, zero storage touches, and `preventDefault` — it never reads the
field value — and `submit()` re-assigns `input.value` before every
fire. T118's round-1 review proved the gap with mutation M4 (clear moved
into the invalid branch): the suite passes 9/9 on the mutant. T118 could
not close this itself — its AC1(c)/AC4 forbade editing T056-era case
assertions, and its files_budget was consumed. This ticket is that
owner.

## Analysis

Test-only hardening ticket: NO production change — the property already
holds in `options.js` (round-1 review EVIDENCE: options.js:51-54, the
clear sits only in the try-success branch). Tests-first (Constitution
VII) applies here as the regression-gate form (storage.test.js A-case
precedent): the new case is authored against shipped code that already
satisfies it, and non-vacuity is demonstrated by the M4 mutation probe,
not by a RED state.

Design constraints pinned up front:

- **New named case only** — in the T118 P6 section of
  `options.save.test.js` (or a sibling P6 case). NO edit to any
  T056-era case's assertions (the T118 constraint becomes this ticket's
  own scope rule; the seven T056 cases and the two T118 cases stay
  byte-identical).
- **Harness note drives the assertion shape:** `submit()` re-assigns
  `input.value` before firing, so the case must capture the submitted
  invalid string and assert the field still equals it AFTER the drained
  turn — with zero storage touches and the error status in the same
  drained state (all three observable in the same harness idiom the
  T118 cases use).
- **Must hold:**
  - After an invalid submit (pick a representative from the existing
    matrix, e.g. the whitespace-padded valid token): after drain, the
    field value still equals the submitted string, the status is
    INVALID_MESSAGE, and storage touches are zero — all in one case.
  - Every existing case (seven T056-era + two T118) passes UNMODIFIED.
  - Zero new globals / surface unchanged (P1 conformance case stays
    green unmodified).
- **Gated:**
  - The new named case is non-vacuous: mutation M4 (an
    `input.value = ''` added to the invalid branch of `saveToken`)
    MUST fail exactly the new case — exercised in a throwaway copy and
    recorded in §Notes (T118 falsification-record convention).
  - The frozen T034e suite and the canonical §5.1 string untouched;
    `bash scripts/verify.sh` green.
- **Residue:**
  - A single representative invalid input gates the branch, not the
    full T056 matrix — the invalid branch is one shared code path
    (`if (!TOKEN_PATTERN.test(value))`), so per-input repetition adds
    cases without adding coverage; the matrix stays where it is.

## Acceptance

1. **New named case in `options.save.test.js`** (P6 section): an
   invalid submit leaves the field value equal to the submitted string
   after drain, alongside the error status and zero storage touches.
2. **No production diff:** `extension/options/options.js` is untouched
   by this ticket (`git diff` names no options.js hunk).
3. **Existing cases untouched:** the seven T056-era cases and two T118
   cases pass unmodified (`git diff` on the file shows only the new
   case + header/comment line if needed).
4. **Runnable:** `node extension/options/options.save.test.js` green;
   `node extension/options/options.test.js` 3/3, 0 skipped;
   `sh extension/run-tests.sh` exits 0; `bash scripts/verify.sh` green.
5. **Falsification record** (§Notes): mutation M4 (invalid-branch
   clear) exercised in a throwaway copy → the new case FAILS, all
   others pass; pristine control green.

## Out-of-scope

- Any `options.js` change (the property already holds — this ticket
  gates it, not fixes it).
- Edits to T056-era or T118 case assertions (named-case-only rule,
  §Analysis).
- `type="password"` masking, configured-state display, clipboard
  timers (T118 §Out-of-scope carries forward unchanged).
- Extending the assertion to the full invalid matrix (§Analysis
  residue).

## Notes

Hand-filed follow-up on 2026-09-06, mirroring the T116/T117/T118 filing
convention. Origin: T118 round-1 verdict (APPROVE-WITH-FIXES, 1 Minor)
finding 1 — the reviewer's EVALUATED-AS grep for the corrected gating
claim passes on the corrected record, but the underlying gap (ungated
must-hold) is real and was explicitly ruled out-of-reach for T118's own
diff by its AC1(c)/AC4.
