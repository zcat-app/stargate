---
id: T119
title: 'Gate invalid-path field preservation in options.save.test.js'
status: done
created: 2026-09-06
last_updated: "2026-10-10"
source: target/runs/T118.verdict finding 1 (round-1 APPROVE-WITH-FIXES, 1 Minor)
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: ["T155", "T156"]
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
reviews: { round: 2, date: 2026-10-10, verdict: APPROVE, candidate_sha256: "31dd9826f15506f24716e477a48005928577dd8e4e2da83cac8f0a32cef2c573", reviewers: "gpt-6-astra/high: APPROVE; gpt-6-luna/high: APPROVE", findings: "Both independent reviewers approved the exact candidate; no findings remain." }
overrides: [{"date": "2026-10-10", "by": "user", "decision": "Limit verification to the changed options.save.test.js case and affected ticket/status/diff checks; do not run options.test.js, extension/run-tests.sh, Java, scripts/verify.sh, or push", "reason": "The user explicitly scoped verification to changed and affected parts and excluded the broader suites and push."}]
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
holds in `options.js`: invalid values enter the `!TOKEN_PATTERN.test(value)`
branch, which renders `INVALID_MESSAGE` and returns before the field clear
inside the successful storage-write path. Constitution VII applies as
regression-gate work: the added case is authored against shipped code that
already satisfies the invariant; non-vacuity is demonstrated by the M4
mutation probe, not by a red-before-implementation state. The harness's
`submit()` helper assigns `input.value` before firing the real submit
listener and drains asynchronous work before returning, so the new test
captures the whitespace-padded submitted string and reads the field only
after that drain.

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
- **Must hold:** after an invalid submit using the whitespace-padded
  valid-shaped token, the field exactly equals that submitted string after
  drain, status equals `INVALID_MESSAGE`, and storage touches are empty —
  all asserted by the one new named case. Every prior case remains
  unmodified and passes; no global or surface changes are introduced.
- **Gated:** the new named case is non-vacuous: M4, adding
  `input.value = '';` inside the invalid branch before rendering the error,
  fails exactly that case in a throwaway copy while all nine prior cases
  pass. The pristine focused test file is the green control. Ticket lint,
  regenerated STATUS, and `git diff --check` cover ticket metadata and
  patch hygiene.
- **Residue:** the complete static-warning suite and canonical repository
  gate are not run under the user's affected-only verification instruction.
  The unchanged HTML warning and production options implementation are
  outside this test-only diff; the direct test-file command covers the
  touched regression and its existing nine cases.

## Acceptance

1. **New named case in `options.save.test.js`** (P6 section): an
   invalid submit leaves the field value equal to the submitted string
   after drain, alongside the error status and zero storage touches.
2. **No production diff:** `extension/options/options.js` is untouched
   by this ticket (`git diff` names no options.js hunk).
3. **Existing cases untouched:** the seven T056-era cases and two T118
   cases pass unmodified (`git diff` on the file shows only the new
   case + header/comment line if needed).
4. **Runnable:** `node extension/options/options.save.test.js` green with
   all ten cases. The user-authorized verification override limits this
   ticket to the directly changed component plus ticket/status/diff checks;
   broader extension and repository gates are excluded.
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
- Running `options.test.js`, `extension/run-tests.sh`, Java, or
  `scripts/verify.sh` under the explicit affected-only verification
  override.

## Notes

Hand-filed follow-up on 2026-09-06, mirroring the T116/T117/T118 filing
convention. Origin: T118 round-1 verdict (APPROVE-WITH-FIXES, 1 Minor)
finding 1 — the reviewer's EVALUATED-AS grep for the corrected gating
claim passes on the corrected record, but the underlying gap (ungated
must-hold) is real and was explicitly ruled out-of-reach for T118's own
diff by its AC1(c)/AC4.

**Verification evidence (2026-10-10).** Pristine control:
`node extension/options/options.save.test.js` — PASS, 9/9 before the
change. After the change, that command passed 10/10, including the new
named case. M4 non-vacuity: a temporary copy preserved the relative paths of
this test, `options.js`, `options.html`, and `lib/storage.js`; only copied
`options.js` was mutated to clear `input.value` immediately inside the
invalid-token branch. The copied whole test file exited 1 with exactly
`invalidSubmitKeepsTheSubmittedValueInTheField` failing and all nine
existing cases passing (10 total, 9 pass, 1 fail). The temporary
directory was removed. The new assertions and failure messages do not
print the submitted token. The affected-only override excludes broader
tests and `scripts/verify.sh` as directed.
