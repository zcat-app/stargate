---
id: T118
title: 'Clear the bearer-token field after a successful save'
status: pending
created: 2026-09-06
last_updated: 2026-09-06
source: target/runs/T056.verdict RECOMMENDED-FOLLOW-UP (T056 round-1 APPROVE, 0 findings)
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: []   # T056 is done
parallel: true
files_budget: 4   # raw-diff-path counting (run-task.sh): options.js +
                  # options.save.test.js + this ticket + STATUS.md regen;
                  # specs/ paths are excluded from the budget
privacy_critical: true   # touches the credential surface (the options page
                         # is the edge where pasted input becomes the stored
                         # token); Constitution VII applies
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §FR-019 (the options-page UX this hardens — FR-019 is spec-SILENT on field clearing, so options.save.test.js remains the machine side of the coupling, T034c label precedent)"
  - "specs/001-tor-route/data-model.md §5 (validation shape `^[0-9a-f]{32}$` and the device schema — unchanged by this ticket)"
  - "specs/001-tor-route/quickstart.md §Step 4 (operator prose: paste → Save — no drift; the cleared field does not contradict it)"
constitution_refs:
  - "V: Honest Threat Model (bound the on-screen lifetime of the pasted secret; the §5.1 warning discloses the strictly stronger on-disk exposure, but the rendered field is an avoidable residual)"
  - "VII: Tests-First for Privacy-Critical and Contract Code (new cases authored FIRST in options.save.test.js, RED before the impl change — T056/router.test.js precedent)"
decision_refs:
  - "specs/001-tor-route/tickets/T056-author-extensionoptionsoptionshtml-and-e.md (the shipped save flow this ticket amends; §Residue 'no configured-state display' is a SEPARATE decision — this ticket does not add read-back)"
  - "target/runs/T056.verdict (RECOMMENDED-FOLLOW-UP origin; reviewer's falsified-and-dropped entry for the shoulder-surf concern is superseded by filing: the human opted to track it)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T118: Clear the bearer-token field after a successful save

## Context

T056's options page leaves the pasted token rendered in `#bearer-token`
indefinitely after a successful save. The §5.1 warning discloses the
on-disk exposure (any local process with profile-directory read access),
but the still-rendered field is an avoidable residual: a shoulder-surf /
screen-share window on the exact secret, bounded by nothing. T056's
round-1 review APPROVED with this as RECOMMENDED-FOLLOW-UP ("spec-silent
today — would need a spec/ticket owner, not a code drive-by"); this ticket
is that owner.

## Analysis

Quick-to-medium pass (privacy-critical by surface, trivial by mechanics —
property map per `docs/process/analysis.md`).

Design constraints pinned up front:

- **Clear ONLY on a resolved save.** The failure path MUST preserve the
  input: a user whose write failed must be able to retry without
  retyping a 32-char token (and the failure status must stay accurate).
  The invalid path already preserves it (T056 suite case (b) pins zero
  storage touches; the field is untouched there).
- **No read-back, still.** Clearing must not grow into displaying whether
  a token is configured — T056 §Analysis decision 7 (no prefill / no
  state UI) stands; the popup (T057) / connectivity (T034f) carry that
  signal.
- **Timing:** clear in the same resolution branch that renders
  `SAVED_MESSAGE` — never before the write resolves (a cleared field
  paired with a failure status would be a lying UI).

- **Must hold:**
  - After a valid save whose storage write RESOLVES: `#bearer-token`
    value is `''` and the status is the saved message — both observable
    in the same drained turn (T056 suite harness).
  - After a valid save whose storage write REJECTS: the field still
    holds the typed token (retryable) and the status is the failure
    message — never cleared, never saved.
  - Invalid input: field value unchanged, zero storage touches
    (existing T056 case (b) must stay green unmodified).
  - Zero new globals / surface unchanged (existing T056 case (a) and
    surface-flow case stay green unmodified).
- **Gated:**
  - New named cases in `extension/options/options.save.test.js`,
    authored FIRST and RED before the impl edit (Constitution VII;
    same-commit as impl per the T056 precedent), executed fail-closed by
    verify.sh Gate 2b.
  - The frozen T034e suite and the canonical §5.1 string are untouched
    (byte-exact gate must stay green unmodified).
- **Residue:**
  - The token remains visible between paste and Save — inherent to a
    paste-affordance UX (the user must be able to verify what they
    pasted); unfixable without dropping paste verification, not attempted.
  - `type="password"` masking is a DIFFERENT mitigation (dots the field
    during entry) — deliberately out of scope here; mask-vs-verify is a
    UX trade this ticket does not settle.
  - A screen-scraping process can read the field mid-edit regardless —
    THREAT-MODEL §2.8 OS-level attacker, out of scope.

## Acceptance

1. **New named cases in `options.save.test.js`, authored FIRST and RED
   before the impl edit:** (a) valid save → after drain, input value is
   `''` AND status is the saved message; (b) storage-rejection save →
   after drain, input value STILL equals the typed token and status is
   the failure message; (c) the existing T056 cases (a)–(g) pass
   UNMODIFIED (surface, fail-closed matrix, merge, fresh-profile,
   failure status, surface-flow, html wiring).
2. **`options.js` implements the clear** in the write-resolved branch
   only; diff confined to the `try` block's success path (plus nothing
   else — surgical).
3. **Runnable:** `node extension/options/options.save.test.js` green
   with the new cases; `sh extension/run-tests.sh` exits 0;
   `bash scripts/verify.sh` green from repo root.
4. **Diff scope:** `extension/options/options.js`,
   `extension/options/options.save.test.js` (new cases only — no edits
   to the T056-era cases' assertions), this ticket's status edits,
   STATUS regen. NO edit to `options.html`, `options.test.js` (frozen
   T034e), `lib/storage.js`, quickstart, or data-model.
5. **Falsification record** (§Notes): the new cases are exercised
   against impl mutations — clear moved to the failure branch (case b
   fails: field emptied on a failed write), clear moved before the
   `await` (case b fails via the rejection probe), clear dropped
   entirely (case a fails).

## Out-of-scope

- `type="password"` masking (§Analysis residue — a separate UX decision).
- Any configured-state display or prefill (T056 §Analysis decision 7
  stands).
- Clipboard-clear timers / password-manager integration (research.md §6
  rejected the credential-API alternatives for v1).
- Popup (T057), canonical warning string, either markdown replica
  (amend path only).
- The storage wrapper (T052) — the clear is page-scope only; the stored
  token is of course untouched by it.

## Notes

Hand-filed follow-up on 2026-09-06 (not a tasks.md entry), mirroring the
T116/T117 filing convention. Origin: T056 round-1 verdict (APPROVE,
0 findings) RECOMMENDED-FOLLOW-UP; the reviewer had dropped the
shoulder-surf concern as "no contract basis" under then-current scope —
filing it gives it the owner the reviewer required.
