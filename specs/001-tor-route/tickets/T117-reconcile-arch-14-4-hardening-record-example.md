---
id: T117
title: 'Reconcile arch §14.4 hardening-record example with T091'
status: pending
created: 2026-09-06
last_updated: 2026-09-06
source: target/runs/T055-r1.verdict RECOMMENDED-FOLLOW-UP (T055 round-1 APPROVE, 0 findings)
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: '-'
blocked_by: []
parallel: true
files_budget: 4   # specs/000-architecture/spec.md + this ticket + STATUS.md
privacy_critical: false   # doc-only reconciliation; the authoritative §14.5
                          # boundary is already correct and untouched
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/000-architecture/spec.md §14.4 (the stale `hardening.lastAuditResult` example, line ~963)"
  - "specs/000-architecture/spec.md §14.5 (the amended enforcement boundary + failure UX item 3 the example must match)"
constitution_refs:
  - "V: Honest Threat Model (an illustrative layout claiming DoH/HTTP-3 audit fields implies a runtime capability the amended boundary forbids claiming)"
decision_refs:
  - "specs/001-tor-route/tickets/T091-amend-browser-hardening-boundary.md (the amendment that made the §14.4 example stale)"
  - "specs/001-tor-route/tickets/T055-author-extensionbackgroundhardeningjs.md (the shipped record shape: hardening.{lastAuditedAt, lastAuditResult:{blockedSurface, pref, readError}})"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T117: Reconcile arch §14.4 storage-layout example with the T091-amended hardening record

## Context

T091 amended the enforcement boundary (arch §14.5, Constitution III bullet 3)
but left the §14.4 `storage.local` layout example showing the pre-T091
hardening record: `"lastAuditResult": { "doh": "disabled", "webrtc":
"disabled", "h3": "disabled" }` (specs/000-architecture/spec.md ~line 963).
That shape implies runtime DoH/HTTP-3 audit state the stable WebExtensions
API cannot read — exactly the false-assurance class T091 removed. T055
shipped the real record (`blockedSurface`, `pref`, `readError` beside
`lastAuditedAt`); T055's round-1 review APPROVED with this doc-only
reconciliation as RECOMMENDED-FOLLOW-UP.

## Acceptance

1. The §14.4 `hardening` example block shows the shipped record shape —
   `hardening.{lastAuditedAt: <hourBucket>, lastAuditResult:
   {blockedSurface, pref, readError}}` — or wording the reviewer accepts as
   equivalent, with no field implying runtime DoH/DoT/HTTP-3 state.
2. No other §14.4 (or adjacent) text is modified beyond what the
   reconciliation requires; §14.5 is untouched (it is authoritative and
   correct).
3. `python3 scripts/lint-ticket.py` clean on this ticket; `scripts/verify.sh`
   green from repo root (doc-only diff — code gates self-detect SKIP).

## Out-of-scope

- Any change to `extension/**`, THREAT-MODEL.md, or spec §14.5.
- Re-litigating the record's internal schema (T034b §Analysis residue pins
  it to T055's choice; the admin-dashboard consumer is a future flow).

## Notes

Filed 2026-09-06 from T055's round-1 verdict RECOMMENDED-FOLLOW-UP per the
follow-up-don't-expand doctrine (CONTRIBUTING.md). Doc-only; can run any
time.
