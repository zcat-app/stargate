---
id: T034g
title: 'T034d follow-up: assert surface exclusivity in `firstparty.tes'
status: pending
created: 2026-09-03
last_updated: 2026-09-03
source: specs/001-tor-route/tickets/T034d-unit-test-for-extensionlibfirstpartyjs-p.md (T034d round-1 review RECOMMENDED-FOLLOW-UP; not a tasks.md line)
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T034d]   # extends the suite T034d authored; T053 must be gated
                      # by the extended gate, so this lands before T053
parallel: true
files_budget: 4   # 1 code file edit + this ticket + STATUS.md regen
privacy_critical: true   # strengthens a Principle-VII gate over FR-002's
                         # surface; same rationale as T034d's flip
complexity: low
risk: low
round_cap: 2
test_for: []   # not an impl-gating suite; it IS an edit to T034d's suite,
               # authorized by T034d §Acceptance 6's refine path (the
               # finding is recorded in T034d's round-1 verdict file)
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code (the gate must pin what the ticket claims it pins)"
  - "VI: Open and Auditable (the background-page global scope is shared across classic scripts — an unpinned extra global is an unauditable collision surface)"
spec_refs:
  - "specs/001-tor-route/tickets/T034d-unit-test-for-extensionlibfirstpartyjs-p.md §Analysis \"Pinned surface\" (\"exactly one new global\" — the clause this ticket makes mechanically enforced)"
  - "specs/001-tor-route/spec.md §FR-002 (the surface the gate protects)"
decision_refs:
  - "target/runs/T034d.verdict (T034d round-1 APPROVE; FINDINGS[1] Minor — the pin-vs-mechanics gap this ticket closes; RECOMMENDED-FOLLOW-UP names the probe)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
out_of_scope:
  - extension/lib/firstparty.js
  - any behavioural change to the eight existing cases
---

# T034g: T034d follow-up — assert surface exclusivity in `firstparty.test.js` conformance gate

## Context

T034d's round-1 review APPROVED with one Minor finding: the pinned-surface
clause "exposes exactly one new global" (`firstPartyDomain`) is asserted
nowhere — `requireConformance()` checks only that the global is present
and a function, so a T053 implementation that leaks extra top-level
globals passes the suite green. That gap is MV2-real: `lib/firstparty.js`,
`background/router.js`, `background/hardening.js`, and `lib/storage.js`
all load as classic scripts into ONE background-page global scope, so an
extra top-level `var` is a namespace-collision surface the ticket claims
(per its §Analysis pin) to gate and does not. T053 is barred from editing
the test (T034d §Acceptance 6), so the fix cannot ride T053; it is this
micro-ticket.

> **Verdict finding (verbatim, T034d round 1):**
>
> [Minor] extension/lib/firstparty.test.js:91-101 — requireConformance
> asserts only `typeof sandbox.firstPartyDomain === 'function'`
> (presence), but the ticket §Analysis "Pinned surface" pins the module
> as exposing "exactly one new global"; an impl that leaks extra
> top-level globals passes the suite green.

## Acceptance

1. `requireConformance()` in `extension/lib/firstparty.test.js` — after
   the existing `firstPartyDomain` presence assertion — also asserts
   surface exclusivity: `Object.keys(sandbox)` filtered to remove the
   three seeded globals (`browser`, `URL`, `console`) deep-equals exactly
   `['firstPartyDomain']` (order-insensitive deep-equal on the filtered
   list; a set-comparison is equally acceptable). On violation it
   hard-FAILS naming expected-vs-actual, in the register of the existing
   conformance message.
2. Every existing case flows through `requireConformance()`, so the new
   assertion lifts automatically with the existing skip mechanics —
   pre-T053 the suite stays GREEN (8 skips), no skip logic changes.
3. Falsification probe (must be recorded in the ticket's Falsification
   record before commit): with a conforming reference stub, the suite
   passes 8/8; appending `var helperGlobal = function () { return 1; };`
   to the stub must flip EVERY case to failure via the exclusivity
   assertion (the probe mutation from the T034d verdict, M6), while all
   other T034d-recorded mutations keep tripping their named cases.
4. No behavioural change to the eight existing cases; no new file; no
   `package.json`; the Apache-2.0 SPDX header stays;
   `scripts/verify.sh` green from repo root.

## Out-of-scope

- `extension/lib/firstparty.js` (T053's artifact) and any other
  extension source.
- Re-litigating the pinned surface itself — if exclusivity turns out to
  be unhostable for T053's design, that is a refine escalation against
  **T034d** (its §Analysis is the authorization boundary), not a silent
  weakening here.
- The other seeded-global names (`browser`, `URL`, `console`) — pinned
  by T034d §Analysis; not adjustable here.

## Notes

Filed 2026-09-03 from T034d's round-1 verdict (APPROVE, 1 Minor,
RECOMMENDED-FOLLOW-UP) per the follow-up-don't-expand doctrine
(CONTRIBUTING.md). Lands before T053 so T053 is gated by the exclusivity
assertion from its first verify run.
