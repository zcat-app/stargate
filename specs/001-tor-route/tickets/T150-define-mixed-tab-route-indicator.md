---
id: "T150"
title: "Define truthful mixed-tab route indicator semantics"
status: done
created: "2026-09-12"
last_updated: 2026-09-23
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T057", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T057"
tests_first: []
reviews: { round: 2, date: 2026-09-23, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T150: Define truthful mixed-tab route indicator semantics

## Context

Browser Minor m1: the unqualified Route: Tor label reflects the latest subresource; the spec does not define main-document or mixed-tab scope.

## Analysis

- Must hold (III/V): the label identifies only the latest observed main-navigation
  decision, never whole-tab protection or successful transport. Subresources cannot overwrite
  it; unknown/unreadable state cannot claim Tor. Routing descriptors remain unchanged.
- Gated (VII): router/popup tests exercise both mixed-page directions through both cache-writing
  callbacks and the popup consumer, pending/obsolete completions, tab removal and unreadable
  replies. Existing descriptor, per-tab isolation and popup surface tests remain required.
- Residue: Node mocks do not prove real browser delivery order or network outcomes; T157/T155
  retain live enforcement/evidence. Independent review checks wording against Principles III/V
  and the foundation-boundaries contract's truthful-UI section.
- Decision: spec.md §Per-tab indicator scope defines main-navigation-only reporting before
  implementation, with explicit unmeasured subresource coverage and unverified connection success.
  Constitution check: no new traffic, storage, permissions or routing authority; III/V are
  clarified, VII requires red-before-green and VIII requires both independent reviews.

## Acceptance

1. Specify the indicator scope explicitly against Principle V and the existing per-tab acceptance before changing UI behavior.
2. Add direct-main/onion-resource and onion-main/direct-resource cases; require labels matching the selected scope rather than an arbitrary last-request overclaim.
3. Preserve unknown-tab and unreadable-state handling and document that a route decision is not proof of successful tunnel establishment.
4. Run router/popup tests, scripts/verify.sh and both required reviews.

## Out-of-scope

Changing actual routing, or presenting this audit observation as proven direct traffic leakage.

Acceptance 1–3 necessarily updates `extension/popup/popup.test.js`'s historical unqualified
label expectations: recorded routes gain main-navigation scope and the coverage disclaimer;
missing/malformed/unreadable state keeps the no-Tor behavior and now truthfully says Unknown.
`extension/background/router.test.js` adds mixed-resource and stale-decision regressions;
its existing descriptor expectations are unchanged.

## Notes

T150 regression evidence (2026-09-23): `node --test extension/background/router.test.js
extension/popup/popup.test.js` ran 46 tests before implementation: 26 passed, 20 failed.
The failures included both mixed-page directions through both callbacks, subresource-only
unknown tabs, late main decisions after newer navigation/tab removal, scoped labels and stale
popup replies. After implementation all 46 passed, with zero skips. Raw outputs are retained
locally in `target/runs/T150.red.log` and `target/runs/T150.green.log` (gitignored).

Round-1 Astra Major closure: `pendingMainNavigationClearsExistingTor-{proxy,webRequest}`
first establishes Tor, suspends a replacement HMAC, queries the actual background responder
for Unknown while pending, then releases and checks the replacement Tor result. Both tests
fail when `current.route` is mutated to retain the previous entry's route; after restoring
the unchanged production implementation all 48 router/popup tests pass with zero skips.
Local evidence: `target/runs/T150.round2-mutation.log` and `T150.round2-green.log`.
This is additional mutation-backed coverage of the existing guard, not new production behavior.

Round-1 GLM Minor follow-up: update the current operator quickstart's Step 6
(`specs/001-tor-route/quickstart.md:203`) and any live label quotations to the scoped wording.
Its retired `Route: Tor` quotation remains a documentation inconsistency; this follow-up is
recorded rather than expanding the eight-file implementation budget. No privacy guarantee
or runtime finding is accepted or waived by that deferral.

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
