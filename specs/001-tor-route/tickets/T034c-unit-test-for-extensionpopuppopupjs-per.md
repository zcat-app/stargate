---
id: T034c
title: 'Unit test for `extension/popup/popup.js` per-tab indicator (Principle '
status: done
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T034c
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # T096/M6: no inverted dep on T057 — the test must NOT wait on its impl (Constitution VII)
parallel: true
files_budget: 8   # raw-diff-path counting (run-task.sh): 1 code file + this
                  # ticket + T057 dep-link edit + STATUS.md regen; ticket-template.md excludes
                  # specs/ paths from the budget
privacy_critical: true
complexity: low
risk: low
round_cap: 2
test_for: [T057]   # reverse view: the impl ticket this suite gates (T057
                   # carries tests_first: [T034c] + blocked_by: [T009, T034c])
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code"
spec_refs:
  - "specs/001-tor-route/tasks.md §Tests for User Story 1, T034c (cases (a)–(d); the canonical-label coupling: 'drift between them and T034c's assertions fails CI')"
  - "specs/001-tor-route/tasks.md §Tests for User Story 1, T057 (the pinned impl surface: 'per-tab indicator reading the routing decision from webRequest.onBeforeRequest cache for the active tab'; the two canonical label strings)"
  - "specs/001-tor-route/spec.md §User Story 1, acceptance scenario 1 ('the extension's per-tab indicator shows route = Tor' — the indicator is how the privacy property is observable; wrong-label drift makes it invisible)"
  - "specs/001-tor-route/quickstart.md §Step 6 ('The Stargate popup icon should show **Route: Tor** for this tab' — operator-facing corroboration of the Tor label)"
  - "specs/001-tor-route/research.md §2 (Manifest V2 pin — grounds the popup↔background transport decision: no storage.session in MV2)"
  - "specs/001-tor-route/research.md §10 (Node 20 LTS CI pin; node:test + node:assert; no third-party JS deps, no package.json)"
decision_refs:
  - "specs/001-tor-route/tickets/T034b-unit-test-for-extensionbackgroundhardeni.md (the direct extension-plane precedent: access-recording mock, self-skip-then-bite, apiReadFailureFailsClosedWithoutThrowing; round-1 APPROVE)"
  - "specs/001-tor-route/tickets/T034d-unit-test-for-extensionlibfirstpartyjs-pure.md (pinned-surface conformance-gate precedent: present-but-nonconforming is a hard FAIL, never a silent re-skip; round-1 APPROVE + T034g exclusivity follow-up)"
  - "specs/001-tor-route/tickets/T034e-unit-test-for-the-canonical-storagelocal.md (the M6 structural-dep precedent this ticket copies onto T057: tests_first + blocked_by, 'removed inverted dep — the test must NOT wait on its impl'; round-1 APPROVE)"
reviews: { round: 1, date: 2026-09-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T034c: Unit test for `extension/popup/popup.js` per-tab indicator (Principle 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `extension/popup/popup.js` per-tab indicator (Principle VII for routing-decision *display* logic; the indicator is how US1 acceptance scenario 1's "extension's per-tab indicator shows route = Tor" is observable to the user — wrong-label drift would make the privacy property invisible). Same `vm.runInNewContext()` + handwritten `browser` mock pattern as T034b (no third-party JS deps). Cases:

## Analysis

Property map (grounding-verified 2026-09-03; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (three body-vs-reality
items; method per T035a/T034b/T034e §Analysis):**

1. **The popup↔cache transport is designed nowhere in the spec set —
   this ticket pins it.** tasks.md T057 says the indicator reads "the
   routing decision from `webRequest.onBeforeRequest` cache for the
   active tab", but no spec text names how a popup document reaches that
   cache. Ground truth constrains it: the extension is Manifest V2
   (research.md §2, arch §15 #6) and MV2 has no `storage.session`; the
   cache is background-page memory written by the router's
   `onBeforeRequest` listener (T054 side); and the popup is a *separate
   document* that cannot read another document's memory. The only MV2
   one-shot transport is `browser.runtime.sendMessage`. Pinned protocol
   (the popup's contract — cache internals stay T054/T057's):
   `runtime.sendMessage({ type: 'stargate:getRoute', tabId })`; the
   background replies `{ route: 'tor' }` **iff** its cache holds a
   confirmed Tor decision for that tab, and replies nothing meaningful
   otherwise (no reply / `undefined` = no confirmed decision — exactly
   the cold-start state of case (d)).
2. **"Active tab URL is `https://*.onion/...` → `Route: Tor`" (case a)
   is operationalized cache-driven, not URL-derived.** The popup must
   never re-derive routing from the tab URL: T054's background decision
   is the single routing authority, and a URL-parroting popup is a second
   source of truth that can disagree with it (and would show "Tor" for an
   onion URL opened while routing is blocked/hardening-failed — the
   wrong-positive case (d) forbids). In the mock, case (a) is realized
   the way the real system realizes it: an onion tab the router actually
   routed has a cache entry, so the background answers `{route:'tor'}`.
   The URL is what *made* the decision exist — it is not what the popup
   reads.
3. **popup.js is T057's artifact (tests-first):** the suite self-skips
   with a loud Principle-VII marker while `extension/popup/popup.js` is
   absent, and the conformance gate bites the moment it lands
   (T068a/T034b/T034e precedent). The structural ordering dep this
   ticket adds to T057 (M6): `tests_first: [T034c]` +
   `blocked_by: [T009, T034c]`, and the failing-test signal is never
   bundled with the implementation in one commit (tasks.md §"Notes").

**Pinned surface (the ONLY surface assumptions on T057):**

- `extension/popup/popup.js` evaluates as a classic script at popup open
  and renders at load — no exported global is required; the script is
  self-contained (**zero new context globals**: a top-level `var` /
  function / assignment is a conformance FAIL, same exclusivity doctrine
  T034g added to T034d).
- DOM contract: the label is written to `document.
  getElementById('route-indicator').textContent` — the single canonical
  element id `popup.html` must provide, written via `textContent` (the
  injection-safe write; `innerHTML` on a document whose content the test
  treats as text would be a script-insertion surface). Unline T034e
  (static text, "no element id pinned"), a JS-rendered label needs a DOM
  anchor — the id is that anchor, and the id-coupling residue is
  promoted to a gate (see Residue → `popupHtmlProvidesPinnedIndicatorElement`).
- browser surfaces touched: `tabs.query`, `tabs.onUpdated.addListener`,
  `runtime.sendMessage` — nothing else. `tabs.query` must select the
  active tab of the current window (options carrying `active: true` and
  `currentWindow: true`) — that is the per-tab binding made concrete. The
  popup originates no network I/O and no storage/notifications/proxy/
  privacy access (display-only; routing authority is the background).
- Canonical labels, byte-exact: `Route: Tor` and
  `Route: Direct (unrouted)`. Their only normative source is the
  tasks.md T057/T034c pair itself (no data-model § pins them — unlike
  T034e's warning text), so the suite hard-codes both strings citing
  tasks.md T057, and the CI coupling is bidirectional by construction.

- **Must hold:**
  - **Fail-closed display mapping:** the label is `Route: Tor` **iff**
    the live reply for the active tab is an object with
    `route === 'tor'`; every other reply — `undefined`, `null`, `{}`,
    unknown route values, a rejected `sendMessage` promise — renders
    `Route: Direct (unrouted)`. Direction of harm is asymmetric:
    a wrong-positive tells the user they're routed when they aren't
    (case (d)'s stated failure), a wrong-negative is visible annoyance.
  - **Byte-exact canonical labels** (both strings; spec scenario 1
    observability + T057 CI coupling).
  - **Per-tab binding:** the decision is requested for — and only for —
    the active tab's id; `tabs.onUpdated` for a *non-active* tab never
    re-renders (cross-tab bleed would show Tor while the active tab is
    clearnet — the same wrong-positive, reached sideways).
  - **Live re-ask, both navigation directions (case (c)):**
    `tabs.onUpdated` on the active tab triggers a fresh `tabs.query` +
    `sendMessage` + re-render — never a render from remembered state.
    Onion→clearnet must clear a stale `Route: Tor`; clearnet→onion must
    *show* `Route: Tor` (a blind "flip to Direct on any event" impl
    passes the first and fails the second — that mirror is the
    falsifier).
  - **Render-at-load with zero new globals** (self-contained classic
    script; no `DOMContentLoaded` dependency — `popup.html` loads it at
    body end / `defer`, T057's concern).
  - **Display-only surface:** recorded browser touches ⊆ {`tabs.query`,
    `tabs.onUpdated.addListener`, `runtime.sendMessage`}; DOM lookups
    only for `route-indicator`; element writes only to `textContent`;
    any `storage`/`notifications`/`proxy`/`privacy` touch fails.
  - **Principle VII:** every must-hold above has a named test in
    §Acceptance.
- **Gated:**
  - The suite itself is the gate for all must-holds: `verify.sh` Gate 2b
    executes `extension/run-tests.sh`, whose discovery glob
    (`find . -name '*.test.js' -not -path './dist/*'`) already reaches
    `popup/` — no runner amendment (verified on disk).
  - `scripts/check-license-headers.sh` gates the SPDX header.
  - Pre-commit secret scanner gates fixture hygiene (the plausible-v3
    onion fixture is syntactic only, same as T034d's).
  - `scripts/lint-ticket.py` gates ticket well-formedness; the
    `tests_first`/`blocked_by` M6 cross-check gates the T057 ordering
    dep mechanically.
- **Residue** (documented, not silently dropped):
  - **popup.html ↔ popup.js id coupling:** the JS side is gated by the
    conformance gate from the moment popup.js lands; the HTML side can
    only be gated once `popup.html` exists. **Promoted to a gate in this
    ticket:** `popupHtmlProvidesPinnedIndicatorElement` self-skips until
    popup.html exists, then asserts it provides `id="route-indicator"` —
    after T057 lands, id drift is CI-caught in both directions.
  - **The background's `onMessage` responder** (the cache-read side of
    the pinned protocol) is T054/T057 wiring — no unit gate here; the
    mock defines the protocol both sides must implement. End-to-end
    label truth is T033/T034f/SC-003's.
  - **Visual placement/styling of the indicator is unpinned** (T057
    review concern; the privacy property is the label string, not the
    layout).
  - **No debounce/throttle pin:** each `onUpdated` event re-asks the
    cache; a rapid-navigation burst yields a burst of read-only queries.
    Harmless (no side effects), and popup lifetime is short; performance
    is T079's.

## Acceptance

Runnable via `sh extension/run-tests.sh` (verify.sh Gate 2b). Test-first
state: green **now** via loud self-skips naming the T057 gate they lift
for; every assertion bites inside T057's own verify run. Each case is a
separate named test (tasks.md §"Notes": never bundle the failing signal
with the implementation).

1. **`onionActiveTabShowsExactTorLabel`** (body case (a)): active tab
   `https://<onion>/page`, background answers `{route:'tor'}` →
   `#route-indicator` textContent is exactly `Route: Tor`.
2. **`clearnetActiveTabShowsExactUnroutedLabel`** (body case (b)):
   active tab `https://example.com/page`, background answers a
   non-Tor decision record `{route:'unrouted'}` → exactly
   `Route: Direct (unrouted)`.
3. **`sameTabOnionToClearnetNavigationClearsStaleTorLabel`** (body case
   (c)): start routed (`Route: Tor`), fire the registered
   `tabs.onUpdated` listener for the same tabId with a clearnet URL and
   an emptied cache answer → exactly `Route: Direct (unrouted)`, and a
   fresh `stargate:getRoute` message was sent (the stale answer was not
   reused — re-ask, then render).
4. **`sameTabClearnetToOnionNavigationShowsTorOnFreshCacheAnswer`**
   (case (c) falsifier mirror): start unrouted, fire `tabs.onUpdated`
   with an onion URL and a now-present cache answer → exactly
   `Route: Tor` via a fresh message (a blind flip-to-Direct impl fails
   here).
5. **`coldStartEmptyCacheShowsExactUnroutedLabel`** (body case (d)):
   background replies `undefined` (empty cache) → exactly
   `Route: Direct (unrouted)` — `Route: Tor` requires a confirmed
   decision.
6. **`nonTorRepliesNeverRenderTorLabel`** (must-hold fail-closed matrix):
   replies `undefined`, `null`, `{}`, `{route:'unrouted'}`,
   `{route:'direct'}`, `{route:'TOR'}` all render exactly
   `Route: Direct (unrouted)`.
7. **`sendMessageFailureRendersUnroutedWithoutThrowing`** (residue-
   derived; T034b `apiReadFailureFailsClosedWithoutThrowing` precedent):
   a rejected `sendMessage` (background page gone/reloading) renders
   exactly `Route: Direct (unrouted)` — no unhandled rejection, never
   `Route: Tor`.
8. **`backgroundTabUpdateNeverRerendersActiveIndicator`** (per-tab
   binding): `tabs.onUpdated` for a non-active tabId → the active tab's
   label is unchanged (cross-tab bleed guard). The contract is the
   rendered label, not the ask strategy: filtering events by tabId and
   re-asking on every event are both conforming.
9. **`popupTouchesOnlyPinnedBrowserSurfaces`** (display-only surface):
   across every flow above, recorded browser touches ⊆
   {`tabs.query`, `tabs.onUpdated.addListener`, `runtime.sendMessage`},
   DOM lookups only for `route-indicator`, writes only to `textContent`,
   and the sandbox gains zero new globals (pinned-surface conformance
   gate, hard-FAIL when popup.js exists but deviates — T034d/T034g
   doctrine).
10. **`popupHtmlProvidesPinnedIndicatorElement`** (Residue promotion,
    self-skipping in this commit): while `extension/popup/popup.html` is
    absent it skips loudly naming the T057 gate; once present, it must
    provide `id="route-indicator"` (present-but-drifted is a hard FAIL).

## Out-of-scope

- Authoring `popup.html` / `popup.js` (T057) and the background
  `onMessage` responder / cache wiring (T054/T057 side of the pinned
  protocol).
- Real-browser label verification (T033/T034f integration; SC-003 hand
  measurement T034a).
- Indicator placement/styling; popup performance under navigation
  bursts (T079).
- Any change to the canonical label strings — that is a tasks.md/
  spec.md amendment, never a test edit.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
