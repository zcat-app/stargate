---
id: T057
title: 'Author `extension/popup/popup.html` and `extension/popup/popup.js`'
status: done
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T057
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T034c]   # T034c added 2026-09-03 per T096/M6 (T034e precedent):
                            # the Principle-VII test gates this impl
parallel: false
files_budget: 4   # tightened at /start (was 8 TODO): raw-diff-path counting per
                  # T116 convention — 2 code files + this ticket + STATUS regen
privacy_critical: true
complexity: low
risk: low
round_cap: 2
tests_first: [T034c]   # the popup.test.js suite that self-skips until this ticket lands
spec_refs:
  - "specs/001-tor-route/spec.md §US1 Acceptance Scenario 1 (the indicator is how 'the extension's per-tab indicator shows route = Tor' is observable to the user)"
  - "specs/001-tor-route/tasks.md §T057 (the two canonical label strings; 'drift between them and T034c's assertions fails CI')"
  - "specs/001-tor-route/research.md §2 (MV2 decision: no storage.session; the onBeforeRequest cache is background-page memory a separate popup document cannot read — the sendMessage transport is forced, not chosen)"
  - "specs/001-tor-route/quickstart.md §Step 6 (operator-facing prose corroborating the Tor label: 'The Stargate popup icon should show Route: Tor for this tab')"
decision_refs:
  - "specs/001-tor-route/tickets/T034c-unit-test-for-extensionpopuppopupjs-per.md (the Principle-VII gate that lifts here; §'Pinned surface (the ONLY surface assumptions on T057)' is the executable spec for this ticket)"
  - "specs/001-tor-route/tickets/T056-author-extensionoptionsoptionshtml-and-e.md (sibling page-surface impl precedent: landed-gate lift + own falsification battery in §Notes; round-1 APPROVE)"
  - "extension/background/router.js (T054, done — the background half of the pinned protocol already exists: the onBeforeRequest tabDecisions cache and the runtime.onMessage responder the popup queries)"
reviews: { round: 1, date: 2026-09-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T057: Author `extension/popup/popup.html` and `extension/popup/popup.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/popup/popup.html` and `extension/popup/popup.js` — per-tab indicator reading the routing decision from `webRequest.onBeforeRequest` cache for the active tab; surfaces the literal string `Route: Tor` for `.onion` tabs and `Route: Direct (unrouted)` for everything else (these two strings are the canonical labels; drift between them and T034c's assertions fails CI). **Verified by T034c.**

## Analysis

Property map (grounding-verified 2026-09-06; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (body-vs-reality; T056
method):**

1. **The gate already exists and is loud:** T034c (done) landed
   `extension/popup/popup.test.js` — 10 named cases that self-skip until
   popup.js / popup.html exist ("bites inside T057's own verify run").
   Its §"Pinned surface (the ONLY surface assumptions on T057)" is the
   executable spec for this ticket: the DOM anchor `route-indicator`,
   the three browser surfaces, the fail-closed display mapping, the
   live re-ask, and the byte-exact labels. No surface assumption beyond
   those is made anywhere; everything below conforms to it.
2. **The background half already exists:** router.js (T054, done) ships
   BOTH protocol sides the popup depends on — the
   `webRequest.onBeforeRequest` `tabDecisions` cache and the
   `runtime.onMessage` responder answering `{route:'tor'}` /
   `{route:'unrouted'}` / `undefined` via Promise return. This ticket is
   the ask-and-render side ONLY; the diff never touches router.js.
3. **Manifest never changes:** manifest.json (T051) already registers
   `browser_action.default_popup = 'popup/popup.html'`; manifest.test.js
   gates the registration. The sibling-ticket convention holds — no
   manifest edit here.
4. **The transport is forced, not chosen** (research.md §2; T034c
   §Analysis finding 1): MV2 has no `storage.session`, and the
   `onBeforeRequest` cache is background-page memory a separate popup
   document cannot read — so `runtime.sendMessage({type:'stargate:getRoute',
   tabId})` is the only truthful channel. The popup never derives
   routing from the tab URL: a client-side `.onion` check would
   duplicate router.js's rule (host normalization, hardening gate,
   token presence) in a second authority that can silently disagree —
   the label must show the background's *decision*, not a guess.
5. **Page-script idiom (T034c conformance gate):** popup.js is a
   classic script evaluating in its own popup document — zero new
   context globals (one named IIFE, router.js/options.js style), no
   `DOMContentLoaded` dependency (popup.html loads it at body end, so
   the anchor element exists at eval), DOM lookups only
   `route-indicator`, writes via `textContent` only (the
   injection-safe write). Renders at load: one `tabs.query` +
   `sendMessage` + render chain kicked off at eval.
6. **Fail-closed display mapping (Constitution V):** the label is
   `Route: Tor` **iff** the live reply is an object with
   `route === 'tor'`; every absent, malformed, unknown, or failed
   answer renders `Route: Direct (unrouted)`. Harm is asymmetric: a
   wrong-positive tells the user they are routed when they are not
   (case (d)'s stated failure); a wrong-negative is visible annoyance.
7. **Per-tab binding and the foreign-tab event:** the ask names the id
   from `tabs.query({active:true, currentWindow:true})` — never an id
   taken from the `onUpdated` event itself. For a foreign-tab event the
   T034c contract is the rendered label, and either allowed strategy
   (filter by tabId, or re-ask and render the active tab's own answer)
   satisfies it; this ticket takes **re-ask** — one code path, one
   listener, and the label can never be a remembered answer.
8. **Initial markup renders nothing:** `#route-indicator` ships empty.
   Putting `Route: Direct (unrouted)` in the HTML would create an
   ungated second replica of a canonical string (only the JS-rendered
   write is gated, and the suite is the labels' machine side); an empty
   indicator before the first render is not a wrong-positive — it is
   not a claim at all.
9. **No secrets:** the popup carries no token material — the ask is
   `{type, tabId}` only; gitleaks fixture hygiene is inherited from the
   landed suite (syntactic onion fixture, T034d style).

**Pinned surface:** `popup.html` provides exactly one element by id —
`route-indicator` — and loads exactly one external script, `popup.js`,
at body end (MV2 CSP forbids inline scripts/handlers). `popup.js`
contributes zero new globals; registers exactly one `tabs.onUpdated`
listener; touches only `tabs.query`, `tabs.onUpdated.addListener`,
`runtime.sendMessage`; sends exactly `{type:'stargate:getRoute', tabId}`;
looks up only `route-indicator`; writes only `textContent`.

- **Must hold:**
  - Fail-closed display mapping: `Route: Tor` iff the live reply for
    the active tab is an object with `route === 'tor'`; `undefined`,
    `null`, `{}`, unknown route values, and a rejected `sendMessage`
    all render `Route: Direct (unrouted)` — never an unhandled
    rejection on the popup document (T034c §Analysis must-hold 1).
  - Byte-exact canonical labels — both strings (tasks.md T057; the
    T034c suite is the machine side of the coupling; quickstart Step 6
    corroborates the Tor label in operator prose).
  - Per-tab binding: the decision is requested for — and only for —
    the active tab's id from `tabs.query({active:true,currentWindow:
    true})`; the popup originates no URL-based routing decision of its
    own (grounding finding 4).
  - Live re-ask, both navigation directions (case (c) + its mirror):
    `tabs.onUpdated` triggers a fresh query + ask + render — never a
    render from remembered state; onion→clearnet clears a stale
    `Route: Tor`, clearnet→onion shows `Route: Tor` from the fresh
    answer.
  - Cross-tab isolation: a foreign tab's `onUpdated` never moves the
    active tab's indicator away from its own live answer (the
    wrong-positive reached sideways).
  - Display-only surface: recorded browser touches ⊆ {`tabs.query`,
    `tabs.onUpdated.addListener`, `runtime.sendMessage`}; DOM lookups
    only `route-indicator`; writes only `textContent`; exactly one
    `onUpdated` listener; zero new context globals (T034g namespace
    doctrine; T034c §Analysis "Pinned surface").
  - `popup.html` provides `id="route-indicator"` and wires `popup.js`
    as an external script at body end — id drift fails CI in both
    directions (the promoted `popupHtmlProvidesPinnedIndicatorElement`
    gate lifts in this commit).
- **Gated:**
  - All must-holds above are gated by the LANDED T034c suite's named
    cases — they lift from loud self-skips to PASS inside this
    commit's verify run (verify.sh Gate 2b via `extension/run-tests.sh`
    discovery; no runner amendment needed, verified on disk). This is
    the Principle-VII state: the test exists, is loud-red as a skip,
    and cannot be edited by this ticket (§Acceptance diff scope).
  - `scripts/check-license-headers.sh` gates the SPDX headers.
  - Pre-commit gitleaks gates the no-secrets property (finding 9).
  - `scripts/lint-ticket.py` gates ticket well-formedness;
    manifest.test.js gates the `default_popup` registration that makes
    these two files loadable.
- **Residue** (documented, not silently dropped):
  - **Visual placement/styling of the indicator is unpinned** (T034c
    §Residue): the privacy property is the label string, not the
    layout. Minimal inline style is this ticket's review-facing
    choice, not a gated property.
  - **Reply-channel truthfulness is out of unit scope:** the popup
    trusts the background's answer; that the cache behind it is honest
    is T054's gated surface (router.test.js), and end-to-end label
    truth is T033/T034f/SC-003's.
  - **No debounce/throttle pin:** each active-tab `onUpdated` event
    re-asks; a rapid-navigation burst yields a burst of read-only
    queries (T034c §Residue, documented). The re-ask strategy
    (finding 7) means foreign-tab events also trigger a read-only
    active-tab ask — same bounded cost, display-only surface.
  - **Real-browser popup lifecycle** (open timing, event-page sleep,
    Firefox rendering) is unobservable in the vm unit scope — the
    suite models the contract, the live browser is T033/T034f's.

## Acceptance

1. **The landed T034c suite lifts:** with `popup.js` + `popup.html`
   landed, all impl-gated cases — `onionActiveTabShowsExactTorLabel`,
   `clearnetActiveTabShowsExactUnroutedLabel`,
   `sameTabOnionToClearnetNavigationClearsStaleTorLabel`,
   `sameTabClearnetToOnionNavigationShowsTorOnFreshCacheAnswer`,
   `coldStartEmptyCacheShowsExactUnroutedLabel`,
   `nonTorRepliesNeverRenderTorLabel`,
   `sendMessageFailureRendersUnroutedWithoutThrowing`,
   `backgroundTabUpdateNeverRerendersActiveIndicator`,
   `popupTouchesOnlyPinnedBrowserSurfaces`, and
   `popupHtmlProvidesPinnedIndicatorElement` — go from loud skip to
   PASS inside this commit's verify run, zero skips in the popup file.
2. **`extension/popup/popup.js`** implements the pinned surface: one
   named IIFE, zero new context globals, render-at-load chain
   (`tabs.query({active:true,currentWindow:true})` →
   `runtime.sendMessage({type:'stargate:getRoute', tabId:<active id>})`
   → `textContent` write), the fail-closed display mapping, live
   re-ask on `tabs.onUpdated`, exactly one listener.
3. **`extension/popup/popup.html`** provides `id="route-indicator"`
   (initially empty — §Analysis finding 8) and loads `popup.js` as its
   only external script at body end — no inline scripts, no inline
   handlers (MV2 CSP).
4. **Runnable:** `sh extension/run-tests.sh` exits 0 with no skips in
   `popup/`; `node extension/popup/popup.test.js` passes standalone;
   `scripts/verify.sh` green from repo root.
5. **Diff scope:** `extension/popup/popup.html` (new),
   `extension/popup/popup.js` (new), this ticket's grounding/status
   edits, STATUS regen. NO edit to `popup.test.js` (the frozen T034c
   gate — the labels' only machine side), `background/router.js`, `lib/*`,
   `manifest.json`, `options/*`, quickstart, or tasks.md.
6. **Falsification record** (§Notes): the landed suite is exercised in
   a throwaway copy against impl mutations — URL-derived routing
   (popup decides from the tab URL, ignoring the reply),
   wrong-positive mapping (any reply renders Tor), stale-label render
   (no re-ask on `onUpdated`), blind flip-to-Direct on any event
   (fails the case-(c) mirror), unhandled rejection (try/catch
   removed), listener double-registered, innerHTML write.

## Out-of-scope

- The background half of the pinned protocol — the `tabDecisions`
  cache, the `onMessage` responder, and every routing decision itself
  (T054, landed): this ticket is the ask-and-render side only.
- Anything beyond the two canonical labels in the popup document — no
  device name, no hardening state, no token-configured signal, no
  settings link: the pinned surface allows exactly one DOM anchor and
  a display-only browser surface (T034c); added UI would violate the
  conformance gate and expand the popup's attack surface for no
  contract.
- URL-derived routing display (deciding `.onion` in the popup):
  forbidden by the ask-side design (§Analysis finding 4) and untestable
  without violating the pinned message shape.
- The options page and token lifecycle (T056, done) and the storage
  warning replicas (T034e's three-way gate) — different documents.
- End-to-end label truth against a live stack (T033, T034f, SC-003)
  and the Mullvad Browser release-cadence checks.
- Debounce/throttle of the re-ask (residue, documented — not built
  without a contract that pins its observable behavior).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded on
2026-09-06 (§Analysis; no amendment consumed — the body is consistent
with tasks.md T057/T034c, spec.md US1 scenario 1, research.md §2, and
quickstart Step 6 as landed).

The ticket filename's trailing fragment "popuphtml-and-exten" is a
60-char truncation artifact of `bootstrap-tickets.sh`; the tasks.md body
is authoritative: **…and `extension/popup/popup.js`**.

**Falsification record (2026-09-06, implement phase).** Throwaway copy
at `/tmp/t057-falsify` (popup/ + the frozen T034c suite). Pristine
control: 10/10 PASS, 0 skips — re-verified green after the battery
(restored pristine). Impl mutations, each anchor-guarded (ANCHOR NOT
FOUND = loud abort, never a silent pristine run — T056 lesson):

1. *URL-derived routing* (reply check → `tab.url.endsWith('.onion')`) →
   case 1 fails (the mock tab's full URL ends in `/page`, so the
   suffix test misfires — the mutant is a wrong-negative machine);
   `nonTorRepliesNeverRenderTorLabel` is the durable catch for the
   hostname-check variant of this mutant class. CAUGHT.
2. *wrong-positive mapping* (`route === 'tor'` → any object reply) →
   cases 2 and 6 fail (`{route:'unrouted'}` on a clearnet tab renders
   Tor; the `'TOR'` matrix entry pins exactness). CAUGHT.
3. *no re-ask* (listener registration deleted) → case 3 fails on the
   stale `Route: Tor`; case 9 fails the exactly-one-listener and
   non-vacuousness pins. CAUGHT.
4. *blind flip-to-Direct on any event* (listener renders the default
   without asking) → case 4 — the mirror falsifier — fails (fresh Tor
   answer never shown). CAUGHT.
5. *catch rethrows* → case 7 fails loudly (unhandled rejection
   surfaces the `sendMessage` failure on the popup document). CAUGHT.
6. *listener double-registered* → case 9 fails (stacked listeners).
   CAUGHT.
7. *innerHTML write* → case 9 fails on the textContent-only pin (the
   mock models the pinned write exactly: an `innerHTML` write never
   lands in `textContent`, so every label assertion fails with it).
   CAUGHT.
8. *canonical label drift* (`'Route: Tor'` → `'Route: tor'`) → case 1
   fails byte-exact. CAUGHT.
