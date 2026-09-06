---
id: T054
title: 'Author `extension/background/router.js`'
status: done
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T054
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T091, T034b, T055]
parallel: false
files_budget: 8   # raw-diff-path counting (run-task.sh): 2 code files +
                  # this ticket + STATUS.md regen; ticket-template.md excludes
                  # specs/ paths from the budget
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §FR-001 (the canonical .onion→127.0.0.1:8881 SOCKS5 routing rule this module implements; non-.onion hosts get no proxy in this feature)"
  - "specs/001-tor-route/spec.md §FR-002 (SOCKS5 username = first-party domain string; password = device bearer token; distinct first parties must isolate)"
  - "specs/001-tor-route/spec.md §FR-003 (proxyDNS: true — SOCKS5h, no local DNS)"
  - "specs/001-tor-route/spec.md §FR-004(b) as amended by T091 (non-Direct routing fail-closed at runtime; the hardeningOk gate this module checks before returning the SOCKS descriptor)"
  - "specs/000-architecture/spec.md §14.3 (proxy.onRequest sketch: descriptor shape, username/password wiring, failoverTimeout left at Firefox default)"
  - "specs/000-architecture/spec.md §14.5 Part 2 (the runtime gate + SOCKS5h the router is the second half of)"
constitution_refs:
  - "III: Privacy-Preserving by Construction (per-first-party stream isolation; SOCKS5h; fail-closed non-Direct routing as amended by T091)"
  - "VII: Tests-First for Privacy-Critical and Contract Code (routing decisions are MANDATORY test-first; no dedicated test ticket exists for router.js, so the Principle-VII suite is this ticket's own first artifact)"
decision_refs:
  - "specs/001-tor-route/tickets/T034c-unit-test-for-extensionpopuppopupjs-per.md §Analysis (the pinned popup↔background protocol this module's background half implements: webRequest.onBeforeRequest per-tab decision cache + runtime message {type:'stargate:getRoute', tabId} answered {route:'tor'} iff a confirmed Tor decision is cached; the wrong-positive guard)"
  - "specs/001-tor-route/tickets/T055-author-extensionbackgroundhardeningjs.md (the hardeningOk / auditHardening surface this module consumes; §Out-of-scope assigns router.js and 'its proxyDNS / SOCKS5-username logic and future test' to this ticket)"
  - "specs/001-tor-route/tickets/T034g-t034d-followup-assert-surface-exclusivity.md (the shared-background-scope exclusivity doctrine this module conforms to)"
  - "specs/001-tor-route/tickets/T053-author-extensionlibfirstpartyjs.md (the firstPartyDomain surface — pure string function; router.js owns all browser.* access)"
  - "specs/001-tor-route/tickets/T052-author-extensionlibstoragejs.md (StargateStorage.getDevice — the bearer-token source; §Analysis: router.js reads the token for the SOCKS5 password)"
reviews: { round: 2, date: 2026-09-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T054: Author `extension/background/router.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/background/router.js` — `browser.proxy.onRequest` listener that returns `{ type: "socks", host: "127.0.0.1", port: 8881, username: <first-party from T053>, password: <bearer token from T052>, proxyDNS: true }` for hosts matching `.onion` (**FR-001** — this is the canonical implementation of the `.onion`→port-8881 routing rule); no proxy for other hosts in this feature. `failoverTimeout` is intentionally NOT set — Firefox's default (5 seconds) is acceptable and pinning it would create a magic number with no spec-level rationale; if a future feature needs a tighter or looser failover, the change ships with a justification in that feature's research doc.

## Analysis

Property map (grounding-verified 2026-09-06; required — `privacy_critical:
true` per `docs/process/analysis.md`). Three body-vs-reality items resolved
into the design (method per T035a/T034b/T055 §Analysis):

1. **The body is PRE-T091 text; the T091-amended FR-004 is authoritative.**
   T091 acceptance #6 explicitly names T054 among the tickets "refined at
   step 17" (T091 is `done`; same handling as T034b/T055). The body's
   "returns {…} for hosts matching `.onion`" therefore composes with the
   fail-closed gate: the SOCKS descriptor is returned **only when**
   `hardeningOk === true` (T055's flag, manifest M4 pins hardening.js loads
   before router.js); every gated-off path returns no proxy. The body's
   "failoverTimeout is intentionally NOT set" clause is carried verbatim —
   the descriptor must not carry the key at all.
2. **The body omits the T034c-pinned popup transport; this ticket owns the
   background half.** T034c §Analysis pins the protocol no spec text names:
   the per-tab decision cache is "background-page memory written by the
   router's `webRequest.onBeforeRequest` listener (T054 side)", answered via
   `runtime.sendMessage({type:'stargate:getRoute', tabId})` →
   `{route:'tor'}` **iff** the cache holds a confirmed Tor decision for that
   tab, a non-Tor record `{route:'unrouted'}` otherwise, and nothing
   meaningful (`undefined`) for an unknown tab — the cold-start state of
   T034c case (d). The responder lives on the background page (a popup
   document cannot hold it), whose scripts are exactly firstparty.js /
   storage.js / hardening.js / router.js — the first three have frozen
   single-purpose surfaces, so router.js is the only home. T034c §Residue
   names this side "T054/T057 wiring" with "cache internals stay
   T054/T057's"; the popup half (and its suite) remains T057's.
3. **The routing decision must be synchronous, so the bearer token is
   mirrored into memory at load + on `storage.onChanged`.** The T034c pin
   puts the authoritative per-tab cache write in the *synchronous*
   `onBeforeRequest` listener, and a wrong-positive cache entry is the exact
   failure T034c forbids ("would show 'Tor' for an onion URL opened while
   routing is blocked/hardening-failed — the wrong-positive case (d)
   forbids"). A decision that awaits `storage.local` per request cannot know
   token presence synchronously — an onion tab with no token configured
   would cache `tor` and the popup would lie. So router.js mirrors the token
   in memory: read once at script evaluation (same load-time-async precedent
   as hardening.js's startup audit) and re-read on
   `storage.onChanged( area==='local', changes.device )`. Both listeners
   consult the same in-memory state, so the descriptor and the cache entry
   can never disagree. Token format (`^[0-9a-f]{32}$`) stays at the options
   edge (T052 §Analysis); router checks only presence (a non-empty string),
   which is a routing-decision input, not a validation policy. Per-request
   `proxy.onRequest` stays fully synchronous — no promise, no per-request
   storage I/O.

- **Must hold:**
  - **FR-001 canonical rule:** a request whose URL host (one trailing FQDN
    dot stripped, mirroring firstparty.js normalization) ends in `.onion`
    routes to `{type:'socks', host:'127.0.0.1', port:8881, …}`; every other
    host returns `{type:'direct'}` — the extension never invokes port 8881
    for non-`.onion` requests in this feature (FR-001 scope clause).
  - **FR-002 username/password:** the SOCKS5 username is
    `firstPartyDomain(details)` verbatim (`.onion` hosts unreduced — the
    stream-isolation signal, Constitution III; distinct first parties get
    distinct usernames) and the password is the mirrored bearer token.
  - **FR-003 proxyDNS:** the descriptor carries `proxyDNS: true` — SOCKS5h,
    no local DNS ever.
  - **Fail-closed (FR-004(b), T091; Constitution III):** the SOCKS
    descriptor requires ALL of `hardeningOk === true`, a present non-empty
    mirrored token, and a non-throwing `firstPartyDomain` (a
    `FirstPartyError` governing URL must never yield a guessed or empty
    username — the one-routable-string collapse T034d finding 3 forbids).
    Each unmet condition yields `{type:'direct'}` for `.onion` requests.
  - **Honest per-tab indicator feed (T034c protocol; Constitution V):** the
    `onBeforeRequest` listener records the tab's decision (cache write only
    for `tabId >= 0`; non-tab requests have no indicator) — `tor` only when
    the full gate passes, `unrouted` otherwise. The `runtime.onMessage`
    responder answers `{route:'tor'}` iff the cache holds `tor` for that
    tab, `{route:'unrouted'}` for a recorded non-Tor decision, a Promise
    resolving `undefined` for an unknown tab — and the answer leaves **via
    the response channel** (a Promise return): Firefox's `runtime.onMessage`
    discards plain synchronous listener returns ("The listener function can
    return either a Boolean or a Promise", MDN; round-1 review Major — the
    plain-return shape would have left every popup on its fail-closed
    label). Non-owned or malformed messages get a plain `undefined` (not
    handled — other listeners may answer; the MDN multi-listener pattern).
    An onion tab must NEVER read `{route:'tor'}` while the gate is closed.
  - **failoverTimeout absent:** the returned descriptor does not carry the
    key (tasks.md T054 decision — Firefox's 5-second default; no magic
    number without spec-level rationale).
  - **Surface exclusivity (T034g doctrine):** router.js contributes ZERO
    new globals to the shared MV2 background-page scope — everything lives
    inside one IIFE; the module's surface is its browser registrations
    (`proxy.onRequest`, `webRequest.onBeforeRequest`,
    `runtime.onMessage`, `storage.onChanged`), not scope bindings.
  - **Principle VII:** every must-hold above has a named test in
    `router.test.js` (this ticket's own first artifact — no dedicated test
    ticket exists for router.js; T055 §Out-of-scope assigns "its … future
    test" here).
- **Gated:** `extension/background/router.test.js` runs under
  `extension/run-tests.sh` (verify.sh Gate 2b, fail-closed on non-zero
  exit); the loader mirrors the real shared scope (firstparty.js loaded
  into the same sandbox before router.js, so username behaviour is exercised
  against the real module, not a stub) and hard-fails on surface violation
  (never a silent skip — the module ships in the same commit as its suite).
  `scripts/check-license-headers.sh` gates the SPDX header;
  `scripts/lint-ticket.py` gates ticket well-formedness; the pre-commit
  secret scanner gates fixture hygiene (tokens in fixtures are computed
  32-hex placeholders — `'0f1e2d3c'.repeat(4)`, the T052 storage.test.js
  convention — so the scanner sees no literal, every assertion a full
  32-hex string; caught by the gitleaks hook at first commit attempt and
  fixed, see §Notes).
- **Residue:**
  - **Descriptor correctness in the real browser** — that Firefox MV2
    honours the synchronous ProxyInfo return, `proxyDNS`, and the SOCKS5
    username passthrough end-to-end: T033/T034/T034f territory (live
    stack); no hermetic gate possible without a browser in CI (T091/T055
    residue, same shape).
  - **Token-mirror staleness window** — between `setDeviceToken` and
    `storage.onChanged` delivery, and on cold start before the load-time
    read resolves, the mirror holds the previous (or absent) token: routing
    is unavailable (fail-closed → popup shows the honest unrouted label),
    never inconsistent — descriptor and cache entry read the same memory
    cell. Accepted: the alternative (per-request storage read) reintroduces
    the wrong-positive the sync decision exists to prevent.
  - **Cache lifecycle** — entries are keyed by tabId and cleared when the
    non-persistent event page is torn down (Firefox kills idle event pages,
    resetting script state); no `tabs.onRemoved` listener is added because
    the event-page lifetime already bounds the map and each entry is a
    tabId→constant. If a future feature moves to a persistent background
    page, revisit.
  - **route() evaluated twice per request** (onBeforeRequest for the cache
    write, onRequest for the descriptor — `proxy.onRequest` requestDetails
    carries no tabId, which is exactly why the T034c pin uses the
    webRequest listener): a hardening flip between the two calls can
    transiently disagree the pair; self-corrects on the next request and
    the popup always re-asks fresh (T034c case (c)).

## Acceptance

Named test (new, this ticket, authored FIRST — Principle VII): `extension/
background/router.test.js`. Named runner (pre-existing, unchanged):
`extension/run-tests.sh` (verify.sh Gate 2b). Runnable command:
`scripts/verify.sh` green from repo root; fast inner loop:
`cd extension && ./run-tests.sh`.

1. `extension/background/router.js` exists, carries the Apache-2.0 SPDX
   header, and the new suite reports all named cases green. Pre-impl state
   recorded at grounding: the suite RED (module absent) — the Principle-VII
   signal is the failing run, not a skip, because this suite ships in the
   same commit as the implementation (no downstream impl ticket will lift
   it).
2. Descriptor cases (FR-001/002/003): hardened + tokened top-level `.onion`
   navigation returns exactly the SOCKS descriptor with `username` = the
   full `.onion` host, `password` = the token, `proxyDNS: true`, and no
   `failoverTimeout` key; distinct `.onion` first parties yield distinct
   usernames; a `.onion` subresource of a `.onion` document yields the
   parent page's onion host as username; non-`.onion` requests yield
   `{type:'direct'}` and never carry the token or port 8881.
3. Fail-closed cases (FR-004(b)): with `hardeningOk` false, `.onion`
   requests yield `{type:'direct'}` AND the tab's cache entry reads
   `unrouted` (the T034c wrong-positive guard — the popup must render its
   fail-closed label, not `Route: Tor`); with the token absent or empty,
   same; with a present-but-unparseable governing URL (FirstPartyError),
   same — no guessed or empty username ever leaves the module.
4. T034c protocol cases: the `onBeforeRequest` listener is registered at
   evaluation with an `<all_urls>` filter and records per-tab decisions
   (tabId ≥ 0 only); the `runtime.onMessage` responder answers
   `{type:'stargate:getRoute', tabId}` with `{route:'tor'}` / `{route:
   'unrouted'}` / nothing-meaningful per the pinned semantics — delivered
   through the response channel (a Promise return for owned, valid
   queries; a plain `undefined` for non-owned or malformed messages — the
   channel probe is realm-safe: the vm loader's promises come from the
   sandbox realm, so the suite asserts thenability + the awaited value
   rather than a cross-realm-false `instanceof Promise`).
5. Token-mirror cases: a `storage.onChanged` event for the device key
   updates subsequent descriptors (new token in `password`) and removing
   the device fail-closes.
6. Surface case: loading firstparty.js + router.js into one sandbox adds
   zero property globals beyond the seeded set + `firstPartyDomain`
   (T034g register).
7. The falsification battery (§Notes) shows each mutation tripping its
   named case with the pristine control green.
8. No edits to `extension/background/hardening.js`,
   `extension/background/hardening.test.js`,
   `extension/background/hardening.edges.test.js`,
   `extension/lib/*` (+ their suites), `extension/popup/*`,
   `extension/options/*`, `extension/manifest.json` (already lists
   `background/router.js` after `background/hardening.js` — manifest.test
   M4), or `extension/run-tests.sh`.
9. `scripts/verify.sh` green from repo root.

## Out-of-scope

- **`extension/popup/popup.html` + `popup.js`** — T057's artifact; the
  popup half of the T034c protocol (query, render, canonical labels) and
  its T034c gate. This ticket ships only the background side.
- **`extension/background/hardening.js`** — T055's artifact; router.js is
  a consumer of `hardeningOk` and must never write it or call
  `auditHardening()`.
- **`extension/lib/firstparty.js` / `lib/storage.js`** — frozen surfaces
  (T034d/T034g/T052); consumed as loaded globals, never re-implemented or
  edited.
- **Non-`.onion` routing** (`.i2p`, per-domain rules, blocklist, default
  routes) — arch §14.3 steps beyond this feature; FR-001 scopes this
  feature to `.onion` + direct-for-everything-else.
- **The `webRequest` DoH-endpoint blocklist** (arch §14.2) — a different
  webRequest listener for a different guarantee; release-cadence territory
  (T055 §Out-of-scope carries the same line).
- **`extension/manifest.json`** — already correct (T051; M4 order pin);
  any future manifest change is T051's.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded and
refined on 2026-09-06 (T091 acceptance #6 step-17 refine — T054 is named;
T091 is `done`, so the refine is authorized; same handling as T034b/T055).

**Pre-impl state (Principle-VII signal).** `router.test.js` was authored
first and run before `router.js` existed: 11/11 cases FAILED (loader
ENOENT — this suite ships in the same commit as its implementation, so the
RED run, not a skip, is the tests-first evidence). Two first-run test
harness defects were fixed before any implementation assertion was
satisfied, recorded for honesty: `deepStrictEqual` across a vm context
compares prototypes (fixed with a JSON round-trip `plain()` helper), and
an explicit `device: undefined` silently triggered the loader's
destructuring default — the missing-token case was unknowingly testing the
tokened load (fixed with an explicit `null`-means-absent sentinel).

**Falsification record (2026-09-06, implement phase).** Exercised in a
throwaway copy (`/tmp/t054-probe`, repo untouched) against the shipped
`router.js`; each mutation tripped its named case, pristine control green:

| # | Mutation (what would falsify the claim) | Trips |
|---|---|---|
| M1 | hardening gate check removed (fail-open) | `closedHardeningGateFailsClosedAndRecordsUnrouted` |
| M2 | token-presence check removed | `missingOrEmptyTokenFailsClosed` (+ `storageOnChangedRefreshes…`) |
| M3 | `TOR_PORT = 8880` | `onionTopLevelNavigationReturnsCanonicalSocksDescriptor` |
| M4 | `proxyDNS: true` dropped (SOCKS5h hole) | `onionTopLevelNavigationReturnsCanonicalSocksDescriptor` |
| M5 | username constant `stargate-shared` (isolation collapse) | `distinctOnionFirstPartiesGetDistinctUsernames` + 3 descriptor cases |
| M6 | `.onion` suffix check inverted (route clearnet) | `clearnetRequestsAreDirectAndNeverCarryTheTokenOrPort` + 6 cases |
| M7 | cache writes `'tor'` unconditionally (popup wrong-positive) | `closedHardeningGateFailsClosedAndRecordsUnrouted` + `getRouteResponderPinnedSemantics` |
| M8 | IIFE unrolled to a top-level `var` (global leak) | exclusivity conformance hard-FAIL on every load + `routerContributesZeroNewGlobals…` |
| M9 | `failoverTimeout: 5` pinned | `onionTopLevelNavigationReturnsCanonicalSocksDescriptor` |
| M10 | `storage.onChanged` refresh dropped (stale credential) | `storageOnChangedRefreshesMirroredToken` |
| M11 | FirstPartyError swallowed → guessed username | `firstPartyErrorFailsClosedWithoutGuessedUsername` |
| M12 | trailing-dot strip removed (FQDN evasion) | `trailingDotFqdnOnionHostStillRoutesAsOnion` |
| M13a | cache-writer tabId guard removed ONLY | **SURVIVED — recorded**: masked by the responder's own independent tabId guard, so the mutation is unobservable through the pinned surface (cache internals are not externally visible by T034c design); defense-in-depth, not a suite hole |
| M13b | BOTH tabId guards removed (observable compound) | `getRouteResponderPinnedSemantics` (`non-tab requests never enter the per-tab cache` assertion) |

M13a is the honest survivor the battery exists to surface: the suite pins
the observable protocol, and a write the responder can never serve is
invisible by design. The compound M13b proves the pair of guards is
load-bearing where observability begins.

**Round-1 review (2026-09-06) — REWORK (1 Major, 1 Minor); round-2 record.**
The reviewer (fresh context) independently re-derived 8 of the battery
mutations, confirmed the descriptor path correct, and filed:

- **[Major] the getRoute responder answered via plain synchronous returns**
  (router.js `stargateGetRoute`): Firefox's `runtime.onMessage` discards any
  listener return that is not a Boolean or a Promise ("The listener function
  can return either a Boolean or a Promise", MDN — independently re-verified
  during this rework; reviewer traced `MessageEvent.wrapResponse` in
  ExtensionChild across ESR 91/140/central). Effect: in the real browser the
  popup's `sendMessage` would never receive `{route:'tor'}` and would always
  render `Route: Direct (unrouted)` — fail-safe direction (wrong-negative,
  never wrong-positive), but it hollowed acceptance #4 and the T034c
  protocol into harness-only truth. The hermetic suite missed it because it
  asserted the listener's return value directly and never modeled the
  response channel. **Fix:** owned, valid queries now get
  `Promise.resolve({route:'tor'})` / `Promise.resolve({route:'unrouted'})` /
  `Promise.resolve(undefined)` (unknown tab — owns the channel, resolves
  nothing meaningful); non-owned or malformed messages keep the plain
  `undefined` (not handled; MDN multi-listener pattern). **Probe (the
  verdict's EVALUATED-AS, realized):** the suite now asserts the channel
  itself — `isResponseChannel(reply)` (thenable) + the awaited
  `deepStrictEqual` — in all three responder-driving cases, while foreign /
  malformed messages must still return a plain `undefined`. One probe
  deviation from the verdict's literal text, recorded: `a instanceof
  Promise` is cross-realm-false under the vm loader (the router's answers
  are built with the sandbox realm's Promise constructor), so the suite
  asserts thenability instead — same contract, loader-proof.
- **[Minor] companion TEST-INTEGRITY:** the suite never modeled the
  response channel, so the plain-return mutant stayed green. Same probe
  closes it.
- **Round-2 falsification:** the verdict's own mutant — responder answers
  via plain return — now trips (`closedHardeningGate…` + 2 more); the full
  battery re-run on the fixed code trips M1–M10, M12, M13b with the control
  green. M11 first reported SURVIVED on the re-run: battery-script anchor
  bug (the shortened match hit the URL-parse catch, which no test
  exercises), not a suite hole; re-run with the round-1 unique anchor
  (the `firstPartyDomain` try/catch) trips
  `firstPartyErrorFailsClosedWithoutGuessedUsername` as before. Both probe
  errors recorded for honesty.
- Reviewer RECOMMENDED-FOLLOW-UP carried: once the popup lands (T057) or at
  the live stack (T033), add one real `browser.runtime.sendMessage`
  round-trip assertion — hermetic suites structurally cannot model
  Firefox's response channel, which is where this defect class hides.

**Commit-gate record (2026-09-06, landing).** The first `git commit`
attempt was blocked by the pre-commit gitleaks hook: the fixture literals
`'0f1e…'` / `'a1b2…'` tripped `generic-api-key` (entropy 4.0). The gate did
its job — the fixtures were never credentials, but the house convention
(T052 storage.test.js) is computed placeholders precisely so the scanner
has no literals to adjudicate. Fixed as `'0f1e2d3c'.repeat(4)` /
`'a1b2c3d4'.repeat(4)` (byte-length and assertion semantics unchanged;
suite 11/11 green); no scanner config change, no `--no-verify`.

**Verify notes (2026-09-06).** First full `scripts/verify.sh` run went RED
on `go:tests/contract:control-grpc` (pass=20 fail=2) — the T116-filed
journal-read flake; the package passes fresh standalone (`go clean
-testcache`) and the re-run went GREEN (PASS=20 SKIP=1 FAIL=0). This diff
touches no Go file. Local node is v18 (below the Node 20 CI pin;
run-tests.sh warns and proceeds — CI is authoritative, research.md §10).

**Adjacent decisions.** Classification host = the request URL's host
(one trailing FQDN dot stripped, mirroring firstparty.js) — FR-001 keys on
where the bytes go; the USERNAME separately follows the governing document
via `firstPartyDomain(details)` — FR-002 precedence, pinned by the
cross-origin case (`example.com` page embedding an `ONION_B` pixel routes
via Tor under username `example.com`). An onion subresource OF a clearnet
page has no clearnet alternative (only Tor can resolve it), which is why
FR-001's request-host key and FR-002's username key compose this way.
`route()` is evaluated by both listeners over the same in-memory state
(`hardeningOk`, mirrored token) so the descriptor and the popup feed can
never disagree by construction; the transient double-eval race is §Analysis
residue. The `stargateOnBeforeRequest` listener returns `{}` (no cancel,
no redirect) — it is an observer, not a blocker; the arch §14.2 DoH
blocklist listener is a different guarantee, out of scope here.
