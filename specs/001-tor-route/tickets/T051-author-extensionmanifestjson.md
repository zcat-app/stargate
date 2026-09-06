---
id: T051
title: 'Author `extension/manifest.json`'
status: pending
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T051
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T091]
parallel: true
files_budget: 8   # counted set: 2 (manifest.json + manifest.test.js); specs/ regen exempt per T039 r2 precedent
privacy_critical: true
complexity: low   # confirmed at /start 2026-09-06: one static JSON document + a schema-pinning node:test suite
risk: low
round_cap: 2
spec_refs:
  - "specs/000-architecture/spec.md §14.1 (Manifest V2; the body's non-persistent-background requirement — see §Analysis wording note W1 for the citation imprecision)"
  - "specs/000-architecture/spec.md §14.2 (permission table incl. `management` retained-for-v1; the 'No tabs, no history, no bookmarks, no cookies, no identity' exclusion clause)"
  - "specs/000-architecture/spec.md §14.3–§14.6 (what the registered scripts/pages do: router, storage layout, hardening gate, blocklist delivery inside the package)"
  - "specs/000-architecture/spec.md §12.3 + extension/package.sh (every non-.keep file under extension/ is zipped — manifest lands in the artifact with no packaging amendment)"
  - "specs/001-tor-route/spec.md §FR-001/§FR-002/§FR-003 (router.js contract the manifest registers), §FR-004 (hardening gate flag router checks)"
  - "specs/001-tor-route/research.md §2 (MV2 decision; no MV3 path preserves per-request SOCKS5 username), §10 (node:test + vm idiom, no third-party JS deps)"
  - "specs/001-tor-route/data-model.md §5 (extension storage.local schema — lib/storage.js registration)"
decision_refs:
  - "T091 (done) acceptance #5: 'if retained, T051 must request `management`' — the foreign-extension inventory was retained for v1; acceptance #6 authorizes the step-17 refine of T051 now that T091 is done. This grounding IS that refine (T034b precedent)."
  - "THREAT-MODEL §2.7 (T091 r1 m2 fix): what `management` exposes + the compromised-Stargate fingerprint risk — already itemized; this ticket imports the decision, no amendment."
  - "specs/000-architecture/spec.md §14 amendment Part 3: 'T051's manifest edit to request `management`' + blocked_by: [T091] satisfied (T091 done)."
  - "T034b §Analysis (step-17 refine precedent: consume the T091-amended contract at the dependent's own /start)"
  - "TICKET-LEVEL: gecko id value `stargate@stargate.local` — no spec/doc pin exists for the add-on id; it is an opaque Firefox identifier (email-like form), not a resolvable address. Reviewer falsification: any doc pin found for an id supersedes this."
  - "TICKET-LEVEL: `strict_min_version` omitted — no spec pins a Firefox floor; the MV2 support-window maintenance flag is arch §15 #6, verified at release cadence (residue R4)."
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T051: Author `extension/manifest.json`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/manifest.json` — Manifest V2, `browser_specific_settings.gecko.id`, permissions `proxy`, `storage`, `webRequest`, `webRequestBlocking`, `privacy`, `notifications`, host permission for `<all_urls>`; background script is non-persistent per arch §14.1.

## Analysis

Required (`privacy_critical: true`) — full property map. Grounded 2026-09-06
against the tree: `extension/` contains the four test suites (T034b/c/d +
options) and NO implementation files yet — no `manifest.json` (this ticket),
no lib/background/options/popup sources (T052–T057, all pending, this ticket
is `parallel: true` with them). `extension/run-tests.sh` auto-discovers every
`*.test.js` (no runner amendment needed); `extension/package.sh` zips every
non-`.keep` file (no filter amendment needed; the manifest is therefore
auto-packaged); `scripts/check-license-headers.sh` covers `*.js` (SPDX on the
test) and skips `*.json` (JSON cannot carry the comment header). Blockers
T009 and T091 are both `done`.

**Step-17 refine (T091 acceptance #6; T034b precedent).** The verbatim body
pre-dates the T091 amendment in one load-bearing way: its permission list
omits `management`. T091 (done) retained the foreign-extension inventory for
v1 and its acceptance #5 pins the consequence verbatim: *"if retained, T051
must request `management` and the real-browser test must exercise it."* The
amended contract therefore requests `management`; THREAT-MODEL §2.7 already
itemizes what the permission exposes (T091 r1 m2), so no threat-model change
accompanies this ticket.

**Wording notes.**
- **W1 — §14.1 citation imprecision.** The body grounds
  "non-persistent background" in arch §14.1; §14.1 actually pins the
  manifest *version* (MV2). The non-persistent requirement itself stands
  (it is MV2 event-page semantics and the body demands it explicitly); the
  citation is corrected here, the requirement is kept.
- **W2 — registration completeness.** The body names only the permission
  surface, but a manifest that stopped there would not load the extension's
  own architecture (arch §14.3–§14.5 background scripts; options/popup UX in
  the US scenarios). Since T051 is the manifest ticket and T052–T057 are its
  parallel siblings with no manifest-edit language in their bodies, T051 owns
  ALL manifest keys: the `background.scripts` list, `options_ui.page`, and
  `browser_action.default_popup`. Each key traces to arch §14 / a named
  sibling ticket's pinned path. This keeps the shared file single-owned
  instead of forcing four later manifest amendments.

**Load order.** MV2 background scripts share one global scope and execute in
listed order. Order: `lib/firstparty.js`, `lib/storage.js` (router's
collaborators, T053/T052), then `background/hardening.js` (T055), then
`background/router.js` (T054). Hardening before router closes the window in
which `proxy.onRequest` could serve a non-Direct route before the FR-004 gate
flag exists — an ordering leak, not a style preference (arch §14.5 Part 2).

### Property map

- **Must hold** (each asserted by the named suite, A1)
  - **M1 — MV2.** `manifest_version === 2` (arch §14.1; research.md §2: no
    MV3 path preserves per-request SOCKS5 username, so MV2 is not a styling
    choice but the stream-isolation carrier, FR-002).
  - **M2 — permission set EXACT equality.** `permissions` is exactly
    `proxy`, `storage`, `webRequest`, `webRequestBlocking`, `privacy`,
    `notifications`, `management`, `<all_urls>` — set equality in BOTH
    directions: none missing (body + T091), none extra (arch §14.2: "No
    `tabs`, no `history`, no `bookmarks`, no `cookies`, no `identity`" — a
    sneaked permission is unbounded privacy surface). `management` present
    per T091 (detection-not-prevention; fingerprint cost accepted in
    THREAT-MODEL §2.7).
  - **M3 — non-persistent background.** `background.persistent === false`
    (body; MV2 event page).
  - **M4 — load-order gate window.** `background.scripts` is exactly the
    four pinned paths with `background/hardening.js` listed before
    `background/router.js` (arch §14.5 Part 2 / FR-004 fail-closed).
  - **M5 — gecko id.** `browser_specific_settings.gecko.id` is a non-empty
    email-like string or GUID (body; value is the TICKET-LEVEL decision
    above).
  - **M6 — options/popup registration.** `options_ui.page ===
    "options/options.html"` and `browser_action.default_popup ===
    "popup/popup.html"` (T056/T057 pinned paths; US token-paste and per-tab
    indicator scenarios).
  - **M7 — strict JSON.** The file parses with a strict JSON parser — no
    comments, no trailing commas (it is consumed by Firefox and by
    package.sh verbatim).
- **Gated** (verify.sh catches fail-closed once landed)
  - Gate 2b `extension-tests` runs `extension/run-tests.sh`, which
    auto-discovers `manifest.test.js` — any M1–M7 violation is a red gate.
  - `check-license-headers.sh` covers the new `*.js` (SPDX); `.json` is
    out of its scope (cannot carry comments) — verified non-regressing.
  - Gate 5 reproducibility (opt-in) re-packages the tree; the manifest's
    inclusion in the zip is by package.sh's existing filter (no amendment).
- **Residue** (no gate catches; named for redteam scope)
  - **R1 — dangling references.** No gate in this ticket asserts the
    registered scripts/pages EXIST on disk: T052–T057 land them in
    parallel, so an existence assertion would pin this ticket's gate to
    sibling tickets. Until they land, the manifest references files that
    are not there, and nothing in CI fails on the gap. Coherent only as a
    mid-assembly state; loadability is exercised by the release-cadence
    live-e2e. RECOMMENDED-FOLLOW-UP at assembly time (last of T052–T057):
    extend the suite to assert every registered path exists.
  - **R2 — no schema validator.** No gate runs Mozilla's `web-ext` lint
    (rejected with the npm tree in research.md §10). M1–M7 are the named
    properties, not a full MV2 schema validation — a manifest key neither
    body nor arch §14 names would not be caught (none is known).
  - **R3 — id opacity.** The gecko id's *form* is gated; its *value* is a
    convention (no functional property attaches to it in v1).
  - **R4 — MV2 window.** If Mullvad Browser drops MV2 (arch §15 #6
    maintenance flag), nothing in CI notices; the release-cadence live-e2e
    is the catch.

**Tests-first evidence (Principle VII).** `extension/manifest.test.js` is
authored FIRST and observed RED (manifest.json absent → suite fails), then
`manifest.json` is driven GREEN in-ticket. The suite is non-vacuous by
construction: it reads the real file (no mocked manifest) and asserts set
equality, so removing any one permission, reordering hardening after router,
or flipping `persistent` to `true` each fails a named case.

## Acceptance

- **A1 (named test).** `extension/manifest.test.js` — node:test suite
  (research.md §10 idiom: `node:test` + `node:assert/strict`, Node built-ins
  only, reads the real `extension/manifest.json` from disk) asserting M1–M7:
  strict-JSON parse; `manifest_version === 2`; gecko id well-formed; the
  exact permission set (bidirectional equality); `background.persistent ===
  false`; the exact four-script background list with hardening.js before
  router.js; `options_ui.page` and `browser_action.default_popup` at the
  pinned paths.
- **A2 (tests-first order).** The suite is observed RED before
  `manifest.json` exists, GREEN after — recorded in the landing notes with
  the observed failure (ENOENT) and the passing run.
- **A3 (runnable gates).** From repo root: `bash scripts/verify.sh` GREEN,
  including Gate 2b `extension-tests` (which runs
  `cd extension && ./run-tests.sh` and discovers the new suite).
- **A4 (packaging sanity, in-ticket evidence, not a standing gate).** One
  `bash extension/package.sh` run shows `manifest.json` present in the zip
  member list — proving the packaging filter picks the new file up with no
  amendment.

## Out-of-scope

- **Implementing the registered collaborators** — `lib/firstparty.js` (T053),
  `lib/storage.js` (T052), `background/hardening.js` (T055),
  `background/router.js` (T054), options (T056), popup (T057). The manifest
  references their pinned paths and dangles (residue R1) until they land;
  that is the designed mid-assembly state, not a defect of this ticket.
- **Existence/loadability gating of registered paths** — residue R1; belongs
  to assembly-time (follow-up), not to a `parallel: true` ticket.
- **`web_ext`-style schema validation, `strict_min_version`, MV3 migration**
  — research.md §10 rejection + arch §15 #6 maintenance flag (residue R2/R4).
- **Content scripts / `web_accessible_resources`** — v1 has none: routing is
  `proxy.onRequest` (background), popup/options are extension pages reading
  `storage.local` directly, and the §14.6 blocklist is fetched from the
  extension's own package by a background script (no WAR key needed).
- **No THREAT-MODEL amendment** — `management`'s exposure and accepted
  fingerprint cost are already itemized in THREAT-MODEL §2.7 (T091 r1 m2);
  this ticket imports that decision. No new privacy surface is introduced
  beyond the §14.2-named permissions.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded + step-17
refine (T091) applied 2026-09-06.
