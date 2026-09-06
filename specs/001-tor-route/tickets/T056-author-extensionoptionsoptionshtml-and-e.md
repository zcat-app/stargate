---
id: T056
title: 'Author `extension/options/options.html` and `extension/options/options'
status: in-review
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T056
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T034e]   # T034e is the Principle-VII test-first gate (T096)
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
tests_first: [T034e]   # T096/M6: T034e MUST be done before this impl (Constitution VII)
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §FR-019 (options page: single token field persisted to storage.local, visible warning; canonical text pinned in data-model.md §5.1)"
  - "specs/001-tor-route/data-model.md §5 (device schema `device.{name, bearerToken, tokenStoredAt}`; `^[0-9a-f]{32}$` validation BEFORE save, in the options page)"
  - "specs/001-tor-route/data-model.md §5.1 (the canonical warning string — single source of truth; this file is replica (a) of the T034e three-way gate)"
  - "specs/001-tor-route/quickstart.md §Step 4 (operator-facing UX contract: 'Bearer token' field, 'Save' button)"
  - "specs/001-tor-route/research.md §6 (storage.local rationale; the warning's origin; the doc cross-reference is deliberately NOT in the user-facing string)"
decision_refs:
  - "specs/001-tor-route/tickets/T034e-unit-test-for-the-canonical-storagelocal.md (the tests-first gate that lifts here; §Analysis pins the ONLY surface assumption on this ticket; §Out-of-scope assigns options.js behavior + its test here)"
  - "specs/001-tor-route/tickets/T054-author-extensionbackgroundrouterjs.md (impl-ticket-authors-its-own-suite precedent: no dedicated test ticket exists for options.js behavior — Constitution VII satisfied the router.test.js way, authored FIRST and RED in this ticket)"
  - "extension/popup/popup.test.js (landed T034c suite — the page-script idiom this ticket follows: zero new context globals, listener wiring at load, textContent-only writes, access-recording vm mocks)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T056: Author `extension/options/options.html` and `extension/options/options

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/options/options.html` and `extension/options/options.js` — single bearer-token field with `^[0-9a-f]{32}$` client-side validation; visible warning about `storage.local` per research.md §6 and FR-019. The canonical user-facing warning string is pinned in data-model.md §5.1. **Verified by T034e** (three-way drift assertion: html ↔ data-model §5.1 ↔ quickstart Step 4); T034e MUST be authored and failing before this task lands.

## Analysis

Property map (grounding-verified 2026-09-06; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (body-vs-reality; method per
T035a/T034b/T034e):**

1. **The gate already exists and is loud:** T034e landed
   `extension/options/options.test.js` with the html case self-skipping
   until this file exists ("bites inside T056's own verify run"). Its
   §Analysis pins the ONLY surface assumption on this ticket: options.html
   is static markup whose document text — after comment/script/style
   strip, tag strip, minimal-entity decode, whitespace collapse — contains
   the data-model.md §5.1 canonical string character-exact. No element
   id/class/tag is pinned by it; DOM shape is review concern (its residue).
   Everything else below is this ticket's own design, tested by a suite
   this ticket authors FIRST (router.test.js precedent — no dedicated test
   ticket exists; T034e §Out-of-scope assigns "any `options.js` behavior
   test — all T056").
2. **Manifest never changes:** manifest.test.js M6 already registers
   `options_ui.page = 'options/options.html'` (T051: "registration lives
   here so the sibling tickets never amend this file"). Verified on disk.
3. **Storage write path already exists:** `lib/storage.js` (T052, done)
   provides `StargateStorage.setDeviceToken(token)` with merge semantics
   (preserves `name`) and the hour-bucket `tokenStoredAt` stamp. Its
   header comment names options.js as the consumer that "writes the
   validated one". Validation deliberately lives HERE (the edge) —
   storage.js carries no shape policy (data-model.md §5 puts
   `^[0-9a-f]{32}$` "in the options page"; trust-boundary doctrine).
4. **Page-script idiom (T034c suite precedent):** options.js is a
   classic page script in its own document — not a background-lib script
   sharing the background scope. It contributes ZERO new globals
   (everything inside one named IIFE, router.js style); its surface is
   its DOM wiring + its `storage.local` reach through `StargateStorage`.
   Status writes via `textContent` only (the injection-safe write, T034c
   §Analysis). No I/O at eval time beyond the one submit-listener
   registration.
5. **Test file placement:** new `extension/options/options.save.test.js`,
   NOT an extension of the landed T034e suite (surgical-changes doctrine;
   the `*.edges.test.js` companion-file naming precedent). run-tests.sh
   discovery reaches it with no runner amendment (verified: glob
   `find . -name '*.test.js' -not -path './dist/*'`).
6. **UX contract from quickstart Step 4:** a field labeled "Bearer token"
   and a "Save" button are the operator-facing prose this page must not
   drift from. Status/error message WORDING is spec-silent — this ticket
   pins it in its own suite (popup.test.js "suite IS the machine side of
   the coupling" precedent for unpinned strings).
7. **No token read-back on load (decision):** the page never prefills or
   displays the stored token. Rendering a stored secret on screen is its
   own exposure, FR-019 requires only paste→persist→warn, and configured
   state is observable via the popup (T057) / connectivity (T034f).
   Recorded as residue below.
8. **gitleaks fixture convention:** the suite's token fixtures are
   computed (`'ab'.repeat(16)`-style, T052 storage.test.js convention) —
   never a literal 32-hex string, which the pre-commit scanner
   (generic-api-key) blocks (T054 commit-gate precedent).

**Pinned surface (this ticket's own suite is the executable spec):**
`options.html` provides exactly three elements by id — `token-form`
(form), `bearer-token` (text input), `status` (status line) — plus the
warning paragraph; `options.js` registers exactly one `submit` listener
on `token-form`, reads `bearer-token.value`, writes `status.textContent`,
and persists valid tokens via `StargateStorage.setDeviceToken`; the page
loads exactly `../lib/storage.js` then `options.js` as external scripts
(MV2 CSP forbids inline script; no inline handlers).

- **Must hold:**
  - The rendered page carries the data-model.md §5.1 canonical warning
    character-exact, as document text — not inside a comment or
    script/style element (FR-019 "visible warning"; Constitution V — the
    risk disclosure must not silently soften). T034e's case 3 is the
    named gate; it lifts from loud-skip to PASS in this commit.
  - Validation is exactly `^[0-9a-f]{32}$` (lowercase hex, exactly 32)
    BEFORE any storage write; every invalid input — empty, short, long,
    uppercase, non-hex, whitespace-padded — produces the error status and
    ZERO `storage.local.set` touches (fail-closed edge validation;
    data-model.md §5; a stored malformed token would poison router.js's
    SOCKS5 password, FR-002).
  - A valid save persists through `StargateStorage.setDeviceToken`:
    `device.bearerToken` equals the input, `tokenStoredAt` is the current
    hour-bucket, and an existing `name` survives (merge, not replace —
    data-model.md §5; storage.test.js A4 already gates the wrapper side).
  - A storage failure NEVER reports success to the user: the submit path
    catches the rejection and renders the failure status — never the
    saved status, never an unhandled rejection on the page document
    (storage.test.js A5 swallow-probe lesson: a real storage failure
    during save must not resolve as success; T034b fail-closed-without-
    throwing precedent).
  - Zero new context globals; exactly one submit listener; no
    `browser.*` namespace beyond `storage.local` (via `StargateStorage`);
    status writes via `textContent` only; DOM lookups target only the
    pinned ids; no storage I/O at eval time (T034g namespace-surface
    doctrine; T034c §Analysis "Pinned surface").
  - The page wires `../lib/storage.js` + `options.js` as external
    scripts and provides the pinned element ids — a rename on either
    side fails the suite (the popup.test.js `popupHtmlProvides...`
    id-drift gate, applied to this page).
  - Form default submission is prevented (`preventDefault`), so a save
    never reloads the page and silently discards the status line.
- **Gated:**
  - All must-holds above are gated by named cases in
    `extension/options/options.save.test.js` (written FIRST, RED before
    impl) plus the lifted T034e case 3 — executed fail-closed by
    verify.sh Gate 2b via `extension/run-tests.sh` discovery.
  - `scripts/check-license-headers.sh` gates the SPDX headers.
  - Pre-commit gitleaks gates fixture hygiene (computed fixtures per the
    T052 convention).
  - `scripts/lint-ticket.py` gates ticket well-formedness; manifest.test.js
    M6 already gates the options_ui registration.
- **Residue** (documented, not silently dropped):
  - **Visual presentation of the warning is unpinned** (element type,
    class, CSS) — the no-DOM test model gates text presence in rendered
    document text only (inherited T034e residue); a `role="note"` +
    minimal inline style is this ticket's review-facing choice, not a
    gated property.
  - **No configured-state display:** the page shows neither whether a
    token is stored nor its value (deliberate, grounding finding 7). A
    user misreading the empty field as "not configured" has no in-page
    correction; the popup/connectivity surfaces carry that signal.
  - **Format-only validation:** a well-formed token unknown to the
    control plane passes this page and fails at request time — FR-019's
    "MUST match one of the tokens in the config file" is enforced
    server-side (contract tests T020/T024/T028 own the rejection path),
    untestable in this page's unit scope.
  - **Enter-key vs click submit:** the real form `submit` event covers
    both; the suite fires the registered listener directly (browser-
    equivalent by construction, not observable here).
  - **The page trusts `../lib/storage.js` verbatim** — the wiring case
    pins the `src` attributes textually, so module drift fails loud, but
    the page has no defense against a corrupted sibling file (MV2 CSP
    same-origin makes this extension-internal, same trust boundary as
    the background page's script list, manifest M4).

## Acceptance

1. **`optionsHtmlRendersCanonicalStringByteForByte` (T034e case 3)
   lifts:** with `extension/options/options.html` landed, the loud skip
   becomes a PASS inside this commit's verify run — the rendered text
   (comments/script/style excluded, tags stripped, minimal entities
   decoded, whitespace collapsed) carries the data-model.md §5.1
   canonical warning character-exact as document text.
2. **New named suite `extension/options/options.save.test.js`, authored
   FIRST and RED before the impl lands** (router.test.js precedent;
   Constitution VII), with cases: (a) surface — zero new context
   globals, exactly one submit listener, zero storage touches at eval
   time, DOM lookups only `token-form`/`bearer-token`/`status`; (b)
   invalid-token matrix (empty, 31-hex, 33-hex, uppercase hex, non-hex,
   whitespace-padded valid) → error status, `preventDefault` called, and
   ZERO `storage.local.set` touches; (c) valid computed 32-hex token →
   exactly one `setDeviceToken` write, `device.bearerToken` equals the
   input with hour-bucket `tokenStoredAt` and a pre-existing `name`
   preserved, saved status rendered; (d) storage-set rejection → failure
   status, never the saved status, no unhandled rejection (swallow
   probe, storage.test.js A5 lesson); (e) html wiring — the pinned script
   srcs (`../lib/storage.js`, `options.js`) and pinned element ids are
   present (id-drift fails loud both directions).
   Fixtures are computed per the T052 convention (no 32-hex literals —
   gitleaks).
3. **`extension/options/options.html`** implements the FR-019 minimum:
   single "Bearer token" field, "Save" button (quickstart Step 4 prose),
   the canonical warning as visible document text, and exactly the two
   external script tags — no inline scripts/handlers (MV2 CSP).
4. **`extension/options/options.js`** implements the pinned surface: one
   named IIFE, zero new globals, `^[0-9a-f]{32}$` validation at the
   edge, persistence via `StargateStorage.setDeviceToken`, fail-closed
   status mapping.
5. **Runnable:** `sh extension/run-tests.sh` exits 0 with no skips in the
   options files; `node extension/options/options.test.js` and
   `node extension/options/options.save.test.js` pass standalone;
   `scripts/verify.sh` green from repo root.
6. **Diff scope:** `extension/options/options.html` (new),
   `extension/options/options.js` (new), `extension/options/options.save.test.js`
   (new), this ticket's grounding/status edits, STATUS regen. NO edit to
   `options.test.js` (the frozen T034e gate), `lib/storage.js`,
   `manifest.json`, quickstart, or data-model (the T034e two-replica
   equality must hold untouched).
7. **Falsification record** (§Notes): the suite is exercised in a
   throwaway copy against impl mutations — validation deleted (invalid
   token persisted → case (b) fails on the storage touch), lowercase
   anchor dropped (uppercase accepted → case (b) fails on the matrix),
   saved status outside the try (rejection still reports success → case
   (d) fails), listener double-registered (case (a) fails).

## Out-of-scope

- `extension/popup/popup.html` / `popup.js` and the route indicator
  (T057; the sendMessage round-trip assertion T054 assigned to T057/
  T033) — different page, different suite.
- Device `name` enrollment (control-plane flow, T037/T039): the options
  page writes the token only and relies on `setDeviceToken`'s merge to
  preserve a stored `name` — it never invents device fields.
- Displaying or prefilling the stored token (§Analysis decision 7) and
  any "is a token configured" state UI (residue: popup/T034f carry it).
- Changing the canonical warning string or either replica — a string
  change is a data-model.md §5.1 amendment with same-PR re-sync (T034e
  §Out-of-scope), never an edit here.
- Credential-grade storage (password manager, keyring): research.md §6
  rejected the alternatives for v1; revisiting requires a
  credential-grade WebExtensions API (FR-019 resolution note).
- Any control-plane token-issuance or match behavior (FR-019's server
  side; T020/T024/T028 contracts).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded on
2026-09-06 (§Analysis; no amendment consumed — the body is consistent with
FR-019, data-model.md §5/§5.1, quickstart Step 4, and research.md §6 as
landed).

The ticket title's trailing fragment "and `extension/options/options" is a
60-char truncation artifact of `bootstrap-tickets.sh`; the tasks.md body is
authoritative: **…and `extension/options/options.js`**.

**Falsification record (2026-09-06, implement phase).** Throwaway copy at
`/tmp/t056-falsify` (options + lib/storage.js). Pristine control: 7/7
PASS. Impl mutations, each re-run against the full suite:

1. *validation deleted* (`if (false)`) → `invalidTokensRenderError...`
   fails on the ZERO-storage-touches pin (an invalid token would reach
   storage.local). CAUGHT.
2. *lowercase anchor dropped* (`/i`) → `invalidTokensRenderError...`
   fails on the uppercase-hex matrix entry (data-model.md §5 is
   lowercase-only). CAUGHT.
3. *saved status before the write resolves* (`render(SAVED)` hoisted
   above the `try`) → `storageFailureRendersFailureStatusNeverSaved`
   fails (the swallow — success reported on a rejected write; the same
   mutant class storage.test.js A5 pins for the wrapper). CAUGHT.
4. *listener double-registered* → cases 1/2/3/5/6 fail (surface pin;
   duplicate saves per submit). CAUGHT. — First execution of this
   mutation was a harness-script quoting bug that silently ran PRISTINE
   (7/7 "pass"): re-derived with an anchor-presence check before the
   replace (`ANCHOR NOT FOUND` guard) and a registration-count print.
   Recorded per the honest-mutant doctrine — the suite was never
   weakened; the mutation itself was.
5. *preventDefault dropped* → cases 2 and 6 fail (page reload would
   discard the status line). CAUGHT.

T034e's own suite was exercised separately: its html case lifts from the
loud skip to PASS on the real options.html — not re-mutated here (T034e
§Acceptance 6 owns that battery).

