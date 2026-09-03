---
id: T034e
title: 'Unit test for the canonical `storage.local` warning text (Principle VI'
status: done
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T034e
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # T096/M6: removed inverted T056 dep — the test must NOT wait on its impl (Constitution VII)
parallel: true
files_budget: 6   # raw-diff-path counting (run-task.sh): 1 code file + this
                  # ticket + STATUS.md regen; ticket-template.md excludes
                  # specs/ paths from the budget
privacy_critical: true
complexity: low
risk: low
round_cap: 2
test_for: [T056]   # reverse view: the impl ticket this suite gates (T056
                   # carries tests_first: [T034e] + blocked_by: [T009, T034e])
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "V: Honest Threat Model (the user-facing risk disclosure must not drift/soften silently)"
spec_refs:
  - "specs/001-tor-route/data-model.md §5.1 (the canonical string — single source of truth; 'Drift between options.html's rendered text and the string above is a contract violation; the test gates against silent edits to either side')"
  - "specs/001-tor-route/spec.md §FR-019 (options page: single token field persisted to storage.local with a visible warning that storage.local is not credential-grade; canonical text pinned in data-model.md §5.1)"
  - "specs/001-tor-route/quickstart.md §Step 4 (replica (c) — the operator-facing quote of the canonical string)"
  - "specs/001-tor-route/research.md §6 (rationale origin of the warning; the doc cross-reference is deliberately NOT part of the user-facing string)"
  - "specs/001-tor-route/research.md §10 (Node 20 LTS CI pin; node:test + node:assert; no third-party JS deps, no package.json)"
decision_refs:
  - "specs/001-tor-route/tickets/T068a-contract-test-for-the-response-header-in.md (round-1 APPROVE precedent: a tests-first ticket lands GREEN via self-skips that gate on the impl's surface and lift when it exists)"
  - "specs/001-tor-route/tickets/T034b-unit-test-for-extensionbackgroundhardeni.md (the direct extension-plane precedent: same discovery runner, same self-skip-then-bite shape, same falsification protocol; round-1 APPROVE)"
  - "specs/001-tor-route/tickets/T035a-unit-test-for-tokenloaderjava-t035-diff.md (most recent application of the precedent; the stale-body-refine method this ticket's §Analysis follows)"
reviews: { round: 1, date: 2026-09-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T034e: Unit test for the canonical `storage.local` warning text (Principle VI

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for the canonical `storage.local` warning text (Principle VII; FR-019). Same `vm.runInNewContext()` + handwritten `browser` mock pattern as T034b (no third-party JS deps). Asserts byte-for-byte presence of the data-model.md §5.1 canonical string in **all three** of: (a) `extension/options/options.html`'s rendered text; (b) `specs/001-tor-route/data-model.md` §5.1 (the source of truth); (c) `specs/001-tor-route/quickstart.md` Step 4 (the operator-facing quote). The test extracts (b) and (c) via blockquote-fence matching and fails if any of the three drift. data-model.md §5.1 is the single source of truth; the test gates drift in either of the two replicas. Mock + test live at `extension/options/options.test.js`; picked up automatically by the T034b discovery script. Pairs with T056 (impl) — T034e MUST be authored and failing before T056 lands; never bundle the failing-test signal with its implementation in a single commit (tasks.md §"Notes").

## Analysis

Property map (grounding-verified 2026-09-03; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (three body-vs-reality
items; method per T035a/T034b §Analysis):**

1. **Body's "`vm.runInNewContext()` + handwritten `browser` mock pattern"
   → machinery inapplicable, discipline carried over.** There is no script
   to evaluate: the surface under test is *static markup* (`options.html`),
   and `options.js` is T056's artifact, not this ticket's target. A vm
   sandbox with a `browser` global has nothing to load. What carries over
   from T034b is the discipline: `node:test` + `node:assert`, Node
   built-ins only, no `package.json` (research.md §10), picked up by the
   `extension/run-tests.sh` discovery glob with no runner amendment
   (verified: the glob `find . -name '*.test.js' -not -path './dist/*'`
   already reaches `options/`), license header, self-skip-then-bite
   tests-first shape.
2. **Body's "MUST be authored and failing before T056 lands" →
   operationalized by the T068a/T035a/T034b landed precedent.** A suite
   that hard-fails today would red `verify.sh` Gate 2b and could not land;
   T034b (round-1 APPROVE) states the resolution: "under the T068a
   precedent the signal is the loud skip in this commit, lifting to
   assertions inside T055's commit" — here, inside T056's. The ordering
   constraint is additionally structural: T056 frontmatter carries
   `blocked_by: [T009, T034e]` and `tests_first: [T034e]`.
3. **Two of the three replicas exist today** (`data-model.md` §5.1 and
   `quickstart.md` Step 4 — verified byte-identical as hard-wrapped
   blockquotes); only replica (a) `options.html` is absent. The suite
   therefore splits in two layers, exactly the T035a pattern:
   - **Oracle layer (green now):** extract the canonical string from
     §5.1 by blockquote-fence matching (first `>` blockquote after the
     `### 5.1` heading, within section bounds), extract the quickstart
     Step 4 quote the same way (after `## Step 4`), and assert the two
     are character-exact equal after markdown soft-wrap join. This gates
     drift between the two spec replicas **from today** — the task
     body's "gates drift in either of the two replicas" is live in this
     commit for replica (c).
   - **Replica gate (self-skips until T056, then bites):** while
     `extension/options/options.html` is absent, the (a) case skips with
     a loud Principle-VII marker. Once present, its extracted rendered
     text must carry the canonical string character-exact; present-but-
     drifted is a hard FAIL naming expected vs actual (the conformance
     gate — a silent re-skip would let T056 ship ungated, T034b §Analysis).

**Pinned surface (the ONLY surface assumption on T056):**
`extension/options/options.html` exists as static markup whose document
text — after render-modeling normalization — contains the canonical
string. Nothing else is pinned: no element id/class/tag choice, no
document structure, no `options.js` behavior. Render-modeling
normalization (no DOM and no third-party parser available under the
no-deps constraint): strip HTML comments and `script`/`style` elements,
strip remaining tags, decode the minimal entity set (`amp`, `lt`, `gt`,
`quot`, `apos`, `#39`), collapse whitespace runs to single spaces. Both
sides of the equality are normalized the way real renderers render:
markdown soft-wrapped blockquote lines join with single spaces, and HTML
collapses whitespace runs — so "byte-for-byte" is character-exact on the
*rendered* string, which is what data-model.md §5.1 pins ("the warning
text **rendered** in options.html").

- **Must hold:**
  - **Single source of truth stays single (data-model.md §5.1):** the
    test *derives* the canonical string from §5.1 by extraction and
    never hard-codes a fourth copy; a sanctioned string change is a
    data-model.md §5.1 edit re-synced to both replicas in the same PR,
    and the suite passes again without test edits.
  - **Replica (c) gated from today:** quickstart.md Step 4's quote is
    character-exact equal to the §5.1 extraction (FR-019 / data-model
    §5.1; Constitution V — the risk disclosure must not silently soften).
  - **Replica (a) gated from the moment it exists:** options.html's
    rendered text carries the canonical string character-exact; the
    string must appear as *document text* — placement inside a comment
    or script/style element does not satisfy "rendered" (FR-019 "visible
    warning").
  - **No silent passes:** a missing §5.1 heading, a missing Step 4
    section, or a failed extraction is a loud FAIL, never an empty-string
    equality; only the file-absent state skips, with a loud Principle-VII
    marker naming the gate it lifts for.
  - **Green in this commit, biting in T056's:** `sh extension/run-tests.sh`
    exits 0 now with exactly one skip (the (a) case); every assertion
    bites inside T056's own verify run (T068a precedent).
- **Gated:**
  - The suite itself is the gate for all must-holds: `verify.sh` Gate 2b
    executes `extension/run-tests.sh` and fails closed on non-zero exit.
  - `scripts/check-license-headers.sh` gates the SPDX header.
  - Pre-commit secret scanner gates fixture hygiene (no token-shaped
    strings in fixtures).
  - `scripts/lint-ticket.py` gates ticket well-formedness.
- **Residue** (documented, not silently dropped):
  - **DOM shape of the warning is unpinned** — element type, class, and
    CSS visibility are T056 review concerns; this ticket pins text
    presence in document text only (data-model §5.1 pins the string, not
    the markup).
  - **Entity decoding is a minimal set.** A hypothetical encoding of the
    string via exotic numeric entities beyond `&#39;` could evade the
    decode and fail (fail direction: loud, safe). The canonical string
    contains no character that *requires* an entity, so a conforming
    T056 needs none.
  - **Whitespace-only re-wraps of either markdown blockquote are
    invisible by design** — re-wrapping is a rendering no-op under the
    soft-wrap join; character-level drift (wording, punctuation, case)
    trips the equality.
  - **Exclusivity is unpinned (falsification finding, 2026-09-03):** the
    case asserts *presence* of the exact string; a page carrying both the
    exact string and a drifted duplicate passes. Count-pinning would
    over-constrain the markup this ticket deliberately leaves open (the
    options page has exactly one warning by design, T056); a hidden
    exact-text decoy is likewise outside the no-DOM model and falls under
    the DOM-shape residue above.
  - **A future move of the warning into a JS-injected node** would fail
    the static-text gate. That failure is correct under today's contract
    ("rendered in `extension/options/options.html`"); changing it is a
    data-model.md §5.1 amendment, not a test edit.

## Acceptance

1. **`canonicalStringIsPinnedInDataModelSection51`** (named test, green in
   this commit): extracts the first blockquote after the `### 5.1` heading
   of `specs/001-tor-route/data-model.md` (section-bounded, soft-wrap
   joined) and asserts a shape anchor — starts `Your bearer token will be
   saved`, contains `storage.local`, ends `credential-grade alternative
   for extensions.` — so a failed/empty extraction can never satisfy an
   equality downstream.
2. **`quickstartStep4ReplicatesCanonicalStringByteForByte`** (named test,
   green in this commit): extracts the first blockquote after the
   `## Step 4` heading of `specs/001-tor-route/quickstart.md` the same way
   and asserts it is character-exact equal to the §5.1 extraction
   (replica (c) drift gate, live from today).
3. **`optionsHtmlRendersCanonicalStringByteForByte`** (named test,
   self-skipping in this commit): while `extension/options/options.html`
   is absent it skips with a loud Principle-VII marker naming the T056
   gate it lifts for; once present, it extracts the rendered text per the
   §Analysis normalization (comments/`script`/`style` excluded, tags
   stripped, minimal entities decoded, whitespace collapsed) and asserts
   the §5.1 canonical string appears character-exact — a present-but-
   drifted file is a hard FAIL naming expected vs actual, never a silent
   skip (conformance gate; bites inside T056's own verify run).
4. **Runnable:** `sh extension/run-tests.sh` discovers
   `options/options.test.js` with no runner amendment and exits 0 in this
   commit's state (two passes + exactly one skip — case 3);
   `scripts/verify.sh` green from repo root.
5. **Diff scope:** the commit adds only
   `extension/options/options.test.js` plus this ticket's grounding/status
   edits and the STATUS regen — no `options.html`, no `options.js`
   (T056's artifacts; "never bundle the failing-test signal with its
   implementation in a single commit"), no `run-tests.sh` amendment, no
   edit to `background/hardening.test.js`.
6. **Falsification record** (§Notes): the suite is exercised in a
   throwaway copy against (i) a conforming reference `options.html` stub
   → case 3 passes; (ii) drift mutations of replica (a) — paraphrase,
   punctuation change, string confined to a comment, string confined to a
   `<script>` — case 3 hard-fails each, naming expected vs actual; (iii)
   replica (c) drift (quickstart quote edit) → case 2 fails; (iv) §5.1
   heading removal → case 1 fails loudly (no silent pass).

## Out-of-scope

- Authoring `extension/options/options.html` / `options.js`, the
  `^[0-9a-f]{32}$` token-field validation, and any `options.js` behavior
  test — all T056. This ticket pins the warning *string* only; T056 must
  conform to the §Analysis pinned surface.
- Changing the canonical string anywhere. A string change is a
  data-model.md §5.1 amendment with same-PR re-sync of both replicas
  (spec-kit `amend` path), not a test edit.
- Modifying `extension/run-tests.sh` (discovery already reaches
  `options/` — verified) or `extension/background/hardening.test.js`.
- Gating the warning's visual presentation (element type, class, CSS) —
  §Analysis residue; T056 review concern.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded on
2026-09-03 (this ticket's §Analysis; no amendment consumed — the body is
consistent with data-model.md §5.1, quickstart.md Step 4, and FR-019 as
landed; only stale *machinery* was resolved, items 1–3 there).

The ticket title's trailing "(Principle VI" is a 60-char truncation
artifact of `bootstrap-tickets.sh`; the tasks.md body is authoritative:
**Principle VII; FR-019**.

T034b's falsification protocol is reused verbatim (throwaway copy,
conforming stub, named mutations); any round that catches a real suite
bug gets recorded there like T034b's §Notes does.

**Falsification record (2026-09-03, implement phase).** Throwaway copy at
`/tmp/t034e-falsify` (extension tree + the two spec sources). Canonical
string extracted from §5.1 by the same soft-wrap join the test uses — no
hand-typed copy. Results: (i) conforming stub (hard-wrapped, indented,
`&#39;`-encoded) → case 3 passes; (ii) replica-(a) mutations each trip
case 3 — paraphrase ("stored on disk"), dropped comma after
`storage.local`, string confined to an HTML comment, string confined to
a `<script>`, case drift, suffix truncation; (iii) quickstart quote edit
→ case 2 fails, resync → passes; (iv) §5.1 heading renamed → case 1
fails loudly (no silent pass), restore → passes. Round 1 caught two
*falsification-harness* bugs (both no-op mutations: my sed targeted
"directory, inside" — a substring the canonical string does not contain
— and the case-drift file still carried an unmutated exact copy, so
presence was genuinely satisfied); the suite itself held in every round,
so no suite bug surfaced and no test line changed. The round-1
duplicate-copy observation is recorded as the exclusivity residue in
§Analysis.
