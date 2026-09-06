---
id: T053
title: 'Author `extension/lib/firstparty.js`'
status: in-review
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T053
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T034d]   # T009 derived by scripts/derive-deps.sh; T034d added
                            # at /start 2026-09-06 — the Principle-VII suite gating
                            # this impl (tests_first entries belong in blocked_by)
parallel: true
files_budget: 8   # counted set: extension/lib/firstparty.js + firstparty.edges.test.js (r2 REWORK evidence for the edge guards; specs/ paths exempt per T039 r2/T040 precedent)
privacy_critical: true   # flipped from the bootstrap `false` at grounding — same
                         # argument as T034d's flip: FR-002 stream isolation IS this
                         # module's return string (distinct strings → distinct Tor
                         # circuits via IsolateSOCKSAuth, FR-011); FR-002 is
                         # constitution-listed privacy-critical (Principle VII table)
tests_first: [T034d]   # the suite is done, self-skipping until firstparty.js
                       # exists, then hard-fails on a nonconforming surface
complexity: low   # confirmed at /start 2026-09-06: one pure function against a
                  # pre-existing pinned suite (T034d §Analysis is the contract)
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/tasks.md#T053 (verbatim task body: arch §14.3 first-party computation extended with the feature's .onion rules)
  - specs/001-tor-route/spec.md §FR-002 (SOCKS5 username = the first-party domain string; .onion rules: top-level navigation → the onion address itself, first-party subresources → the parent page's onion address)
  - specs/000-architecture/spec.md §14.3 step 1 (prefer requestDetails.documentUrl / originUrl; otherwise fall back to the request URL's eTLD+1)
  - specs/001-tor-route/spec.md §FR-011 (IsolateSOCKSAuth — the torrc half; this module's string is the isolation signal)
  - specs/001-tor-route/plan.md extension layout (lib/firstparty.js — eTLD+1 + documentUrl; no build step, no third-party JS deps)
decision_refs:
  - specs/001-tor-route/tickets/T034d-unit-test-for-extensionlibfirstpartyjs-p.md (the gating suite; §Analysis "Pinned surface" is this impl's authorization boundary: exactly one new global firstPartyDomain(requestDetails), FirstPartyError sentinel by name, naive two-label eTLD+1 by design (finding 4), zero browser.* touches (finding 5), documentUrl-over-url precedence pinned by cases (b)/(d))
  - specs/001-tor-route/research.md §10 (Node 20 LTS CI pin; no third-party deps, no build step — therefore no public-suffix list; MV2 classic scripts, no exports/wrapper)
constitution_refs:
  - "III: Privacy-Preserving by Construction (per-first-party stream isolation is FR-002's operationalisation; this string is the signal)"
  - "VII: Tests-First for Privacy-Critical and Contract Code (satisfied via done, self-skipping T034d — T068a/T034b/T035a precedent)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T053: Author `extension/lib/firstparty.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/lib/firstparty.js` — first-party-domain computation per arch §14.3 (prefer `requestDetails.documentUrl`/`originUrl` eTLD+1), **extended for this feature with `.onion`-specific rules** that arch §14.3 does not carry: for top-level `.onion` navigation, return the onion address itself; for subresources under a `.onion` document, return the parent page's onion address. **Verified by T034d.**

## Analysis

Property map (grounding 2026-09-06; required — `privacy_critical: true`
after the flip above). The governing analysis is T034d §Analysis — its
"Pinned surface" paragraph is this impl's authorization boundary; the map
below is the impl-side residue view.

**Must hold** (each gated by a named T034d case, except the two
"edges-evidenced" bullets — their guards are unreachable by every named
case's inputs, so r2 pins them via `extension/lib/firstparty.edges.test.js`):
- Onion identity is flat — a `.onion` governing host returns verbatim,
  no eTLD reduction (cases a/e/f; FR-002 `.onion` extension).
- Document-scoped binding — `documentUrl`, when present, is the
  governing URL over the request `url` (case b; subresources of a
  `.onion` document bind to the parent onion).
- Clearnet pass-through — governing host reduces to its eTLD+1 (cases
  c/d; arch §14.3 step 1).
- No silent fallback — a PRESENT-but-unparseable `documentUrl`/
  `originUrl` (the empty string included) throws the `FirstPartyError`
  sentinel (case g; T034d finding 3: an empty-string return would be a
  routable username collapsing unrelated origins onto one circuit).
  Same for a governing URL that PARSES but has no host
  (`about:`/`data:`/`blob:`) — hostname `''` is no first-party at all,
  and `''` is the one routable string the contract forbids above all.
  **edges-evidenced** (r2: case (g)'s inputs — `''`, `'not a url'`,
  `'http://'` — all die at `new URL()` and never reach this branch;
  review-verified r1, mutation-pinned by firstparty.edges.test.js).
- Flat hosts return whole — `.onion` (cases a/e/f) AND IPv4 literals:
  the two-label reduction of `'10.1.2.3'` would collide distinct
  addresses on one shared circuit (`'10.9.2.3'` also reduces to
  `'2.3'`); all-numeric labels can never carry a public suffix, so the
  literal whole is always the non-collapsing return. The IPv4 half is
  **edges-evidenced** (r2: no suite input is an IP literal;
  mutation-pinned by firstparty.edges.test.js, which also pins the
  multi-label `.onion` early return).
- Purity — zero `browser.*` touches (T034d finding 5); router.js (T054)
  owns all API access.

**Gated:** verify.sh Gate 2b (`extension/run-tests.sh`) fail-closed;
`scripts/check-license-headers.sh` on the SPDX header; pre-commit secret
scanner; `scripts/lint-ticket.py`.

**Residue** (documented, honored — not silently dropped; same list as
T034d §Analysis Residue, impl-side): `originUrl` steps of arch §14.3's
preference order are unpinned by the suite — implemented as
documentUrl → originUrl → url (arch §14.3's stated order; reviewed here,
gated by the suite only at the two pinned endpoints). eTLD+1 is the
naive last-two-labels algorithm — public-suffix nuance deliberately not
computed (no third-party PSL dep; research §10; this feature routes
`.onion` only). `FirstPartyError` message copy unpinned — only `name`
is contract. Junk-typed `documentUrl`/`originUrl` fall under the
sentinel (consistent with its contract). `requestDetails` itself
missing/undefined is router.js's (T054) caller contract, not defended
here (edge validation lives at the edge).

## Acceptance

Named test (pre-existing — authored by T034d; NOT edited by this
ticket): `extension/lib/firstparty.test.js` (Node built-in `node:test`;
loads `extension/lib/firstparty.js` via `vm.runInNewContext` with the
sandbox pinned in T034d §Analysis). Named runner (pre-existing, zero
amendments): `extension/run-tests.sh` (verify.sh Gate 2b). Runnable
command: `scripts/verify.sh` green from repo root; fast inner loop:
`cd extension && ./run-tests.sh`.

1. Surface conformance: evaluating `extension/lib/firstparty.js` in a
   fresh context exposes exactly one new global — the function
   `firstPartyDomain(requestDetails)` (T034d §Analysis "Pinned surface";
   the suite's `requireConformance` hard-fails on any other shape).
2. All seven T034d body cases lift from self-skip to pass against the
   real module: (a) top-level `.onion` navigation → the onion address
   verbatim; (b) subresource under a `.onion` document → the parent
   page's onion; (c) clearnet `documentUrl` → eTLD+1; (d)
   `documentUrl`+`originUrl` both absent → request `url` eTLD+1; (e)
   distinct onions → distinct strings; (f) same onion → equal strings;
   (g) present-but-unparseable `documentUrl` (`''`, garbage text,
   scheme-only) → throws with `name === 'FirstPartyError'` — never a
   routable fallback string.
3. Purity: zero `browser.*` property touches across the canonical
   inputs (T034d finding 5).
4. `scripts/verify.sh` GREEN from repo root, with Gate 2b biting —
   no `firstparty.test.js` skip lines in `target/verify.log`; and
   `extension/lib/firstparty.edges.test.js` (r2: evidence for the two
   fail-closed edge guards the frozen suite cannot reach, per the r1
   REWORK) passes with zero skips — hostless governing URLs
   (`about:`/`data:`/`blob:`) throw the sentinel, IPv4 literals return
   whole and stay distinct, multi-label `.onion` returns whole.

## Out-of-scope

- extension/lib/firstparty.test.js   # T034d's artifact — this ticket conforms to it, never edits it (T034d frontmatter: "must NOT edit this test")
- extension/background/router.js     # T054 — owns proxy.onRequest, storage rules, and FirstPartyError fail-closed handling
- extension/lib/storage.js           # T052
- extension/manifest.json            # T051 — owns all registration keys
- extension/background/hardening.js  # T055
- SOCKS5 password handling           # the bearer token is router.js's (T054); this ticket owns only the username string
- Any public-suffix list dependency  # research §10 forbids third-party JS deps; naive two-label eTLD+1 by design (T034d finding 4)

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
