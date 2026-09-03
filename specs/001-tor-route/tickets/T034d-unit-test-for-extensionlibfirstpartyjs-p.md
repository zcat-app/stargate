---
id: T034d
title: 'Unit test for `extension/lib/firstparty.js` (Principle VII'
status: done
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T034d
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh
parallel: true
files_budget: 6   # raw-diff-path counting (run-task.sh): 1 code file + this
                  # ticket + STATUS.md regen; ticket-template.md excludes
                  # specs/ paths from the budget
privacy_critical: true   # flipped from the bootstrap `false` at grounding —
                         # the ticket body's own argument: FR-002 stream
                         # isolation IS this module's return string; FR-002
                         # is constitution-listed privacy-critical (Principle
                         # VII table, spec.md constitution-check row)
complexity: low
risk: low
round_cap: 2
test_for: [T053]   # reverse view: the impl ticket this suite gates (T053
                   # carries tests_first: [T034d]; it must NOT edit this test)
constitution_refs:
  - "III: Privacy-Preserving by Construction (per-first-party stream isolation is FR-002's operationalisation)"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
spec_refs:
  - "specs/001-tor-route/spec.md §FR-002 (SOCKS5 username = the first-party domain string; .onion-specific rules: top-level navigation → the onion address itself, first-party subresources → the parent page's onion address)"
  - "specs/000-architecture/spec.md §14.3 step 1 (compute first-party domain: prefer requestDetails.documentUrl / originUrl; else fall back to the request URL's eTLD+1) — the clearnet pass-through cases (c)/(d) pin this at the strength the body states"
  - "specs/001-tor-route/spec.md §FR-011 (the torrc half of the isolation pair: `IsolateSOCKSAuth` makes the username this module computes the circuit-isolation signal; this suite gates the string, T058/T059/T061 gate the circuits)"
  - "specs/001-tor-route/plan.md §\"Large-scale refactoring\" extension layout (`lib/firstparty.js` — eTLD+1 + documentUrl; no build step, no third-party JS deps)"
  - "specs/001-tor-route/research.md §10 (Node 20 LTS CI pin; node:test + node:assert; vm.runInNewContext + synthesized browser global; no source contortion)"
decision_refs:
  - "specs/001-tor-route/tickets/T068a-contract-test-for-the-response-header-in.md (round-1 APPROVE precedent: a tests-first ticket lands GREEN via self-skips that gate on the impl's surface and lift when it exists)"
  - "specs/001-tor-route/tickets/T034b-unit-test-for-extensionbackgroundhardeni.md (the direct extension-plane precedent: same discovery runner, same self-skip-then-bite shape, §Analysis as the impl ticket's authorization boundary, falsification protocol; round-1 APPROVE)"
  - "specs/001-tor-route/tickets/T035a-unit-test-for-tokenloaderjava-t035-diff.md (most recent application of the precedent; the tests-first-before-impl-pairing method this ticket follows)"
reviews: { round: 1, date: 2026-09-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
out_of_scope:
  - extension/lib/firstparty.js
  - extension/background/router.js
  - extension/lib/storage.js
---

# T034d: Unit test for `extension/lib/firstparty.js` (Principle VII

## Context

Principle-VII unit test for the extension's first-party-domain computation
(`extension/lib/firstparty.js`) — the module whose return string IS the
SOCKS5 username FR-002 mandates on every routed request. An incorrect
computation collapses two distinct origins onto one Tor circuit
(`IsolateSOCKSAuth`, FR-011, isolates by auth credential, so equal
usernames share a circuit), which is precisely the privacy property this
entire feature exists to deliver. Pure-logic test using Node's built-in
`node:test` runner (no third-party deps; no-build-step constraint per
plan.md §"Technical Context" and research.md §10). The module is pure —
it takes a `requestDetails`-shaped object and returns a string — so the
test loads it via `vm.runInNewContext()` per the T034b pattern with an
**empty `browser` global** (its emptiness is itself asserted — §Analysis).
Pairs with T053 (impl); T053 is gated by this suite and must conform to
the pinned surface in §Analysis.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `extension/lib/firstparty.js` (Principle VII — FR-002 stream isolation is driven by the *first-party-domain string* this module computes; an incorrect computation collapses two distinct origins onto one Tor circuit and breaks the privacy property the entire feature exists to deliver). Pure-logic test; no browser mock needed for the function itself (the module takes a `requestDetails`-shaped object and returns a string), so the test imports it via `vm.runInNewContext()` per the T034b pattern with an empty `browser` global. Cases (each a separate `it()`):
> (a) Top-level `.onion` navigation: `requestDetails.documentUrl` is the onion address itself, `originUrl` absent → returned first-party equals the onion address verbatim (no eTLD reduction on `.onion` — onion addresses are flat).
> (b) Subresource fetch within a `.onion` document: `requestDetails.documentUrl` is the parent page's onion, `url` is a different onion CDN address → returned first-party equals the parent onion (the *document's* origin, not the subresource's — this is what binds same-tab subresources to one Tor circuit).
> (c) Clearnet documentUrl (used in later features; this feature passes through but the function must still behave correctly so US2's same-origin shared-circuit invariant holds for future Direct/Mixnet routes): `documentUrl = https://news.example.com/article` → returned first-party `example.com` (eTLD+1 reduction).
> (d) `documentUrl` and `originUrl` both missing → fall back to the request URL's eTLD+1.
> (e) Two distinct onion addresses through two distinct requests → two distinct return strings (the *invariant* that drives Tor's `IsolateSOCKSAuth` correctness — verified by string inequality, not by any Tor-side assertion which lives in T058/T059/T061).
> (f) Same onion address through two distinct requests → two *equal* return strings (the same-origin shared-circuit case from US2 acceptance scenario 3; data-plane forwards verbatim so the username equality is what gives Tor the signal to reuse a circuit).
> (g) Malformed `documentUrl` (empty string, garbage, non-URL) → function returns an empty string OR throws a sentinel error consistently — the contract is "no silent fallback to a wrong first-party," and the test pins whichever shape T053 ships with so future drift is gated.
> Mock + test live at `extension/lib/firstparty.test.js`; picked up automatically by the T034b discovery script.

## Analysis

Property map (grounding-verified 2026-09-03; required — `privacy_critical:
true` per `docs/process/analysis.md`; the bootstrap `false` is flipped
above with the justification recorded there).

**Grounding findings resolved into this design (body-vs-reality items;
method per T035a/T034b §Analysis):**

1. **The module does not exist yet** (`extension/lib/` is empty —
   verified). It is T053's named artifact, and T053 is sequenced after
   this ticket (`tests_first` pairing; tasks.md §"Notes" forbids bundling
   a test and its impl in one commit). Per the T068a/T034b/T035a
   precedent, the suite lands GREEN via loud self-skips, hard-FAILS on a
   nonconforming surface once the file exists, and every assertion below
   bites from inside T053's own verify run.
2. **No surface name is pinned anywhere** (grep over spec.md, arch §14.3,
   plan.md, contracts/: no function name for this module). Tests-first
   requires the test to name the surface, so this ticket pins it —
   §"Pinned surface" below. That paragraph is T053's authorization
   boundary: if it genuinely cannot host T053's design, that is a
   **refine** escalation against THIS ticket, never an edit to the test.
3. **Body case (g) offers two acceptable shapes** ("returns empty string
   OR throws a sentinel error … pins whichever shape T053 ships with") —
   unimplementable tests-first, since T053 cannot land before this test.
   **Grounding pins the throw shape:** present-but-unparseable
   `documentUrl`/`originUrl` throws an `Error` whose `name` is exactly
   `'FirstPartyError'`. Rationale (FR-002's own failure mode): an
   empty-string return is a *routable* username — every malformed-
   documentUrl request in the browser would share one SOCKS5 credential
   and therefore one Tor circuit, silently collapsing unrelated origins;
   a sentinel throw makes the failure loud at the only place it can be
   handled (router.js, T054, which can then fail closed) instead of
   encoding it into a circuit identity. The absent-vs-malformed dichotomy
   is load-bearing and pinned: an **absent** `documentUrl` key is
   "missing" (case (d) fallback applies); a **present-but-unparseable**
   value — the empty string `''` included, per the body's own list — is
   malformed (throw). Treating `''` as missing would be exactly the
   "silent fallback to a wrong first-party" case (g) forbids: the caller
   supplied a document URL and must know it was refused, not silently
   routed under request-URL identity.
4. **eTLD+1 strength.** Case (c) pins `news.example.com` → `example.com`.
   Public-suffix nuance (`.co.uk` and friends) is deliberately NOT pinned:
   this feature routes `.onion` only (spec scope: "Other hostnames are
   out of scope for this feature"), the clearnet path is pass-through for
   later features, and a publicsuffix list would be a third-party dep the
   plan forbids (research §10). The body's stated strength is what gates.
5. **Purity is a pinned property, not just a convenience.** The body's
   "no browser mock needed … empty `browser` global" is made testable:
   the sandbox's `browser` is an access-RECORDING empty object, and one
   case asserts firstparty.js touched it zero times across the canonical
   inputs. If firstparty.js ever reaches into `browser.storage` (or any
   API) directly, the router-composition assumption T054 builds on —
   router owns ALL storage/API access, firstparty is a pure string
   function — is false, and this suite catches it.

**Pinned surface (the ONLY surface assumption; everything else is
observable through plain returns):** `firstparty.js` is a browser-global
MV2 script (plan.md extension layout: `lib/firstparty.js`, loaded by the
background page before router.js consumes it — no exports, no wrapper).
Evaluating it in a fresh context exposes exactly one new global:

- `firstPartyDomain(requestDetails)` — a function; takes a
  `requestDetails`-shaped object (`url` required string;
  `documentUrl`/`originUrl` optional strings, *absent keys* meaning
  missing per FR-002/arch §14.3) and returns a **string**: the onion
  address (verbatim hostname, no reduction) when the governing URL is
  `.onion`, else the governing URL's eTLD+1; the governing URL is
  `documentUrl` when present, per case (b)'s document-binding (the
  `documentUrl`-over-`url` precedence is what the body's cases pin — see
  Residue for the unpinned `originUrl` steps of arch §14.3's preference
  order). Present-but-unparseable `documentUrl`/`originUrl` → throws
  `Error` with `name === 'FirstPartyError'` (finding 3).

The test sandbox provides exactly `{ browser: <recording, empty>, URL,
console }` — the host's WHATWG `URL` because it is the one non-ECMAScript
builtin a URL-computing module may legitimately need (spec-identical to
the browser's), and nothing else: any further global the impl reaches for
is a loud ReferenceError in the suite, which is the conformance signal,
not a test bug.

- **Must hold:**
  - **Onion identity is flat (FR-002 `.onion` extension):** a top-level
    `.onion` navigation's first-party is the onion address itself — no
    eTLD reduction (case a).
  - **Document-scoped binding (FR-002's subresource rule):** a
    subresource of a `.onion` document carries the *document's* onion as
    its first-party, never the subresource's own host (case b) — this is
    what makes same-tab subresources share one circuit.
  - **Clearnet pass-through correctness (arch §14.3 step 1):**
    `documentUrl` host reduces to its eTLD+1 (case c); with `documentUrl`
    and `originUrl` both absent, the request `url`'s eTLD+1 is the
    fallback (case d).
  - **The FR-002 invariant, string-level (Constitution III):** distinct
    first parties → distinct username strings (case e); the same first
    party across distinct requests → equal strings (case f). The
    Tor-side circuit behaviour this signal drives is T058/T059/T061's,
    deliberately not duplicated here.
  - **No silent fallback (case g):** present-but-unparseable
    `documentUrl`/`originUrl` throws `FirstPartyError`, consistently for
    every malformed shape tested — never a wrong-string return, never a
    silent request-URL fallback for a *supplied* value.
  - **Purity:** zero `browser.*` touches across the canonical inputs
    (finding 5).
- **Gated:** verify.sh Gate 2b executes the suite via
  `extension/run-tests.sh` (fail-closed on non-zero exit) — the runner's
  discovery pattern picks this file up with no runner amendments
  (run-tests.sh header comment names T034d explicitly);
  `scripts/check-license-headers.sh` gates the SPDX header; the
  pre-commit secret scanner gates fixture hygiene;
  `scripts/lint-ticket.py` gates ticket well-formedness.
- **Residue** (documented, not silently dropped):
  - **`originUrl` steps of arch §14.3's preference order** (documentUrl
    absent + originUrl present; both present and differing) are not among
    the body's cases and are unpinned by this suite — gated by T053
    review, and by this suite only insofar as cases (b)/(d) pin the two
    endpoints of the order.
  - **eTLD+1 algorithm strength** beyond case (c)'s pinned example —
    public-suffix nuance unpinned by design (finding 4).
  - **`FirstPartyError` message copy** — only `name` is pinned.
  - **URL forms**: schemes other than http/https, ports, userinfo, IPv6
    literals, trailing-dot hosts — unpinned.
  - **Junk-typed inputs** (`documentUrl: 123`, arrays) — the sentinel
    contract plausibly covers them, but only the body's string-shaped
    malformations are pinned.
  - **`requestDetails` itself missing/undefined** — out of the body's
    scope; router.js (T054) owns the caller contract.

## Acceptance

Named test: `extension/lib/firstparty.test.js` (Node built-in `node:test`
+ `node:assert`; loads `extension/lib/firstparty.js` via
`vm.runInNewContext` with the sandbox pinned in §Analysis). Named runner
(pre-existing, zero amendments): `extension/run-tests.sh`. Runnable
command: `scripts/verify.sh` green from repo root (Gate 2b = `cd
extension && ./run-tests.sh`); fast inner loop: `cd extension &&
./run-tests.sh`.

1. The seven body cases — each a separate `test()`, self-skipping with a
   loud Principle-VII marker naming T053 until `firstparty.js` exists,
   hard-FAILING on a nonconforming surface (missing or non-function
   `firstPartyDomain` global), then driving the real module:
   `onionTopLevelNavigationReturnsOnionAddressVerbatim` (a);
   `onionSubresourceBindsToParentDocumentOnion` (b);
   `clearnetDocumentUrlReducesToEtldPlusOne` (c);
   `missingDocumentAndOriginUrlsFallBackToRequestEtldPlusOne` (d);
   `distinctOnionsYieldDistinctFirstPartyStrings` (e);
   `sameOnionAcrossRequestsYieldsEqualFirstPartyStrings` (f);
   `malformedDocumentUrlThrowsSentinelNeverSilentFallback` (g — `''`,
   garbage text, and a scheme-only string each throw, all with
   `name === 'FirstPartyError'`, and no return-shape fallback).
2. The purity case `firstPartyModuleNeverTouchesBrowserApis`: one fresh
   context, every canonical input from cases (a)–(g) driven through it,
   the recording `browser` reports zero property touches (finding 5).
3. The onion fixture addresses are syntactically plausible v3 addresses
   (56 base32 chars + `.onion`); checksum validity is irrelevant to this
   pure-logic contract and is not asserted. Clearnet fixtures use https,
   onion fixtures http (matching how onion services are actually
   reached); no scheme-specific behaviour is pinned beyond what the
   cases state.
4. Pre-T053 state is GREEN, not red: verify.sh Gate 2b passes with the
   eight cases reported skipped (T068a-precedent tests-first state; the
   loud skip IS the failing-test signal tasks.md §"Notes" requires be
   separable from T053's impl commit). This ticket introduces no
   `extension/lib/firstparty.js` and no extension source changes at all.
5. No third-party modules, no `package.json` introduced; the file
   carries the Apache-2.0 SPDX header
   (`scripts/check-license-headers.sh` stays green).
6. §Analysis's pinned-surface paragraph is T053's authorization
   boundary: T053 must NOT edit `firstparty.test.js`; a genuine surface
   conflict is a refine escalation against THIS ticket.

## Out-of-scope

- **`extension/lib/firstparty.js` itself** — T053's named artifact. This
  ticket must not create it; the suite self-skips until T053 lands it,
  then gates T053's verify.
- **`extension/background/router.js`** — T054's surface: `proxy.onRequest`
  wiring, the SOCKS5 descriptor (`username` = this module's return,
  `password` = bearer token, `proxyDNS: true`), blocklist and per-domain
  rule lookups, and the fail-closed handling of `FirstPartyError`.
- **`extension/lib/storage.js`** — the per-domain rule source; untouched
  and unloaded here (purity case forbids this module reading it anyway).
- **Tor-side circuit assertions** (distinct circuits per distinct
  first-party in the running stack) — T058/T059/T061 per the body.
- **Publicsuffix-strength eTLD+1** — finding 4 / Residue.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded
2026-09-03: surface pinned (finding 2), case (g) shape pinned to the
throw sentinel (finding 3 — the body's "whichever shape T053 ships with"
is unimplementable tests-first and was resolved per the
T068a/T034b/T035a authorization-boundary method), `privacy_critical`
flipped true with justification in frontmatter.

tasks.md §"Notes" (binding): "never bundle a test and its corresponding
implementation into one commit (the failing-test signal is part of the
audit trail)" — under the T068a precedent the signal is the loud skip in
this ticket's commit, lifting to assertions inside T053's commit.

**Falsification record (2026-09-03, implement phase).** The suite was
exercised in a throwaway copy against a conforming reference stub and
seven drift mutations. 8/8 pass on the stub; each mutation trips its
named case — onion identity collapsed to the TLD →
`onionTopLevelNavigation…` + `onionSubresourceBinds…` +
`distinctOnionsYieldDistinct…`; address truncated (drops `.onion`) →
the two onion-identity cases; subresource misbound to the request URL →
`onionSubresourceBindsToParentDocumentOnion` (+ (g)); empty
`documentUrl` silently treated as missing →
`malformedDocumentUrlThrowsSentinelNeverSilentFallback`; generic
`TypeError` instead of the sentinel → same (g) case; surface renamed
(`firstParty`) → conformance hard-fail on all 8 cases, never a silent
skip; `browser.storage` read → `firstPartyModuleNeverTouchesBrowserApis`.
Two tooling notes from the exercise: an onion-host "eTLD reduction"
mutation was VACUOUS (a v3 onion host is single-label, so a
last-two-labels reduction is identity-preserving — the suite correctly
pins the verbatim return value, not the algorithm), and the first round
caught a real suite bug: the sentinel validator originally used a
host-realm `instanceof Error`, which rejects the vm-context's own Error
realm — replaced with a duck-typed `name` check (assert.throws already
guarantees something was thrown).
