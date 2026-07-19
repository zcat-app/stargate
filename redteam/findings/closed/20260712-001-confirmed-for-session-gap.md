---
id: 20260712-001-confirmed-for-session-gap
status: closed
severity: major
principle: [III, V]
threat-model: 5.4
location: specs/001-tor-route/spec.md:294-301
first-seen-run: 20260712-T091
first-seen-date: 2026-07-12
fix-commit: pending (lands in the T091 start commit on 001-tor-route)
decision-ref: null
closed-date: 2026-07-12
closed-by: stargate-redteam re-review (2026-07-12) — M1 RESOLVED
---

# "Confirmed for this session" runtime gate is underspecified for DoH/DoT/HTTP-3

## What the code does

The T091 amendment rewrites Constitution Principle III bullet 3 so the
DoH/DoT/HTTP-3 hardening guarantee is an "externally verified precondition"
(release-cadence, human-run `prefs.js` grep) and the extension's runtime gate
covers only WebRTC (`privacy.network.peerConnectionEnabled`) and SOCKS5h
(`proxy.ProxyInfo`). The amendment concedes (arch §14.5 Part 2) that the
extension cannot read the DoH/DoT/HTTP-3 prefs at runtime — that is the whole
point of sol-review B4.

Despite that concession, FR-004 (`specs/001-tor-route/spec.md:294-301`) and the
§14.5 Failure UX (`specs/000-architecture/spec.md:959-965`) add a *second*
runtime clause on top of the WebRTC gate:

> "If any precondition fails, **or the profile has not been verified for the
> session**, the extension MUST display a blocking dialog ... and MUST NOT route
> non-Direct requests through port 8881" (FR-004)

> "On any failed gate — WebRTC enabled at runtime, **or the externally verified
> profile not confirmed for this session** — the extension: 1. Displays a
> blocking dialog ... 2. Sets an internal `hardeningOk = false` flag that
> `router.js` (T054) checks before returning a SOCKS descriptor from
> `proxy.onRequest` for non-Direct routes" (§14.5)

No mechanism is defined for how the extension learns whether the out-of-band,
release-cadence, human-run live-e2e test "confirmed" anything for *this* browser
session. The extension has no API to read those prefs (B4) and no defined signal
channel from `tests/live-e2e/mullvad-browser-hardening/run.sh` (which greps
`prefs.js` externally and writes nothing to the extension's `storage.local`).

## Why it leaks

Constitution Principle III's "Why" states: "Privacy claims that depend on
configuration discipline drift over time. Privacy claims enforced by code remain
true under future changes, contributor turnover, and operator mistakes." The
"confirmed for this session" wording asserts a per-session, code-enforced
runtime binding ("`hardeningOk` flag that `router.js` checks") that the
mechanism cannot deliver for three of the four surfaces. This is configuration
discipline dressed in mechanism-language — exactly the pattern Principle III's
"Why" rejects, and a Principle V violation (asserting a privacy property the
mechanism does not deliver).

Concretely, T055's implementer reading FR-004 + §14.5 has exactly three
implementable readings of "confirmed for this session," all of which undermine
the claim:

  (i) A release-time-baked constant that is always "confirmed" — vacuous gate;
      the three surfaces have no runtime check at all, but the spec implies one.
  (ii) A manual `storage.local` flag the user toggles after running the live-e2e
       — pure operator discipline, unmentioned in the spec.
  (iii) Silently equating "WebRTC off ⇒ profile confirmed" — collapses three
       surfaces into one at runtime while the docs describe four, hiding the
       residue behind a single-pref gate.

The threat model (THREAT-MODEL.md §5.4/§5.5) honestly names the *residue*
(post-verification drift not caught at PR cadence), but FR-004/§14.5's "for this
session" wording contradicts that honesty by implying a per-session runtime
confirmation. An adversary who flips DoH on between release runs (via another
extension, a Firefox update, or `about:config`) gets DNS leaks to the DoH
provider on every non-Direct request, and the extension's `hardeningOk` gate
does not fire because no defined signal tells it the profile drifted.

No extension runtime code exists in the tree yet (`extension/{background,options,
popup,lib}/.keep` placeholders only), so this is not a leak *today* — it is a
spec ambiguity that *will* produce one of the three broken readings when T055 is
refined (T091 acceptance #6) and implemented.

## Suggested fix

Pick one coherent reading and align FR-004, §14.5 Failure UX, and Principle III
bullet 3 to it. Recommended (the "release-time confirmation + WebRTC-only
runtime gate" reading, which matches what the mechanism can actually deliver):

  - **FR-004** (`specs/001-tor-route/spec.md`): strike "or the profile has not
    been verified for the session." Rewrite (a) to: "the extension ships only in
    a release whose live-e2e hardening test was green against the target-browser
    profile — this is a release-process precondition, not a per-session runtime
    check. At runtime, the extension gates WebRTC via
    `browser.privacy.network.peerConnectionEnabled` (the only hardening surface
    Firefox's stable WebExtensions API exposes — sol-review B4)." Keep the
    WebRTC fail-closed clause; drop the "for the session" clause.
  - **§14.5 Failure UX** (`specs/000-architecture/spec.md`): strike "or the
    externally verified profile not confirmed for this session." Make
    `hardeningOk` a pure function of `peerConnectionEnabled`. Add a sentence:
    "DoH/DoT/HTTP-3 are not runtime-gated; their guarantee is the release-
    cadence live-e2e verification (Part 1) plus defense-in-depth `webRequest`
    blocklist. Post-verification drift is accepted residue (THREAT-MODEL
    §5.4/§5.5)."
  - **Principle III bullet 3** (`.specify/memory/constitution.md`): "If the
    hardened profile cannot be confirmed, non-Direct routing is fail-closed" is
    acceptable *if* "confirmed" is read as "the release shipped with a green
    live-e2e" (release-time) — but to remove the ambiguity, consider "Non-Direct
    routing is fail-closed at runtime against WebRTC; the DoH/DoT/HTTP-3
    surfaces are verified at release cadence and their drift is accepted residue
    named in THREAT-MODEL."

Alternative fix (the "real per-session signal" reading): define a signed
release-time manifest the extension verifies against its build ID at startup,
plus a `storage.local` flag the live-e2e runner writes via a documented channel.
More mechanism, more work; the recommended fix is sufficient for v1 given the
named residue.

## Regression test

No code exists yet, so the test lands with T055 (and T034b). Sketch:

  - **Location**: `extension/background/hardening.test.js` (Node unit over real
    API values only, per §14.5 Part 2) and `tests/live-e2e/mullvad-browser-
    hardening/` Part 2 (manual, then Phase 5+ automation).
  - **Asserts**:
    (a) `hardeningOk` is a pure function of `peerConnectionEnabled` — flipping
        only DoH/DoT/HTTP-3-related mock state (which the API does not expose)
        does NOT change `hardeningOk`, demonstrating the spec no longer claims a
        per-session binding it cannot deliver.
    (b) The failure dialog text for WebRTC-disabled names *only* WebRTC as the
        runtime-blocked surface and explicitly states the other three are
        release-cadence-verified (falsifies the smuggle: the dialog must not
        claim a runtime block on DoH/DoT/HTTP-3).
    (c) Live-e2e Part 2: with `peerConnectionEnabled = true`, `proxy.onRequest`
        returns no SOCKS descriptor for a `.onion` request (FR-004 fail-closed on
        the one surface that is runtime-gated).

## Related

- Root cause: `review/sol-review.md` B4 (Firefox stable WebExtensions does not
  expose `network.trr.mode`, `network.dns.over_tls.*`,
  `network.http.http3.enable`).
- Depends on resolution before: T091 acceptance #6 (refine T034b/T051/T054/T055
  to the accepted boundary). T055 inherits this spec; if M1 is unresolved at
  refine time, the implementer must guess a reading.
- Related minor in same run: m1 (live-e2e grep verifies test-profile
  `user_pref`, not effective distribution pref state) — the two together define
  the real strength of the "externally verified precondition" claim.
