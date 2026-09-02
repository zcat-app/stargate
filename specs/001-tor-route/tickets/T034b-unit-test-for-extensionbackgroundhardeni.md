---
id: T034b
title: 'Unit test for `extension/background/hardening.js` (Principle VII; FR-0'
status: in-review
created: 2026-07-04
last_updated: 2026-09-02
source: tasks.md#T034b
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T091]
parallel: true
files_budget: 6   # raw-diff-path counting (run-task.sh): 4 code files + this
                  # ticket + STATUS.md regen; ticket-template.md excludes
                  # specs/ paths from the budget
privacy_critical: true
complexity: low
risk: low
round_cap: 2
test_for: [T055]
constitution_refs:
  - "III: Privacy-Preserving by Construction (as amended by T091)"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical Paths"
spec_refs:
  - "specs/001-tor-route/spec.md §FR-004 (as amended by T091: runtime fail-closed is WebRTC-only via browser.privacy.network.peerConnectionEnabled; DoH/DoT/HTTP-3 are release-cadence-verified, not runtime-enforced)"
  - "specs/000-architecture/spec.md §14.5 (enforcement boundary Parts 1–3; failure UX — blocking dialog naming WebRTC only, hardeningOk as a pure function of peerConnectionEnabled, storage.local.hardening.lastAuditResult)"
  - "THREAT-MODEL.md §5.3 (WebRTC leaks — the surface the runtime gate closes) and §5.4/§5.5 (DoH/DoT and HTTP/3 residue the dialog must NOT claim to close at runtime)"
  - "specs/001-tor-route/research.md §10 (Node 20 LTS CI pin; node:test runner; vm.runInNewContext + synthesized browser global; no source contortion)"
  - "specs/001-tor-route/plan.md §\"Technical Context\" (extension: no build step, no third-party JS deps; Node 20 is CI-only)"
decision_refs:
  - "specs/001-tor-route/tickets/T091-amend-browser-hardening-boundary.md (the amendment; acceptance #6 names T034b for step-17 refine; its §Analysis residue scopes this ticket to real-API values only: peerConnectionEnabled, proxyDNS)"
  - "specs/001-tor-route/review/sol-review.md#B4 (originating finding: stable WebExtensions APIs do not expose DoH/DoT/HTTP-3 prefs)"
  - "specs/001-tor-route/tickets/T068a-contract-test-for-the-response-header-in.md (round-1 APPROVE precedent: a tests-first ticket lands GREEN via self-skips that gate on the impl's surface and lift when it exists)"
  - "specs/001-tor-route/tickets/T035a-unit-test-for-tokenloaderjava-t035-diff.md (most recent application of that precedent; the Java analog of this ticket's refine-vs-stale-body handling)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
out_of_scope:
  - extension/background/hardening.js
  - extension/background/router.js
  - tests/live-e2e/**
---

# T034b: Unit test for `extension/background/hardening.js` (Principle VII; FR-0

## Context

Principle-VII unit test for the extension's runtime hardening gate
(`extension/background/hardening.js`, FR-004) — the code that makes
non-Direct routing fail-closed against WebRTC and is the only runtime
enforcement the extension truthfully performs (Constitution III as amended
by T091). Pure-logic test using Node's built-in `node:test` runner (no
third-party deps; no-build-step constraint per plan.md §"Technical Context"
and research.md §10) against a thin handwritten mock of the
`browser.privacy.network.*`, `browser.notifications`, and
`browser.storage.local` APIs. Because MV2 background scripts are loaded by
the browser as global scripts (not ES modules), the test loads
`hardening.js` via Node's `vm.runInNewContext()` with a synthesized
`browser` global — no source-code contortion (UMD wrapper, conditional
`module.exports`, etc.) is added to the extension to make it testable.
Pairs with T055 (impl); T055 is `blocked_by` this ticket and must conform
to the pinned surface in §Analysis. This ticket also lands the discovery
runner `extension/run-tests.sh` that verify.sh Gate 2b has been SKIPping
on since scaffolding.

## Analysis

Property map (grounding-verified 2026-09-02; required — `privacy_critical:
true` per `docs/process/analysis.md`). The task body quoted in tasks.md is
the PRE-T091 text; per T091 acceptance #6 ("refine and reopen T034b … only
after this amendment is accepted" — T091 is `done`) the **amended FR-004 /
arch §14.5 boundary is authoritative** where the two conflict. T034b is the
first of the step-17 dependents to run; this §IS the step-17 refine for
this ticket.

**Grounding findings resolved into this design (the body-vs-amendment
contradictions):**

1. Body cases (b)/(c)/(e) assert runtime DoH/DoT/HTTP-3 detection
   (`network.trr.mode`, `network.dns.over_tls.*`, `network.http.http3.enable`)
   → **RETIRED.** Stable Firefox WebExtensions do not expose those prefs
   (sol-review B4; T091). A mock that invents them creates false assurance
   (T091 §Context verbatim). Those surfaces are release-cadence-verified by
   `tests/live-e2e/mullvad-browser-hardening/` (present in tree: README +
   run.sh) with accepted residue (THREAT-MODEL §5.4/§5.5).
2. Body's mock list includes `browser.proxy.settings` → **RETIRED.** The
   amended hardening.js reads no proxy surface; `proxy.onRequest` /
   `ProxyInfo` (`proxyDNS`, username/password) belongs to router.js (T054),
   whose own logic-over-API-values unit is the future second test research
   §10 anticipates — not this ticket.
3. Body case (f) "all failing preconditions appear in dialog payload" →
   **collapses.** The amended audit has exactly ONE runtime surface
   (WebRTC), so the full-set-vs-fail-fast property becomes the negative
   constraint that matters instead: the dialog must not claim runtime
   blocks on DoH/DoT/HTTP-3 (arch §14.5 failure UX item 1).
4. Body's "blocking dialog" → the MV2-available approximation: a
   `notifications.create` payload with `requireInteraction: true`. The
   blocking itself is `hardeningOk = false` (router.js checks the flag);
   the notification is the UX surface, per arch §14.5 failure UX.
5. Body's runner requirements (discover `*.test.js` under `extension/`,
   CI invocation, Node 20 pin) → unchanged by the amendment; kept.

**How a unit test for a not-yet-existing file lands green** (the
load-bearing constraint, T068a/T035a precedent): `hardening.js` is T055's
artifact and does not exist yet (`extension/background/` is empty —
verified). The test file self-skips with a loud Principle-VII marker while
the file is absent, hard-FAILS naming expected-vs-actual if the file
exists but does not expose the pinned surface (conformance gate), and
drives the real script through the mock once it does — every assertion
below bites from inside T055's own verify run.

**Pinned surface (the ONLY surface assumption; everything else is
observable through the mock):** `hardening.js` is a browser-global MV2
background script (no exports, no wrapper). Evaluating it in a context
that has a `browser` global starts an audit automatically (the arch
"read at startup and on browser restart" contract — script evaluation is
the restart mechanism). It exposes exactly two globals:

- `hardeningOk` — boolean; `false` until the first audit completes, then a
  **pure function of** the `peerConnectionEnabled` value (arch §14.5
  Part 2): `true` iff the value read is exactly `false`.
- `auditHardening()` — async function; performs the runtime audit (read
  `browser.privacy.network.peerConnectionEnabled.get(...)`, update
  `hardeningOk`, fire the failure side effects), and resolves only after
  its side effects are observable, so tests await determinism.

Failure side effects (observed through the mock, shapes pinned only to
what arch §14.5 names): each failing audit surfaces exactly one
`browser.notifications.create(<payload>)` whose
`message` names WebRTC and the remediation (`peerConnectionEnabled`) and
which carries `requireInteraction: true`, plus one
`browser.storage.local.set({ hardening: { lastAuditResult: … } })` whose
serialized value identifies the blocked surface. Because the script also
audits at load, content cases assert `>= 1` over the context lifetime
while the exact per-audit count is pinned by the no-explicit-call and
0→1-transition cases. Success: no notification,
no storage write. The audit never throws synchronously and never
rejects — an API read that returns `undefined` (pref reachable but unset)
or rejects (permission/unavailable) fails **closed** (`hardeningOk ===
false`), never open.

- **Must hold:**
  - **Fail-closed against WebRTC (FR-004(b), Constitution III):**
    `hardeningOk === false` whenever the read value is `true`, non-`false`
    (unset/undefined), or the read fails; `hardeningOk === true` only when
    the read value is exactly `false`.
  - **Failure UX names the truth (arch §14.5 failure UX item 1,
    Constitution V):** on failure, the dialog payload names WebRTC +
    `peerConnectionEnabled` remediation, and does NOT contain any DoH /
    DoT / HTTP-3 / QUIC runtime-block claim (`DoH`, `DoT`, `TRR`, `HTTP/3`,
    `http3`, `QUIC` tokens absent from the notification payload and the
    stored `lastAuditResult` — those surfaces are release-cadence-verified,
    and claiming otherwise is the false assurance T091 removed).
  - **Failure is surfaced for the operator (arch §14.5 Part 2 item 3):**
    `storage.local` receives `hardening.lastAuditResult` on failure and
    nothing on success.
  - **Startup contract (arch §14.5 Part 2: "read at startup and on browser
    restart"):** the audit runs at script load without an explicit call;
    a re-audit observes changed profile state (no cached flag).
  - **No invented API claims (T091 must-hold verbatim: "No green test
    claims a Firefox WebExtension setting that does not exist"):** across
    every case, the mock records every `browser.privacy` access; the
    accessed set is exactly `privacy.network.peerConnectionEnabled` —
    `browser.proxy` is never touched by hardening.js (that surface is
    T054's).
- **Gated:** verify.sh Gate 2b executes the suite once
  `extension/run-tests.sh` exists (fail-closed on non-zero exit);
  `scripts/check-license-headers.sh` gates SPDX headers on `.js`/`.sh`;
  the pre-commit secret scanner gates fixture hygiene;
  `scripts/lint-ticket.py` gates ticket well-formedness.
- **Residue** (documented, not silently dropped):
  - **Exact dialog copy** beyond the WebRTC/`peerConnectionEnabled`
    mention and `requireInteraction: true` is UX polish pinned at T055's
    review, not here.
  - **`get()` argument shape** (`{}` vs `{ userSetting }`) is unpinned;
    the mock ignores arguments.
  - **`lastAuditResult` internal schema** beyond "identifies the blocked
    surface" is T055's choice (the admin-dashboard consumer is a future
    signed-export flow, arch §14.5 Part 2 item 3).
  - **Load-time auto-run error observability:** case (e) pins resilience
    of the explicit `auditHardening()` path; an impl whose load-time
    auto-run produces an unhandled rejection on a hostile API is caught
    by review, not by this suite (the mock cannot observe unhandled
    rejections portably across Node versions).
  - **proxyDNS / SOCKS5-username logic** (the other half of T091's
    real-API list) lives in router.js — future test per research §10
    follow-up; this ticket pins hardening only.
  - **Node-version drift:** hosts below the Node 20 pin run the suite
    under a warned, non-pinned runner (see §Acceptance 6); CI is the pin.
  - **The webRequest DoH-endpoint blocklist** (arch §14.2
    defense-in-depth) is browser-network behaviour; release-cadence
    territory, not unit-testable here.

## Acceptance

Named test: `extension/background/hardening.test.js` (Node built-in
`node:test` + `node:assert`; loads `extension/background/hardening.js` via
`vm.runInNewContext` with a synthesized `browser` global). Named runner:
`extension/run-tests.sh` (executable; POSIX sh). Named CI change: a Node 20
step in `.github/actions/setup-toolchain/action.yml`. Runnable command:
`scripts/verify.sh` green from repo root (Gate 2b = `cd extension &&
./run-tests.sh`); fast inner loop: `cd extension && ./run-tests.sh`.

1. `extension/run-tests.sh` discovers every `*.test.js` under `extension/`
   (excluding `dist/` build output) and runs each with the `node:test`
   runner; exits non-zero if any file fails or if `node` is missing;
   zero test files → loud notice + exit 0 (self-detecting-gate philosophy).
2. The mock is thin, handwritten, and access-recording: it implements ONLY
   `browser.privacy.network.peerConnectionEnabled.get` (controllable
   resolved value / rejection), `browser.notifications.create`,
   `browser.storage.local.{get,set}` — and records every `browser.privacy`
   namespace read plus every notification/storage call for assertion.
   No third-party modules; no `package.json` introduced.
3. The eight named cases — each a separate `test()`, self-skipping with a
   loud Principle-VII marker until `hardening.js` exists, hard-FAILING on
   a nonconforming surface, then driving the real script:
   `hardenedProfileAuditsCleanAndSilent` (value `false` → `hardeningOk`,
   no notification, no storage write);
   `webrtcEnabledFailsClosedAndDialogNamesWebrtc` (value `true` →
   fail-closed + WebRTC-naming `requireInteraction` notification +
   `hardening.lastAuditResult` written);
   `failureDialogNeverClaimsDohDotHttp3RuntimeBlocks` (negative-token
   assertion over the failure dialog payload AND stored record);
   `webrtcPrefUnsetFailsClosed` (read resolves `undefined` → fail-closed
   + surfaced);
   `apiReadFailureFailsClosedWithoutThrowing` (read rejects →
   `auditHardening()` still resolves, `hardeningOk === false`);
   `auditRunsAtScriptLoadWithoutExplicitCall` (fresh context, drain the
   event loop, no explicit call → audit observed);
   `reauditObservesChangedProfileState` (flip the mock value between
   audits → flag follows; the restart re-read property);
   `extensionTouchesOnlyRealPrivacyApiSurfaces` (recorded `browser.privacy`
   accesses ⊆ {`network.peerConnectionEnabled`}; `browser.proxy` never
   accessed).
4. Pre-T055 state is GREEN, not red: verify.sh Gate 2b passes with the
   eight cases reported skipped (T068a-precedent tests-first state); this
   ticket introduces no `extension/background/hardening.js` (that file is
   T055's named artifact) and no extension source changes at all.
5. `.github/actions/setup-toolchain/action.yml` gains a `setup-node` step
   pinning Node `20` (research §10 CI pin) so the CI mirror of Gate 2b
   exercises the suite for real instead of failing on a missing runner;
   the action's description is updated to match.
6. `extension/run-tests.sh` enforces the pin where it exists: node absent
   or major < 18 → non-zero with a message naming research.md §10; major
   18–19 → loud stderr warning (running outside the §10 pin) then run;
   major ≥ 20 → silent.
7. Both new files carry the Apache-2.0 SPDX header
   (`scripts/check-license-headers.sh` stays green).

## Out-of-scope

- **`extension/background/hardening.js` itself** — T055's named artifact.
  THIS ticket must not create it; the suite self-skips until T055 lands
  it, then gates T055's verify. **T055 must NOT edit
  `hardening.test.js` or `run-tests.sh`**: the mock and the pinned
  surface in §Analysis are this ticket's contract. If the pinned surface
  genuinely cannot host T055's design, that is a **refine** escalation
  against THIS ticket (rewrite §Analysis's pinned-surface paragraph), not
  a test edit — "fix the code, never the test" applies, and this
  paragraph is the explicit authorization boundary.
- **`extension/background/router.js` and its `proxyDNS` / SOCKS5-username
  logic** — T054's surface; its unit test is the future second JS test
  research §10 anticipates. `test_for: [T055]` pins the pairing; T054 is
  NOT gated by this ticket.
- **`tests/live-e2e/mullvad-browser-hardening/`** — the release-cadence
  oracle for DoH/DoT/HTTP-3 (arch §14.5 Part 1); already in tree via T091.
  DoH/DoT/HTTP-3 runtime assertions belong nowhere, by design.
- **Options-page, popup, first-party, storage-warning text tests** —
  T034c/T034d/T034e's tickets; the runner this ticket lands discovers
  their files automatically when they land (no per-task runner
  amendments).
- **Exact notification copy / `lastAuditResult` field list** — T055's
  review, per §Analysis residue.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded and
refined to the T091-amended boundary on 2026-09-02 (T091 acceptance #6
step-17 refine; T091 is `done`, so the refine is authorized).

**T091 amendment (2026-07-12) — consume the amended contract.** The unit
test covers logic over real-API values only (`peerConnectionEnabled` per
arch §14.5 Part 2): fail-closed semantics, the truthful failure dialog,
the operator-facing audit record, the startup/restart re-read, and the
no-invented-API-claims property. It does NOT cover DoH/DoT/HTTP-3 —
mocking those prefs is precisely the false-assurance failure mode T091
removed (redteam M1, 2026-07-12). The runner + CI pin sentences of the
original body survive unchanged.

tasks.md §"Notes" (binding): "never bundle a test and its corresponding
implementation into one commit (the failing-test signal is part of the
audit trail)" — under the T068a precedent the signal is the loud skip in
this commit, lifting to assertions inside T055's commit.

**Falsification record (2026-09-02, implement phase).** The suite was
exercised in a throwaway copy against a conforming reference stub and
four drift mutations: 8/8 pass on the stub; each mutation trips the named
case — dialog claiming DoH → `failureDialogNeverClaimsDohDotHttp3…`;
fail-open flag semantics → `…FailsClosed` + startup + reaudit cases;
`browser.proxy.settings` touch → `extensionTouchesOnlyRealPrivacyApi…`;
`let`-declared (non-global) flag → conformance hard-fail on every case,
never a silent skip. First falsification round caught a real suite bug
(absolute notification counts double-counted the load-time audit alongside
the explicit call) — fixed by pinning exact counts only where they are
unambiguous (no-explicit-call case, 0→1 transition case) and `>= 1` +
per-payload assertions in the content cases.
