---
id: T055
title: 'Author `extension/background/hardening.js`'
status: done
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T055
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T091, T034b]
parallel: false
files_budget: 8   # raw-diff-path counting (run-task.sh): 2 code files +
                  # this ticket + STATUS.md regen; ticket-template.md
                  # excludes specs/ paths from the budget
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/000-architecture/spec.md §14.5 (enforcement boundary Parts 1–3 + failure UX — the runtime gate this module implements)"
  - "specs/001-tor-route/spec.md §FR-004 (non-Direct routing fail-closed at runtime against WebRTC via browser.privacy.network.peerConnectionEnabled)"
  - "THREAT-MODEL.md §5.3 (the WebRTC leak the gate closes; §5.4/§5.5 residue the dialog must not claim at runtime)"
constitution_refs:
  - "III: Privacy-Preserving by Construction (as amended by T091 — fail-closed at runtime against WebRTC; DoH/DoT/HTTP-3 release-cadence-verified, not runtime-enforced)"
  - "V: Honest Threat Model (the dialog and the audit record name only what is truthfully gated)"
  - "VII: Tests-First for Privacy-Critical Paths (gated by the frozen T034b suite lifting inside this ticket's verify)"
decision_refs:
  - "specs/001-tor-route/tickets/T034b-unit-test-for-extensionbackgroundhardeni.md (the verifying suite; §Analysis 'Pinned surface' is the authorization boundary this implementation conforms to)"
  - "specs/001-tor-route/tickets/T091-amend-browser-hardening-boundary.md (the amendment defining the runtime enforcement boundary, failure UX, and accepted residue)"
reviews: { round: 1, date: 2026-09-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T055: Author `extension/background/hardening.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/background/hardening.js` — DoH off (`network.trr.mode = 5`) / DoT off (`network.dns.over_tls.*` family absent or all-false; defense-in-depth against future ESR adding DoT) / WebRTC fully disabled (`privacy.network.peerConnectionEnabled = false`, read via `browser.privacy.network.peerConnectionEnabled`) / HTTP/3 off (`network.http.http3.enable = false`) audit per arch §14.5; blocking dialog on failure; routing is blocked via a flag that `router.js` (T054) checks before returning the SOCKS descriptor (FR-004). **Verified by T034b.**

## Analysis

Property map (grounding-verified 2026-09-06; required — `privacy_critical:
true` per `docs/process/analysis.md`). The task body quoted in the §Context
blockquote is the PRE-T091 tasks.md text ("DoH off … DoT off … HTTP/3 off
audit", "blocking dialog on failure"). T091 acceptance #6 named T055 for the
step-17 refine ("only after this amendment is accepted" — T091 is `done`),
and T034b already performed the same resolve for its own body: the **amended
FR-004 / arch §14.5 boundary is authoritative** where the two conflict. So:

- The body's runtime DoH (`network.trr.mode`), DoT (`network.dns.over_tls.*`),
  and HTTP/3 (`network.http.http3.enable`) audit clauses are **RETIRED** —
  stable Firefox WebExtensions do not expose those prefs (sol-review B4), a
  mock or implementation that invents them is the false assurance T091
  removed. Those three surfaces stay release-cadence-verified by
  `tests/live-e2e/mullvad-browser-hardening/` (in tree via T091) with
  accepted residue (THREAT-MODEL §5.4/§5.5).
- The body's "blocking dialog" resolves to the MV2 approximation T034b
  pinned: a `notifications.create` payload with `requireInteraction: true`;
  the blocking itself is `hardeningOk = false`, which router.js (T054)
  checks before returning a SOCKS descriptor for non-Direct routes (FR-004).
  The runtime audit is **WebRTC-only**: `hardeningOk` is a pure function of
  the `browser.privacy.network.peerConnectionEnabled` value — `true` iff the
  value read is exactly `false` (arch §14.5 failure UX item 2; no per-session
  "profile confirmed" signal — redteam M1, 2026-07-12).

- **Must hold:**
  - **Fail-closed (FR-004(b), Constitution III):** `hardeningOk === true`
    only when the read value is exactly `false`; enabled (`true`),
    reachable-but-unset (undefined/absent `.value`), or a failed read all
    yield `false`. The flag is never cached across audits — each
    `auditHardening()` re-reads the live setting (browser restart = script
    re-evaluation = fresh audit at load, arch §14.5 Part 2).
  - **Failure UX names the truth (arch §14.5 failure UX item 1,
    Constitution V):** each failing audit surfaces exactly one
    `notifications.create` payload whose `message` names WebRTC and the
    `peerConnectionEnabled` remediation and which carries
    `requireInteraction: true`, containing no DoH/DoT/TRR/HTTP3/QUIC
    runtime-block claim — the frozen T034b case
    `failureDialogNeverClaimsDohDotHttp3RuntimeBlocks` pins token absence
    over the whole payload (see §Notes for the §14.5 "states …
    release-cadence-verified" clause resolution).
  - **Operator record (arch §14.5 failure UX item 3; §14.4 layout):** each
    failing audit writes `storage.local.hardening.{lastAuditedAt,
    lastAuditResult}`, the record identifying the blocked surface; a
    hardened audit writes nothing (success is silent and write-free).
  - **Never throws / never rejects:** an API read that rejects, or a
    side effect (notification, record write) that rejects, degrades to
    fail-closed and is contained inside `auditHardening()` — the load-time
    auto-run leaves no unhandled rejection on the background page.
  - **Surface exclusivity (T034b §Analysis "Pinned surface"; T034g
    doctrine):** exactly two new globals on the shared MV2 background-page
    scope (`hardeningOk`, `auditHardening` — firstparty.js, storage.js, and
    router.js load there too); the only `browser.privacy` traversal is
    `network.peerConnectionEnabled`; `browser.proxy` is never touched
    (that surface is T054's).
  - **Real-API value shape:** Firefox `privacy.*` Settings resolve
    `{ value, levelOfControl }` while the T034b mock resolves the raw
    value; the implementation normalizes at the API edge (extract `.value`
    from an object result, accept the raw form) so it is correct in the
    real browser, not only under the mock. `levelOfControl` is deliberately
    ignored — arch §14.5 pins the gate to the value only.

- **Gated:** the frozen T034b suite (`extension/background/hardening.test.js`,
  8 named cases) lifts from `SKIP` to assertions inside this ticket's own
  verify — Gate 2b (`extension/run-tests.sh`, fail-closed on non-zero exit)
  executes it; its conformance gate hard-FAILs (never silently skips) if
  `hardening.js` exists but does not expose the pinned surface. The new
  `hardening.edges.test.js` gates the T034b-named residues (Settings shape,
  side-effect containment incl. the load-time path, hostile-environment
  fail-closed, surface exclusivity). `scripts/check-license-headers.sh`
  gates the SPDX header; `scripts/lint-ticket.py` gates ticket
  well-formedness; the pre-commit secret scanner gates payload hygiene.

- **Residue:**
  - **Real-browser behaviour** — that Mullvad Browser renders the
    notification and honours `requireInteraction`, that the permission set
    lets the read succeed in-production: transport-relevant, release-cadence
    territory (`tests/live-e2e/mullvad-browser-hardening/`); no hermetic
    gate possible without a browser in CI (T091 §Analysis residue, same
    shape).
  - **Exact dialog copy** beyond the pinned WebRTC/`peerConnectionEnabled`
    mentions and `requireInteraction: true` is UX polish pinned at THIS
    ticket's review (T034b §Analysis residue names T055's review as where
    copy lands); the negative-token gate bounds it from above.
  - **`levelOfControl` ignored** — a profile where policy forces WebRTC off
    reads `value: false` and routes; a policy the extension cannot see does
    not exist for it. Value-based gating is the honest gate; drift after the
    read is the same accepted residue arch §14.5 documents for all four
    surfaces.

## Acceptance

Named test (frozen, pre-existing): `extension/background/hardening.test.js`
(T034b §Acceptance 3 — not editable by this ticket). Named test (new, this
ticket): `extension/background/hardening.edges.test.js`. Named runner:
`extension/run-tests.sh` (pre-existing; unchanged). Runnable command:
`scripts/verify.sh` green from repo root (Gate 2b = `cd extension &&
./run-tests.sh`); fast inner loop: `cd extension && ./run-tests.sh`.

1. `extension/background/hardening.js` exists, carries the Apache-2.0 SPDX
   header, conforms to the T034b pinned surface (exactly the two globals
   `hardeningOk` + `auditHardening()`, audit auto-run at script evaluation,
   pure-function flag, WebRTC-only read, no `browser.proxy` touch), and the
   frozen suite reports **8/8 pass** inside this ticket's verify (pre-impl
   state, recorded at grounding: 8/8 `SKIP` — the Principle-VII signal).
2. `extension/background/hardening.edges.test.js` (Apache-2.0 SPDX header;
   Node built-ins only; no `package.json`) passes its four named cases:
   `realApiSettingsShapeResolvesValueAndFlagFollows` (the `{value,
   levelOfControl}` result shape is normalized and the flag follows the live
   profile), `sideEffectRejectionStillResolvesFailClosed` (a rejected
   notification or record write leaves the audit resolving fail-closed with
   the other side effect intact), `loadTimeAuditSurvivesHostileBrowser…`
   (no `browser` global, or a hollow one → fail-closed at load, no unhandled
   rejection — process survival is the evidence), and
   `moduleExposesExactlyThePinnedTwoGlobals` (T034g-register exclusivity).
3. Behavioral, pinned by the frozen cases: the failure dialog names WebRTC +
   the `peerConnectionEnabled` remediation with `requireInteraction: true`
   and zero forbidden tokens; the hardened profile audits clean and silent
   (no notification, no storage write); a re-audit observes changed profile
   state (no cached flag).
4. No edits to `extension/background/hardening.test.js`,
   `extension/run-tests.sh`, `extension/manifest.json` (manifest.test M4
   already pins `background/hardening.js` before `router.js`, and §14.2
   already carries the `privacy` + `notifications` permissions), or any
   router.js file.
5. The falsification battery (§Notes) shows each mutation tripping its named
   case with the pristine control green.
6. `scripts/verify.sh` green from repo root.

## Out-of-scope

- **`extension/background/router.js`** — T054's artifact and the consumer of
  `hardeningOk`; its `proxyDNS` / SOCKS5-username logic and future test are
  T054's. This ticket ships only the flag and the audit.
- **`extension/background/hardening.test.js` and `extension/run-tests.sh`**
  — T034b's contract; "fix the code, never the test" applies, and T034b
  §Out-of-scope names its §Analysis as the authorization boundary. If the
  pinned surface genuinely could not host this design, the escalation is a
  refine against T034b — it could and did.
- **`extension/manifest.json`** — already correct (background script order,
  `privacy`, `notifications`, `storage` permissions); T051 owns any future
  manifest change (e.g. the `management` inventory UX).
- **`tests/live-e2e/mullvad-browser-hardening/`** — the release-cadence
  oracle for DoH/DoT/HTTP-3 (arch §14.5 Part 1). No runtime assertion over
  those surfaces belongs anywhere, by design (T091).
- **The admin-dashboard consumer of `lastAuditResult`** — a future
  signed-export flow (arch §14.5 Part 2 item 3); this ticket only writes the
  record.
- **The `webRequest` DoH-endpoint blocklist** (arch §14.2
  defense-in-depth) — browser-network behaviour, release-cadence territory.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. Grounded and
refined to the T091-amended boundary on 2026-09-06 (T091 acceptance #6
step-17 refine; T091 is `done`, so the refine is authorized — same handling
as T034b).

**Dialog copy vs arch §14.5 failure UX item 1 (design decision for review).**
Item 1 says the dialog "states those surfaces are release-cadence-verified"
(of DoH/DoT/HTTP-3). The frozen T034b gate forbids the only clear names of
those surfaces (`DoH`, `DoT`, `TRR`, `HTTP/3`, `http3`, `QUIC`) anywhere in
the payload, so the shipped copy states the fact **without naming** them:
"WebRTC is the only hardening surface this extension can verify at runtime;
the rest of the hardened profile is verified outside the extension at each
Stargate release." Naming them could only add claim surface (the false
assurance T091 removed); a token-dodging circumlocution ("secure DNS", "h3")
would be vaguer, not safer (Constitution V). T034b §Analysis residue
explicitly pins exact copy at this ticket's review — this note is the
rationale the reviewer adjudicates.

**Falsification record (2026-09-06, implement phase).** Exercised in a
throwaway copy (`/tmp/t055-probe`, repo untouched) against the shipped
`hardening.js`; each mutation tripped its named case, pristine control
green in both suites:

| # | Mutation (what would falsify the claim) | Trips |
|---|---|---|
| M1 | fail-open on unset: `readValue !== true` | frozen `webrtcPrefUnsetFailsClosed` |
| M2 | dialog claims a DoH runtime block | frozen `failureDialogNeverClaimsDohDotHttp3RuntimeBlocks` |
| M3 | `browser.proxy` touch | frozen `extensionTouchesOnlyRealPrivacyApiSurfaces` |
| M4 | `let hardeningOk` (escapes the global surface) | conformance hard-FAIL on all 8 frozen + all 4 edges — never a silent skip |
| M5 | raw-value-only read (drop the Settings `{value}` normalization) | frozen stays GREEN (its mock resolves raw values — exactly T034b's blind spot), edges `realApiSettingsShapeResolvesValueAndFlagFollows` |
| M6 | record-write containment removed (catch re-throws) | frozen stays GREEN (its mock never rejects side effects — its named residue), edges `sideEffectRejection…` + `loadTimeAuditSurvives…` |
| M7 | extra top-level `var` | edges `moduleExposesExactlyThePinnedTwoGlobals` (frozen has no exclusivity assertion) |
| M8 | startup auto-run removed | frozen `auditRunsAtScriptLoadWithoutExplicitCall` |

M5/M6/M7 are the point of the edges suite: they mutate along axes the frozen
suite is structurally blind to, and each was named as residue in T034b
§Analysis. Two first-round probe errors are recorded for honesty: an M6
variant with unbalanced braces (SyntaxError noise — proves nothing beyond
loud failure) and an M8 variant whose search string missed (no-op — tested
pristine code); both were redone as above before recording.

**Pre-impl state (Principle-VII signal).** At grounding, before
`hardening.js` existed: `./run-tests.sh` → `hardening.test.js` 8/8 `SKIP`
("T055 not landed …"), all other extension suites green — the frozen gate
was in place and visible before the implementation landed.

**Adjacent decisions.** `lastAuditedAt` reuses the spec-pinned hour-bucket
formula `floor(epoch ms / 3600000)` (arch §14.4 `<hourBucket>`; T052's
note for downstream consumers). `get({})` argument shape is unpinned
(T034b residue); `{}` is the convention. The `console.warn` containment
messages are background-page-local diagnostics, not per-request logs
(Constitution III untouched).
