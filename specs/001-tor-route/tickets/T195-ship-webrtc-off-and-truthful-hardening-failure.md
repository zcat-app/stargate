---
id: T195
title: 'Ship WebRTC off and make the hardening failure visible and truthful'
status: pending
created: 2026-10-01
last_updated: 2026-10-01
source: "T155 attempt 2 cumulative redteam (candidate 79d49e9), area 2 finding A2-M2, survived falsification; orchestrator spot-checked the cited lines; maintainer approved filing 2026-10-01"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: false
files_budget: 11  # ticket + generated STATUS.md + evidence/T195-tests-first.json
                  # + browser-profile/user.js + extension/background/hardening.js
                  # + extension/background/hardening.test.js
                  # + tests/live-e2e/mullvad-browser-hardening/probe.py
                  # + tests/live-e2e/mullvad-browser-hardening/README.md
                  # + specs/001-tor-route/quickstart.md + specs/001-tor-route/spec.md (FR-004(b))
                  # + THREAT-MODEL.md (§5.3)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"   # browser precondition; onboarding must be truthful
  - "V: Honest Threat Model"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-004
  - specs/001-tor-route/quickstart.md
  - THREAT-MODEL.md
decision_refs:
  - "Maintainer decision 2026-10-01: file A2-M2 as a Major blocking T155; fold in the T157 full-probe label orphan from T188"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T195: Ship WebRTC off and make the hardening failure visible and truthful

## Context

Redteam A2-M2 (T155 attempt 2, candidate 79d49e9), survived falsification:

- Mullvad Browser 153.3.0esr defaults `media.peerconnection.enabled=true`
  (observed via Marionette). The T188 profile template `browser-profile/user.js`
  does not set it (0 matching lines). A user following the quickstart therefore
  has the extension's WebRTC gate closed and every `.onion` request blocked
  (fail-closed; no leak).
- The failure notification never shows: `extension/background/hardening.js`
  (~line 97) passes `requireInteraction: true`, which Gecko's `notifications.create`
  schema rejects; `hardening.test.js` (~line 231) pins that property, so unit
  tests pass against a mock that the real browser does not match. (Also observed
  live by the T188 developer.)
- `specs/001-tor-route/quickstart.md` (~line 290) says the defaults pass and
  points to a **Re-audit** button that does not exist. FR-004(b) ("blocking
  dialog") and THREAT-MODEL §5.3 describe behaviour that does not happen.
- The live probe masked this: `tests/live-e2e/mullvad-browser-hardening/probe.py`
  (~line 326) injects `media.peerconnection.enabled` itself instead of starting
  from the browser's real defaults.

Folded in (orphan of T188): `probe.py --only full` is red at the candidate. Five
no-fallback scenarios fail only on the popup-label prefix, because since T188
the baseline warning precedes "Main navigation decision: Blocked by Stargate"
and full mode runs without `user.js`. Their network outcomes are clean.

## Analysis

- Must hold: following the quickstart on Mullvad Browser 153 yields a working
  Tor route; when the WebRTC precondition fails, the user sees a notification
  that Gecko actually displays plus a persistent popup state; docs describe only
  behaviour that exists; the live probe starts from the real browser defaults
  and would have caught this defect.
- Gated: unit tests against Gecko's real `notifications.create` schema; live
  probe red (real defaults, current template) before green.
- Residue: the WebRTC re-audit cadence (startup-only vs per decision) is T190
  item 1 and stays there.

## Acceptance

1. Tests first, red before green: (a) a unit test that rejects notification
   options Gecko's schema does not accept (fails at the current
   `requireInteraction`); (b) the live probe started from Mullvad Browser 153's
   real defaults with the shipped `user.js` (fails today: `.onion` blocked by the
   WebRTC gate).
2. `browser-profile/user.js` sets `media.peerconnection.enabled=false`; the
   extension's failure notification uses only schema-valid options and is
   verified to display in the real browser; the popup state persists.
3. `probe.py` no longer injects the WebRTC pref outside an explicit
   negative-control scenario; `--only full` is green at the candidate (popup-label
   expectations match the T188 baseline-warning order, or full mode runs with the
   shipped `user.js`, whichever matches the spec).
4. Quickstart, FR-004(b) and THREAT-MODEL §5.3 describe the actual behaviour
   (no nonexistent Re-audit button; truthful wording of what the user sees).
5. `scripts/verify.sh` green.

## Out-of-scope

WebRTC re-audit cadence (T190 item 1); other hardening prefs (DoH/DoT/HTTP-3
remain the documented T091 out-of-band residue).
