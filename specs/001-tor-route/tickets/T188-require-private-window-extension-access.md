---
id: T188
title: 'Detect and require private-window access for the extension'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 2 m4, survived falsification, promoted to Major)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 6
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"   # no silent fallback; onboarding explains prerequisites truthfully
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md#FR-004a
  - specs/001-tor-route/quickstart.md
decision_refs: []
remediates: "T157"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-006-private-window-access"]
clarity_check: {}
---

# T188: Detect and require private-window access for the extension

## Context

Mullvad Browser runs with `browser.privatebrowsing.autostart=true`. The
quickstart loads the extension through about:debugging, which grants no
private-window access, and never tells the user to allow it. Falsification
(2026-09-29, real Mullvad Browser) installed the extension without that access:
every listener was inactive, and a protected `.onion` navigation reached the
browser's ordinary configured proxy catcher. With no proxy configured, Gecko's
blockDotOnion stops it; with one, this is the silent system-proxy fallback
Constitution III forbids. T157's probe always forced `allowPrivateBrowsing`.

## Analysis

- Must hold: without private-window access the extension reports a blocked,
  unprotected state and onboarding tells the user; protected routing is never
  claimed while listeners cannot see requests.
- Gated: unit tests for the access check; a real-browser probe without access
  with a configured ordinary proxy, showing the user-visible blocked state.
- Residue: the extension cannot intercept requests it cannot see; the browser
  proxy configuration remains the user's precondition and is disclosed.

## Acceptance

1. Check `browser.extension.isAllowedIncognitoAccess()` at startup and on
   relevant changes; show a blocking notification and an unprotected popup state.
2. Update the quickstart/onboarding to require private-window access (and state
   the remaining precondition truthfully).
3. Real-browser evidence, red before green: without access, record the
   current behaviour (ordinary-proxy capture), then the candidate's truthful
   state; with access, protected routing still works.
4. Reconcile spec/threat-model text on the browser precondition.

## Out-of-scope

Blocked-result semantics (T186); packaging/signing for permanent install.
