---
id: T197
title: 'Reset the route indicator on no-request commits; fix prose'
status: pending
created: 2026-10-01
last_updated: 2026-10-01
source: "T155 attempt 3 cumulative redteam (candidate 989b8f9): A2-M3 (reproduced live), A2-M5 prose, A2-m8; all survived falsification as Minor"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 8   # ticket + STATUS.md + router.js + router.test.js + THREAT-MODEL.md + architecture spec + hardening README + probe.py (live Back step)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md
  - THREAT-MODEL.md
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T197: Reset the popup route indicator on no-request commits; truthful extension-claim prose

## Context

Mullvad Browser 153.3.0esr restores a clearnet page from the back/forward cache without
any network request after an onion page, so `proxy.onRequest` and `onBeforeRequest` never
fire and the popup keeps the previous decision. Reproduced live: onion page B, Back to
clearnet page A, popup shows "Main navigation decision: Tor" over A (the extension's
blocking listeners do not disable bfcache; `no-store` pages are unaffected). Routing is
unaffected; the label is untruthful (Constitution III route-indicator scope).

## Analysis

- Must hold: the popup never attaches a decision to a document that did not produce it.
- Gated: extension unit tests; `probe.py` live scenarios.
- Residue: the live Back step needs the pinned browser (T155 live-e2e README section 3).

## Acceptance

1. In `webNavigation.onCommitted` for `frameId === 0`, clear (or bind to the committed
   document) the tab's decision so `getRoute` answers unknown unless that document's own
   main-frame request produced it. Router unit test: commit a top-level document with no
   proxy event; `getRoute` must not return `tor`. Add a live Back-navigation scenario to the
   browser probe (red before green).
2. THREAT-MODEL §5.3 "Reference" quotes the pre-T156 constitution wording; reconcile it
   with the canonical Principle III text.
3. THREAT-MODEL.md:226-249 and :1573-1577, architecture §14.2/§14.5 Part 3/§14.6 and the
   hardening live-e2e README row 5 describe the foreign-extension inventory, the DoH-endpoint
   blocklist and "blocked until the profile is verified" as present mechanisms; none exists
   (the gate is WebRTC-only). Relabel as required target not implemented in 001, or implement
   with tests (Constitution V). Wording changes to THREAT-MODEL need maintainer approval.

## Out-of-scope

T190 items (including the unused `management` permission and the WebRTC re-audit decision),
any routing behaviour change.
