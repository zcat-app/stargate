---
id: T197
title: 'Reset the route indicator on no-request commits; fix prose'
status: pending
created: 2026-10-01
last_updated: 2026-10-03
source: "T155 attempt 3 cumulative redteam (candidate 989b8f9): A2-M3 (reproduced live), A2-M5 prose, A2-m8; all survived falsification as Minor. Items 3-5 additions from the T155 attempt-4 redteam (area 3 m8, area 2 M4 residue and i1(b), the 989b8f9 Tor-reach residue), maintainer approved 2026-10-03"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 8   # ticket + STATUS.md + router.js + router.test.js + THREAT-MODEL.md + architecture spec + hardening README + probe.py (live Back step);
                  # the T155 attempt-4 additions (items 3-5) touch only THREAT-MODEL.md, already counted
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
   Extended (T155 attempt 4, area 3 m8 and area 2 M4 residue): THREAT-MODEL also presents as
   current mitigations, with none existing in the Local source-build profile:
   - about `:1709-1711`: sidecar images "referenced by sha256 digest" so silent swaps fail
     (the Tor image is `stargate/tor:local`, built locally, not digest-pinned);
   - about `:523-525`: pinned digests detecting silent sidecar swaps "via image-pull checks"
     (no pull happens);
   - about `:1715-1717`: Tor's "only writable mount is the config volume" (Tor writes its state
     and fabric volumes and tmpfs `/tmp` and `/run`; there is no config volume since T191);
   - about `:1755-1758`: updates via "automated tracker (Renovate)" applied "in the admin
     dashboard" (contradicts CONTRIBUTING about `:330-331`; no admin enrollment exists);
   - §7.3 about `:2402-2405`: Stargate "encodes those mitigations in code".
   Relabel each as a required target (T081 where it owns the item, e.g. signing) or not
   implemented, and describe the actual mechanism (digest-pinned bases, InRelease and closure
   locks, local build, no pull check). A grep-based doc check fails on "Renovate" and
   "image-pull checks" in present-tense mitigation text.
4. (T155 attempt 4, area 2 i1(b), Info) THREAT-MODEL about `:1291` still says the hardening
   failure notification is never displayed; T195 fixed the notification. Correct the prose.
5. (989b8f9 residue, re-confirmed by the T155 attempt-4 falsification of area 3 M1) THREAT-MODEL
   §3.1/§5.8 do not say that a compromised Tor sidecar can reach household LAN devices and host
   services through the `stargate-egress` bridge (init's owner rules cover only the DP UID).
   Add a disclosure sentence. Whether this is only residue or a Constitution III code
   requirement is T078's decision.

All THREAT-MODEL wording in items 2-5 needs maintainer approval at T197 time: stop and return
drafts before writing it.

## Out-of-scope

T190 items (including the unused `management` permission and the WebRTC re-audit decision),
any routing behaviour change; any change to the Tor sidecar's network boundary (T078 decides
whether one is required); the DoH/HTTP-3 profile precondition (T200).
