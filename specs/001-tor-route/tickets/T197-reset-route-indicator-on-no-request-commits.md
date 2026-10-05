---
id: T197
title: 'Reset the route indicator on no-request commits; fix prose'
status: pending
created: 2026-10-01
last_updated: "2026-10-05"
source: "T155 attempt 3 cumulative redteam (candidate 989b8f9): A2-M3 (reproduced live), A2-M5 prose, A2-m8; all survived falsification as Minor. Items 3-5 additions from the T155 attempt-4 redteam (area 3 m8, area 2 M4 residue and i1(b), the 989b8f9 Tor-reach residue), maintainer approved 2026-10-03; item 1 addition, item 3 run.sh addition and items 6-8 from the T155 r5 cumulative redteam (areas 2 and 3, falsified 2026-10-05), maintainer approved 2026-10-05 (item 6 reduced by the maintainer's \"Split to T209 (Recommended)\")"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T205"]
parallel: true
files_budget: 13   # ticket + STATUS.md + router.js + router.test.js + THREAT-MODEL.md + architecture spec + hardening README + probe.py (live Back step);
                  # the T155 attempt-4 additions (items 3-5) touch only THREAT-MODEL.md, already counted
                  # raised 8 -> 13 for the T155 r5 additions (maintainer-approved 2026-10-05, "Fold in, one new ticket" with "Split to T209 (Recommended)"):
                  # specs/001-tor-route/spec.md (item 1c, only if the scope text changes); tests/live-e2e/mullvad-browser-hardening/run.sh (item 3);
                  # CLAUDE.md (item 6); items 7 and 8 touch only THREAT-MODEL.md, already counted;
                  # plus two paths the earlier 8 left out: specs/001-tor-route/evidence/T197-tests-first.json (overhead)
                  # and the test file holding the doc checks of item 3 (named at START)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
complexity: medium
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
   Addition (T155 r5 cumulative redteam, area 2 M3, never-committed case, narrowed to Minor
   by falsification 2026-10-05; maintainer approved filing 2026-10-05): the decision is set
   when a `main_frame` request is seen (`router.js` `beginIndicator`, and
   `commitIndicator(…, 'tor')` in `onBeforeRequest`), before any response, and
   `webNavigation.onCommitted` does not touch it. An onion navigation that never commits
   (for example a 204 answer or a download) therefore leaves "Main navigation decision: Tor"
   over the clearnet document still displayed, so clearing on commit alone does not meet
   the must-hold above.
   This is read from `router.js` and ordinary navigation behaviour; it has not been run.
   (a) Router unit test: a tab committed on a clearnet document; an onion `main_frame`
       request is allowed and no `onCommitted` follows; `getRoute` must not answer `tor`
       for that tab.
   (b) Live probe scenario, red before green: from a committed clearnet page, navigate to
       an onion URL that answers 204; the popup must not show the Tor label over the
       clearnet document.
   (c) Maintainer stop point: `spec.md` (T150 scope text, about `:119-136`) defines the
       label as the latest main-navigation request's decision. Either that text is
       reconciled with the committed-document rule (exact wording needs maintainer
       approval), or the maintainer records here that the request-decision definition
       stands and this case is stated scope; in the second case (a) and (b) assert the
       recorded outcome. Stop and ask before implementing.
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
   Addition (T155 r5, area 2 M2 residue, Info, falsified 2026-10-05; maintainer approved
   filing 2026-10-05): `tests/live-e2e/mullvad-browser-hardening/run.sh` Part 2 still tells
   the tester to "exercise the foreign-extension inventory (allowlisted present, disallowed
   flagged)". Remove or relabel that instruction with the README row. If T200 lands first
   and has already corrected it, record that here instead.
4. (T155 attempt 4, area 2 i1(b), Info) THREAT-MODEL about `:1291` still says the hardening
   failure notification is never displayed; T195 fixed the notification. Correct the prose.
5. (989b8f9 residue, re-confirmed by the T155 attempt-4 falsification of area 3 M1) THREAT-MODEL
   §3.1/§5.8 do not say that a compromised Tor sidecar can reach household LAN devices and host
   services through the `stargate-egress` bridge (init's owner rules cover only the DP UID).
   Add a disclosure sentence. Whether this is only residue or a Constitution III code
   requirement is T078's decision.
6. (T155 r5 cumulative redteam, area 3 m6 remainder, Minor, falsified 2026-10-05; maintainer
   approved filing 2026-10-05 and chose "Split to T209 (Recommended)": the T203 orphans,
   including the quickstart Engine-floor reason, and the Dockerfile/Makefile comments are
   T209 Acceptance 8, not this item) Stale statements that are older than T191 and T203:
   - THREAT-MODEL's status banner ("T134/T138/T152/T157–T159 and the other foundation
     repairs remain pending; no repaired runtime or live pass is claimed") and "Last
     updated: 2026-05-17" against §3.1's measured results; §5.9 "Releases are reproducibly
     built" stated as present. Relabel as target or update.
   - `CLAUDE.md` says the proxy refuses a non-loopback bind "without a corresponding tunnel
     sidecar in the same compose stack"; the constitution's Deployment Model says a tunnel
     elsewhere in the stack is insufficient. Match the constitution. (Info.) The same
     sentence in `docs/html/index.html`, `diagrams.html` and `advanced-guide.html` is the
     989b8f9 Info residue left to T078 and is not covered here. `CLAUDE.md` wording needs
     maintainer approval.
7. (T155 r5, area 2 m4, narrowed to an Info disclosure by falsification 2026-10-05;
   maintainer approved filing 2026-10-05) THREAT-MODEL does not state, for the allowed
   path, that while the DP is down any local process able to bind `127.0.0.1:8881` receives
   the bearer and onion names from the extension, and that the DP does not restart
   automatically (`restart: "no"`). Add one disclosure sentence (§3.1 or §4.2).
8. (T155 r5, area 2 m7, Info, falsified 2026-10-05; maintainer chose "Owners for two, rest
   no ticket (Recommended)" 2026-10-05) THREAT-MODEL §4.1 and §4.3-§4.5 describe routes
   that 001 does not ship (clearnet via Tor exit, I2P, Nym, Direct adapter) in the present
   tense, with no per-route implemented/target label (Constitution V: a protection is a
   required target, an implemented mechanism or a verified result). Label each route section
   with its 001 state. Wording needs maintainer approval.

All THREAT-MODEL wording in items 2-8, and the `CLAUDE.md` wording in item 6, needs
maintainer approval at T197 time: stop and return drafts before writing it.

## Out-of-scope

T190 items (including the unused `management` permission and the WebRTC re-audit decision),
any routing behaviour change; any change to the Tor sidecar's network boundary (T078 decides
whether one is required); the DoH/HTTP-3 profile precondition (T200). The plane Dockerfile and Makefile comments, the post-T203 observer
descriptions and the quickstart Engine-floor reason (T209 Acceptance 8).

## Approved dependency reconciliation — 2026-10-03

The approved T205 hardening-record/schema repair precedes this ticket's dependent hardening claims. T203 has already repaired the observer boundary. Other accepted T197 scope remains unchanged.
