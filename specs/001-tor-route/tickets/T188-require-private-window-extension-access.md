---
id: T188
title: 'Detect and require private-window access for the extension'
status: done
created: 2026-09-29
last_updated: 2026-09-30
source: "reviews/redteam-20260929-694dbd8.md (area 2 m4, survived falsification, promoted to Major)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 13   # router.js + router.test.js + popup.js + popup.test.js + quickstart.md + spec.md + THREAT-MODEL.md + live-e2e probe.py + live-e2e README.md + browser-profile/user.js + this ticket + STATUS.md regen + evidence/T188-tests-first.json (6 -> 12 -> 13 maintainer-authorised 2026-09-29; anything beyond 13 is a stop)
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
reviews: { round: 2, date: 2026-09-30, verdict: APPROVE }
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

Refined 2026-09-29 (maintainer-authorised, see Notes 2). Premise correction from the
developer's clarity finding: in Mullvad Browser's permanent private browsing mode an
extension without private-window access never starts its background page (Gecko
`ext-backgroundPage.js` returns early), so no extension-side detection can run there.

- Must hold:
  - C (fail-closed baseline, option 6 manual proxy with a TLD allowlist; Notes 4): the
    dedicated Stargate profile's `user.js` sets `network.proxy.type=1` with SOCKS5 and
    proxy-side DNS to the T186 Unix sink, and `network.proxy.no_proxies_on` = `<local>`
    plus one leading-dot entry per ICANN top-level domain, derived from the local Ubuntu
    `publicsuffix` package (20231001.0357-0.1, sha256
    02074b85e6f1454055b82aa7812bcea05f6afd9076e9a60ae1eb30ad61a26881; `onion` and `arpa`
    excluded). Extension absent or not running: clearnet TLDs go direct as the 001
    extension's non-`.onion` route does; `.onion`, `.onion.`, any case and unknown TLDs
    fail closed with no direct connection, no ordinary proxy and no DNS naming them.
    Extension present: its Tor descriptor overrides; its unchanged `{type:'direct'}`
    falls to this configuration, so a misclassified onion still reaches the sink. The
    extension compares `proxy.settings` with the shipped values and warns on drift.
    Scoped to 001, where only `.onion` is protected; a feature that protects clearnet
    must revisit the allowlist. A TLD delegated after the list fails closed until a
    reviewed update.
  - A (onboarding): the quickstart requires the baseline profile, "Run in Private Windows:
    Allow", and a positive check that the Stargate popup opens.
  - Detection: where the extension runs without private-window access, it shows a
    blocking notification and an unprotected popup state, and blocks protected routing
    while access is missing or unknown. Protected routing is never claimed while
    listeners cannot see requests.
- Gated: unit tests for the access check, routing block and popup state; a real-browser
  probe covering the baseline (with calibrated positive controls) in both permanent
  private and ordinary modes, with and without access.
- Residue: the extension cannot intercept requests it cannot see. Skipping the baseline
  step reverts to the pre-T188 behaviour (requests follow the browser's own proxy
  settings); this is disclosed in the quickstart, spec and THREAT-MODEL.

## Acceptance

1. Fail-closed baseline (C, option 6): ship `browser-profile/user.js` as described in
   Analysis, recording the PSL package version and sha256 (updates are reviewed
   promotions). Before implementation, verify live in Mullvad Browser 153 with a
   disposable profile and calibrated controls: (1) suffix entries match subdomains
   case-insensitively and the full list is accepted without visible page-load cost;
   (2) extension absent, or present without private access: clearnet loads direct;
   `.onion`, `.onion.`, mixed case and an unknown TLD fail closed with no DNS and no
   destination/proxy/impostor hits; (3) extension present: Tor works via its
   descriptor, clearnet `{type:'direct'}` loads direct, a forced router "direct" for
   `.onion.` hits the sink; (4) Mullvad does not lock `network.proxy.type`, `socks` or
   `no_proxies_on`; (5) record what an emptied or garbled `network.proxy.socks` does
   (falling open is a disclosed residue covered by the tamper check); (6) record whether
   CIDR entries (`0.0.0.0/0`, `::/0`) bypass IP literals. If a check among 1-4 fails, ship
   the fallback in Notes 4 instead. Router `{type:'direct'}` semantics stay unchanged.
2. Detection: check `browser.extension.isAllowedIncognitoAccess()` at startup (the
   about:addons toggle reloads the extension); show a blocking notification and an
   unprotected popup state; block protected routing while access is missing or unknown.
   Tamper check: while the extension runs, compare `browser.proxy.settings.get()`
   (proxy type, SOCKS, passthrough) with the shipped baseline; warn in the notification
   and popup when it is missing, changed or unreadable.
3. Onboarding (A): the quickstart requires the baseline profile, "Run in Private Windows:
   Allow" and a positive popup check, and states the remaining precondition truthfully.
4. Real-browser evidence, red before green, in both modes (permanent private and
   ordinary windows): without access, record the current behaviour (ordinary-proxy
   capture), then the candidate's fail-closed/truthful state; with access, protected
   routing still works.
5. Reconcile spec/threat-model/quickstart text on the browser precondition, including
   the residues (new-TLD staleness fails closed; an emptied or garbled SOCKS pref).

## Out-of-scope

Blocked-result semantics (T186); packaging/signing for permanent install.

## Notes

Maintainer decisions (2026-09-29, maintainer-authorised, relayed by the orchestrator):

1. `files_budget` raised 6 -> 12 to cover the twelve paths in the frontmatter comment. A
   thirteenth path (`extension/README.md`) is authorised only if this change makes its
   install text stale. (Superseded by 2: the thirteenth path is the profile template.)
2. Clarity stop resolved by refinement (maintainer-authorised 2026-09-29, relayed by the
   orchestrator) in response to the developer's finding that Mullvad's permanent
   private mode never starts an extension lacking private access: Analysis and
   Acceptance rewritten to design C (fail-closed baseline proxy) + A (onboarding) +
   detection where the extension runs. `files_budget` raised 12 -> 13 for the
   `browser-profile/user.js` template; anything beyond 13 is a stop.
3. Direct/`null` stop resolved (maintainer-authorised 2026-09-29, relayed by the
   orchestrator) after the developer's live finding that under a full-sink manual-proxy
   baseline `{type:'direct'}` follows the browser's proxy configuration (only `null` is a
   true direct connection) and `null` bypasses the baseline: do NOT change Direct to
   `null`; keep router `{type:'direct'}` semantics unchanged; replace the full-sink
   baseline with the PAC baseline (option 5) above. Budget stays 13; the profile
   template path may carry the PAC; any budget change is a stop.
4. Broken-PAC stop resolved (maintainer-authorised 2026-09-29, relayed by the
   orchestrator) after the developer's live finding that a missing, unreadable or
   syntactically broken PAC falls back to DIRECT for `.onion.` and mixed-case names:
   PRIMARY design is option 6 (manual-proxy SOCKS sink with remote DNS and a
   `no_proxies_on` ICANN-TLD allowlist generated from the local `publicsuffix`
   package, list inside `browser-profile/user.js`), plus a `proxy.settings` tamper
   check. FALLBACK, only if a check among 1-4 fails for option 6: option 5 revised
   (inline data: PAC with the HTTPS `127.0.0.1:1023` sink, hermetic PAC unit tests,
   the same tamper check against the PAC pref, a live certificate-error click-through
   probe, and disclosed residues). Router `{type:'direct'}` unchanged; budget stays 13;
   any budget change is a stop.
5. Design shipped: option 6 (primary). Live pre-implementation checks 1-4 passed in Mullvad
   Browser 153.3.0esr (suffix entries match subdomains case-insensitively; the 1,471-label
   list is accepted with no visible load cost; protected forms and an unknown TLD fail closed
   with no DNS and empty surfaces with the extension absent or without access; Tor overrides,
   `{type:'direct'}` loads clearnet directly, a forced Direct `.onion.` reaches the sink; the
   proxy prefs are unlocked). Check 5: an emptied or garbled `network.proxy.socks` falls open
   for non-bypassed names (disclosed residue, reported by the tamper check). Check 6: CIDR
   entries do not bypass a non-loopback IP literal, which fails closed either way. The
   fallback (option 5 revised) was not needed. Evidence: THREAT-MODEL T188 live evidence and
   `specs/001-tor-route/evidence/T188-tests-first.json`.
6. Found live, outside this ticket: Firefox rejects `requireInteraction` in
   `notifications.create` ("Unexpected property"), so T188's notifications omit it (transient;
   the popup is the persistent report) and the pre-existing WebRTC hardening notification in
   `background/hardening.js` is never displayed (its routing block is unaffected). Reported to
   the orchestrator for a remediation ticket; not fixed here (budget and scope).
7. Post-approval (round 2) change: the pre-commit gitleaks hook flagged the baseline
   comparison line in router.js (readBaseline) as a generic-api-key false positive; its loop
   variable was renamed to `field` (no behaviour change; hooks are never skipped). The
   committed package is `fce2d112ffd960761faa86b5954f2dda4bc4effb4cb34992b155454c0a8e7788`
   (a run of it passed 10/10, report
   `0c29c84f6433a430de2ea222291bb205aad5b97e4320ba72abbe61317e8d4193`), superseding the
   round-2 candidate `38751d1f...16f9`; THREAT-MODEL T188 cites both. The evidence JSON holds
   the identical-command green record re-run on the final committed source (the reviewer's
   APPROVE-WITH-FIXES doc correction changed THREAT-MODEL, which the record binds).
