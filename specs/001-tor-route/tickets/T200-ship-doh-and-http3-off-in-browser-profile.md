---
id: T200
title: 'Ship DoH-off and HTTP/3-off in the browser profile; truthful claims'
status: pending
created: 2026-10-03
last_updated: "2026-10-03"
source: "T155 attempt 4 cumulative redteam (index tree 6e70e622): area 2 M1, narrowed to Minor by falsification (E1, E2 and live experiment X1); maintainer approved filing 2026-10-03"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T205"]
parallel: true
files_budget: 11  # ticket + STATUS.md + evidence/T200-tests-first.json (overhead); browser-profile/user.js;
                  # tests/live-e2e/mullvad-browser-hardening/{run.sh,probe.py,README.md};
                  # specs/001-tor-route/quickstart.md; extension/background/hardening.js (+ its test); THREAT-MODEL.md
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: low
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-004
  - browser-profile/user.js
  - tests/live-e2e/mullvad-browser-hardening/README.md
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T200: Ship DoH-off and HTTP/3-off in the browser profile; truthful claims

## Context

Constitution III makes non-Direct routes depend on a tested browser profile with DoH, DoT,
WebRTC and HTTP/3/QUIC disabled, verified out of band at release cadence. The pinned Mullvad
Browser 153.3.0esr defaults to DoH-only (`network.trr.mode=3`, Mullvad's Quad9 resolver) and
leaves HTTP/3 enabled. `browser-profile/user.js`, from which the quickstart builds the only
supported profile, sets neither pref. Falsification of the T155 attempt-4 redteam found:

- `tests/live-e2e/mullvad-browser-hardening/run.sh` Part 1 is RED on a `prefs.js` built only
  from the shipped template (DoH-off and HTTP/3-off both fail, exit 1).
- Every T186/T188 probe session injects `network.trr.mode=5` (`probe.py` around `:1435-1446`),
  which hides the gap.
- The quickstart (around `:308-309`), the `hardening.js` failure notification (around
  `:98-101`) and THREAT-MODEL §5.4/§5.5 call the precondition verified at each release.
  T195 labelled this the "T091 residue", which the constitution limits to drift after
  verification.
- Live experiment X1 (pinned browser, template-only profile) showed no onion name reached the
  resolver, DoH or HTTP/3: Gecko skips those paths for proxied requests. So this is a
  precondition-compliance and truthfulness defect, not a demonstrated leak.

## Analysis

- Must hold: the shipped template meets the Constitution III browser precondition for DoH and
  HTTP/3, the release check verifies the template itself, and no document claims more.
- Gated: `run.sh` Part 1 against a template-only `prefs.js`; extension unit tests.
- Residue: post-verification drift stays the documented T091 residue.

## Acceptance

1. Tests first: `run.sh` Part 1 runs against a `prefs.js` built only from the shipped
   `browser-profile/user.js` (plus nothing the template does not carry). Record it RED before
   the fix with `scripts/test-first-evidence.py`, then GREEN after.
2. `browser-profile/user.js` sets `network.trr.mode=5` and `network.http.http3.enable=false`
   (and any companion pref the release check names for DoT/HTTP-3), each with a comment
   linking Constitution III.
3. `probe.py` sessions stop injecting `network.trr.mode`, or the probe asserts that the
   shipped template carries the value it relies on; the T186/T188 probes stay GREEN.
4. The quickstart, the `hardening.js` notification text and THREAT-MODEL §5.4/§5.5 state what is
   verified and when, and stop calling the precondition release-verified where it was not.
   THREAT-MODEL and user-facing wording need maintainer approval at T200 time: stop and return
   drafts before writing them.

## Out-of-scope

The WebRTC re-audit decision (T190 item 1); onion-page clearnet subresources (T190 item 7);
the foreign-extension inventory and DoH-blocklist prose (T197 item 3).

## Approved dependency reconciliation — 2026-10-03

The approved T205 hardening-record repair precedes this ticket because acceptance 4 consumes the same notification behavior and hardening contract. Existing profile requirements and exact-wording approval remain in force.
