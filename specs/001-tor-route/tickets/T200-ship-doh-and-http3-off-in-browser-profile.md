---
id: T200
title: 'Ship DoH-off and HTTP/3-off in the browser profile; truthful claims'
status: done
created: 2026-10-03
last_updated: 2026-10-18
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
decision_refs: ["user approval: reserved-decisions.md §T200 (SHA-256 2125e70c1f44e16c7d96c30a76fd64fdffafd8911ecc59f21f176b77d57995aa)"]
reviews: { round: 1, date: 2026-10-18, verdict: APPROVE }
overrides: []
aborted_attempts: [{ date: 2026-10-18, round: 2, reason: "run-task --reset", history: target/runs/T200.review-history }]
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


## Current lifecycle note

The corrected-path T186 descriptor-matrix, T186 blocked-proxy and T188 private-access runs
are recorded in `evidence/T200-tests-first.json`; all three passed on pinned Mullvad Browser
Alpha 16.0a12 / Gecko 153.3.0. This records the ticket's scoped live-probe result only.
Hardening-check Part 2 (runtime gate plus allowed/disallowed foreign-extension inventory)
remains a manual release-run-sheet step, and these Alpha runs do not certify the stable
channel or release cadence.

## Review disposition and refinement — 2026-10-18

Round 1's combined verdict was GLM `APPROVE` with one Minor and Astra `REWORK` with one Major.
The GLM Minor was test-integrity: the dialog test asserted the approved sentence but did not
reject an additional false release-verification claim. Its falsifier appended
`DoH, DoT and HTTP/3 are release-verified at each Stargate release.` and expected the test to
fail. The candidate adds a negative guard, a positive control for the false-claim fixture, and
a controlled mutation RED/GREEN record in `extension/background/hardening.test.js` and
`evidence/T200-tests-first.json`; round 2 GLM confirmed that closure.

The Astra Major was inability to verify Acceptance 4 approval: the isolated reviewer lacked
the reserved wording artifact and could not compare the approved text. Its evaluated action
was to provide the existing artifact and verify its SHA-256 and exact wording, without
reconstructing approval. This ticket now embeds the exact four approved passages, their
provenance, and the token-for-token checks. Round 2 GLM confirmed those matches; round 2 Astra
also confirmed them by inspection.

Round 2 Astra's `ESCALATE` identified a separate handoff defect: the isolated reviewer did not
receive the original combined round-1 verdict and its evaluated probes, so it could not
independently close each prior item. This is a review-input defect, not a new source finding.
The complete round-1 and round-2 reports are preserved in `target/runs/T200.review-history`;
the exact prior findings, evaluated probes and dispositions are also summarized here for the
fresh cycle's handoff. The reviewer's recommended refine was applied through the recorded
2026-10-18 reset, which supplied the complete prior findings and probes without changing the
source candidate. The final round-1 pair approved snapshot
`0323b5df931eba35142e0d22a0d31a4a6ab1d5ec728a8445269208482f8d86e1`; the earlier round-2
ESCALATE remains preserved as history, not the final disposition.

## Approved wording provenance

Acceptance 4 required maintainer approval before applying the Quickstart, notification and
THREAT-MODEL wording. The exact approved artifact is
`/home/claudia/stargate-t208/.scratch/reports/2026-10-16-finish-tor-orchestration/reserved-decisions.md`
(SHA-256 `2125e70c1f44e16c7d96c30a76fd64fdffafd8911ecc59f21f176b77d57995aa`); the
matching reply record is
`/home/claudia/stargate-t208/.scratch/reports/2026-10-16-finish-tor-orchestration/user-decision-record.json`
(SHA-256 `063c14e1fd9dc3e9efc491114d5d5db4236f87fc335169eefa363f881be73b3f`), whose
`user_T200_reply` is exactly `Approve the T200 wording` and whose
`approved_T200_wording_sha256` matches the reserved artifact. The four applied passages were
compared byte-for-byte after Markdown quote-prefix and line-wrap normalization; each matches
its approved excerpt. These excerpts are included here so a ticket reviewer can verify the
approved wording without relying on access to the external orchestration directory.

Approved Quickstart replacement for the two release-verification sentences (normalized SHA-256 `dee075ac59bc16d4d7ca140ff7d3eb8e9a31fb5c5ec732e8f19c8dbb773c6f23`):

> The shipped profile sets DoH off (`network.trr.mode=5`) and HTTP/3 off
> (`network.http.http3.enable=false`). The extension cannot read DoH, DoT or HTTP/3 settings.
> They require a separate check of the exact supported browser/profile at release cadence.
> A passing template check alone does not establish that browser result; until its evidence
> is recorded, release verification remains pending. Later profile changes require rechecking.

Approved hardening failure notification ending (after the existing WebRTC explanation; normalized SHA-256 `fdef8d84ce6c457f9ed4eb0a7e0a04c11af94bd129db92ab6e0d4086e3fec8d5`):

> WebRTC is the only hardening surface this extension can verify at runtime. DoH, DoT and
> HTTP/3 require separate browser-profile checks; this notification does not verify them.

Approved THREAT-MODEL §5.4 mitigation replacement (normalized SHA-256 `e1064aa510dabf5f696c8782978bf55e16cab6d8e809ebddc9bab912470a27e2`):

> DoH/DoT being disabled is an external browser-profile precondition, not an extension runtime
> guarantee. The shipped template sets `network.trr.mode=5`. The release-cadence Part 1 check
> verifies a `prefs.js` built only from that template, including absence of an enabled
> `network.dns.over_tls.*` setting. This source check does not prove the effective settings or
> network behavior of a running browser. Exact browser/profile release evidence remains pending
> until the required out-of-band checks complete. The extension cannot read these settings;
> its WebRTC gate cannot certify DoH/DoT. Post-verification drift remains the T091 residue.

Approved THREAT-MODEL §5.5 mitigation replacement (normalized SHA-256 `c9f6cedb3e9ed403945073bc85e0bc69aeebee26cc8c8b75668c4f9a852bdbd2`):

> HTTP/3 being disabled is an external browser-profile precondition. The shipped template sets
> `network.http.http3.enable=false`; the release-cadence Part 1 check verifies that setting in a
> template-only `prefs.js`. Neither that source check nor the extension establishes effective
> settings or network behavior in a running browser. Exact browser/profile release evidence
> remains pending until the required out-of-band checks complete. Later changes require
> revalidation; the extension cannot detect drift in this preference.

## Wording scope boundary

The approved T200 excerpts cover Quickstart, the hardening notification and THREAT-MODEL
§5.4/§5.5 only. The related wording in `specs/001-tor-route/spec.md` FR-004,
`specs/000-architecture/spec.md` §14.5 and THREAT-MODEL §2.7 was not included in those
approved replacements. This ticket leaves those passages unchanged; reconciling them requires
a follow-up with its own scoped wording review. T200's pinned-Alpha results and pending Part 2
record do not establish release-cadence browser evidence.

## Ticket disposition — 2026-10-18

The four acceptance criteria are complete: the template-only Part 1 check is GREEN; the
T186 descriptor-matrix and blocked-proxy probes and T188 private-access probe are GREEN on
the pinned Alpha 16.0a12 / Gecko 153.3.0 candidate; the required source and user-facing
wording is applied; and the final paired round-1 review approved the exact candidate above.
The affected Node and Python suites and ticket lint were rerun on the integration tree and
passed.

GLM's APPROVE includes one non-blocking test-integrity Minor: the notification guard's
negative pattern can miss an additional surface-agnostic release-verification sentence.
The shipped notification remains truthful, the approved wording is positively pinned, and
the candidate-specific DoH false-claim regression is covered. This reviewer finding does not
change the four acceptance outcomes; the future-phrase guard is retained as a test-only
test-hardening residue rather than silently treated as product qualification.

This closes T200's ticket scope. It does not claim a stable-channel or release-cadence
qualification, an effective-profile runtime measurement, or completion of manual Hardening
Part 2. Those remain separate browser-release gates; the revised wording continues to say
they are pending. The 2026-10-17 system-browser diagnostic recorded Mullvad Browser
140.17.0 / Gecko 140.17.0; this is a historical diagnostic and was not the pinned Alpha
16.0a12 / Gecko 153.3.0 used for these probes. It makes no claim about a later system-browser
installation.
