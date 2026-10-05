---
id: T190
title: 'Resolve surviving control-plane and browser redteam minors'
status: pending
created: 2026-09-29
last_updated: "2026-10-05"
source: "reviews/redteam-20260929-694dbd8.md (area 2 minors that survived falsification); items 5 and 8 additions, item 7 redirect addition and item 10 from the T155 r5 cumulative redteam (area 2, falsified 2026-10-05): items 7 and 8 maintainer approved 2026-10-05, items 5 and 10 filed under the maintainer's delegation of 2026-10-05"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192", "T204", "T205"]
parallel: true
files_budget: 22   # raised 12 -> 17 for T155 attempt-2 additions (maintainer-approved 2026-10-01): TokenLoader.java, TokenLoaderTest.java, data-model.md, quickstart.md, THREAT-MODEL.md
               # raised 17 -> 22 for the T155 r5 additions (maintainer-approved 2026-10-05 for items 7, 8; items 5, 10 under the maintainer's 2026-10-05 delegation):
               # extension/background/router.test.js + tests/live-e2e/mullvad-browser-hardening/probe.py (item 7 redirect test; item 10(b));
               # browser-profile/user.js + extension/background/router.js (item 10(a) only); scripts/subcommands/init (item 5 comment).
               # The earlier 17 was not re-inventoried against items 1-9; the T190 developer checks it at START.
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "II: Plane Separation"
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-004
  - specs/001-tor-route/data-model.md
decision_refs:
  - "architecture spec §14.5 Part 2: WebRTC read at startup and on browser restart (item 1 needs a spec decision)"
  - "2026-10-05 maintainer: \"A: No, scoped + release decision\" (item 7 redirect addition: not an automatic route downgrade under 001's destination-only routing; 001-specific, not extended to user-selected routes; maintainer decides block-or-disclose before T078)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T190: Resolve surviving control-plane and browser redteam minors

## Context

Surviving items from the 2026-09-29 cumulative redteam area 2 after
falsification. The stale `control.sock` finding was falsified (shipped Netty
unlinks before bind) and the skip-when-missing extension tests were falsified
(other suites fail); they are out of scope except the misleading javadoc noted
below.

## Analysis

- Must hold: each item is fixed with a discriminating regression or corrected text.
- Gated: extension and CP test suites, `scripts/verify.sh`.
- Residue: item 1 requires a maintainer/spec decision before code.

## Acceptance

1. WebRTC re-audit: decide in the spec whether FR-004(b) requires a fresh check
   per protected decision. If so, re-read `peerConnectionEnabled` per decision
   (`onChange` alone misses about:config edits) and fail closed while pending;
   test a mid-session flip. Otherwise document the startup-only residue in the
   threat model.
2. Zero-row timeline: keep a single current zero checkpoint for `enrolled`
   (not one per closed hour), never write a zero for an hour not observed, and
   test the total row count.
3. Remove the unused `management` permission (or land its specified consumer)
   and update `manifest.test.js`.
4. Exclude tests, `run-tests.sh`, README and untracked files from
   `extension/package.sh` output; test the archive listing.
5. CP capabilities: mount `stargate-keys` read-only in the CP with ownership that
   keeps the directory non-CP-writable, and update `control_mount_test.sh`. (The
   orphan `stargate-tor-config` mount is T191 item 7.)
   Addition (T155 r5 cumulative redteam, area 2 m6 note, 2026-10-05; maintainer delegated
   the filing choice 2026-10-05, orchestrator decided): the comment in
   `scripts/subcommands/init` above the `stargate-keys` volume initialisation,
   "stargate-keys: CP-owned (writes pubs/pepper at runtime), group ipc.", describes the
   ownership this item changes; correct it with the mount change so the two agree.
6. Nits: token input `type="password"`; stale "non-persistent" comment in
   `hardening.js`; drop or constrain unused timestamped V001 tables before any
   writer lands; correct the `ControlGrpcService` and `HealthEndpoint` javadocs.


Added 2026-10-01 from the T155 attempt-2 redteam (`reviews/redteam-20261001-79d49e9.md`),
maintainer-approved:

- Item 1 addition (A2-M1 gap): `hardening.test.js` re-calls `auditHardening()`
  (`hardening.js:48`; test :184, :196, `reauditObservesChangedProfileState` :341) but no
  production path does; the only production call is load-time (`hardening.js:129`) and the
  `:29` comment ("re-reads the setting every call") implies otherwise. Either add a
  production re-read caller (per protected decision, failing closed) or relabel those
  tests as API-contract-only and fix the comment.

7. THREAT-MODEL.md:707 "The destination service does not learn the user's IP address"
   is scoped to the onion route: in 001 only `.onion` destinations are Tor-routed, and
   clearnet resources an onion page causes the browser to fetch go Direct (with local DNS),
   revealing the user's IP and resolver to those hosts (cf. §2.5, §6.2; spec.md:123). (A2-M3)
   Addition (T155 r5 cumulative redteam, area 2 B1, redirect sub-case, narrowed to Minor by
   falsification 2026-10-05; maintainer approved filing 2026-10-05).
   Maintainer reading, 2026-10-05 ("A: No, scoped + release decision"): under 001's
   destination-only routing, an onion page's redirect to a clearnet URL is not an "automatic
   route downgrade" (Constitution III network-origins matrix, "Browser's routed request").
   The reading is specific to 001 and does not extend to user-selected routes.
   (a) Maintainer decision, first, and in any case before T078: whether clearnet requests
       initiated from an onion page are blocked in 001 instead of only disclosed. This
       ticket does not decide it. Stop and ask before writing (b) or (c); record the
       decision and its date here.
   (b) Disclosure, written to the decided outcome: the scoped THREAT-MODEL §4.2 sentence and
       the quickstart baseline list also name the ways an onion service can cause clearnet
       requests in 001 (subresources, links, script navigation, HTTP redirects) and state
       what happens to them. If they stay unrouted, "(with local DNS)" is written to match
       the profile shipped when this lands. Wording needs maintainer approval: stop and
       return drafts before writing it.
   (c) Test, asserting the decided outcome: a `router.test.js` case and a `probe.py`
       scenario for an onion main-frame 302 to a clearnet URL, with a clearnet top-level
       positive control. If the decision is "disclosed only": the redirect target gets the
       Direct decision, the popup shows `Main navigation decision: Direct (unrouted)`, and
       the probe observes the network outcome (the clearnet target is fetched outside the
       SOCKS route and does not appear in the 8881 capture). If the decision is "blocked":
       stop. Blocking is a routing change against FR-001 and `foundation-boundaries.md`
       ("Intentional non-protected traffic returns the explicit Direct descriptor and is not
       canceled"); it needs its own tests-first ticket in T078's `blocked_by`, and the
       maintainer re-scopes (b) and (c) here. No onion-to-clearnet redirect has been run;
       the present behaviour is read from `router.js`.
8. `TokenLoader` (`TokenLoader.java:145` uses SnakeYAML `compose()`, which keeps duplicate
   keys; `:184-189` takes the first top-level `tokens`; `:216-225` keeps the last duplicate
   within a record) rejects the whole file on any duplicate key at document, top-level or
   record level as `config_error` (no store, generation or push), documented in data-model
   §1.1. TokenLoaderTest covers a duplicate top-level `tokens` (e.g. an appended
   `tokens: []`) and duplicate `label`/`token` in a record. (A2-M4)
   Addition (T155 r5 cumulative redteam, area 2 m3, narrowed to Info by falsification
   2026-10-05; maintainer approved filing 2026-10-05): `TokenLoader` enforces unique labels
   only, so two labels may carry the same token value; removing one label then leaves the
   credential valid while the `revoked` label diff counts it. Either reject a file in which
   two records share a token value, whole, as `config_error` (no store, generation or push),
   with a `TokenLoaderTest` case; or state in data-model §1.1 and the quickstart revocation
   text that removing one of two labels sharing a token does not revoke the credential.
   The maintainer chooses (rejecting a file that loads today is an operator-visible change);
   the choice is recorded in this ticket before code. Data-model and quickstart wording
   needs maintainer approval.
9. Quickstart "Check token delivery (and revocation)" (`quickstart.md:122-137`) states that
   `scripts/stargate status` reflects only the credential set the running control plane
   last loaded, so `stargate-control` must be restarted after editing `tokens.yaml` before
   checking; the `ACKNOWLEDGED(<generation>)` row at :134 is made true. (A2-m6)
10. (T155 r5 cumulative redteam, area 2 m2, narrowed to a Minor disclosure by falsification
    2026-10-05; filed under Acceptance 6; maintainer delegated the filing choice 2026-10-05, orchestrator
    decided)
    `browser-profile/user.js` keeps `<local>` in the proxy bypass list, so a single-label
    hostname requested from any page, an onion page included, is unrouted. `<local>` is part
    of the maintainer-selected T188 baseline, so the maintainer chooses, recorded here before
    any change:
    (a) remove `<local>` from the bypass list, with the baseline fingerprint
        (`passthroughFnv1a64` in `router.js`) and the `router.test.js` template test
        (`profileTemplateBypassesOnlyIcannTopLevelDomains`) updated, red before green; or
    (b) name single-label hosts as unrouted in the quickstart baseline list and the
        THREAT-MODEL T188 residue, and add a `probe.py` case that records where a
        single-label name is resolved under the template shipped when this lands (T200
        changes the resolver mode; the path is unmeasured today).
    THREAT-MODEL and quickstart wording needs maintainer approval: stop and return drafts
    before writing it.

## Out-of-scope

Blocked-result semantics (T186); revocation status (T187); private-window access (T188).

## Approved dependency reconciliation — 2026-10-03

The approved T204 CP listener repair and T205 hardening-record/schema repair precede this ticket because its HealthEndpoint and hardening comments/tests consume those mechanisms. Their direct own-change orphan corrections belong to those owners; this ticket retains its remaining acceptance and does not duplicate completed repairs.

## T204 endpoint-javadoc absorption

T204 owns Acceptance 6's `HealthEndpoint` javadoc correction together with its
HTTP listener repair: Compose and the installer do not poll the stub. T190's
`ControlGrpcService` javadoc item, other acceptance and lifecycle remain pending.
