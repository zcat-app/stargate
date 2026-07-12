---
id: T091
title: 'Amend the browser-hardening enforcement boundary'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#B4
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: false
files_budget: 8
privacy_critical: true
constitution_refs:
  - "III: Privacy-preserving by construction"
  - "V: Honest threat model"
  - "VII: Tests-first for privacy-critical paths"
  - "VIII: Adversarial review at milestones"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - .specify/memory/constitution.md §III
  - specs/000-architecture/spec.md §14.5
  - specs/001-tor-route/spec.md §FR-004
decision_refs: []
spec_amend_for: .specify/memory/constitution.md §III
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T091: Amend the browser-hardening enforcement boundary

## Context

Stable Firefox WebExtension APIs do not expose the raw DoH, DoT, or HTTP/3
preferences named by FR-004. The existing mock invents properties and would
create false assurance. The implementable v1 boundary is a hardened Mullvad
Browser configuration verified outside the ordinary extension API, while the
extension gates only surfaces it can truthfully inspect.

## Analysis

Property map (privacy_critical + complexity: high → required per
`docs/process/analysis.md`). This ticket is split across the governance
window: **start** (step 5 of `review/sol-review-implementation-plan.md`)
authors the proposal + downstream amendments + the real-browser integration
test + the foreign-extension decision and commits them to the feature branch;
**finish** (step 17) completes the 7-day comment window, ratifies the
passing `stargate-redteam` review, refines T034b/T051/T054/T055 to the
accepted boundary, and merges to main. Acceptance #2 (comment window +
pre-approval redteam) and #6 (dependent refine) are step-17; T091 is **not
`done` until governance completes**.

- **Must hold:**
  - Principle III bullet 3 is rewritten so the hardened target-browser
    configuration is an **externally verified precondition** for non-Direct
    routing, not a WebExtension-API guarantee; the extension gates only
    surfaces Firefox's stable API truly exposes (Constitution III, V;
    sol-review B4).
  - No green test claims a Firefox WebExtension setting that does not exist.
    `network.trr.mode`, `network.dns.over_tls.*`, and
    `network.http.http3.enable` are NOT asserted as readable via
    `browser.privacy.*`. Only `privacy.network.peerConnectionEnabled`
    (WebRTC) and `proxy.ProxyInfo` (`proxyDNS`, SOCKS5 username/password)
    are claimed as extension-API surfaces (Constitution V; Principle VII).
  - Non-Direct routing stays **fail-closed** until the externally verified
    profile is confirmed: `proxy.onRequest` MUST NOT return a SOCKS
    descriptor for non-Direct routes while the profile is unverified
    (FR-004; Principle III).
  - The Sync Impact Report at the top of `constitution.md` records the
    amendment: principle modified = III; proposed version MINOR
    1.1.0 → 1.2.0 (principle stands; one bullet's enforcement locus is
    clarified — governance may override to MAJOR during the comment
    window); privacy-critical-principle redteam + 7-day comment apply
    regardless (Constitution §Governance).
  - A real Mullvad Browser integration test exercises the externally
    verified precondition in the actual target browser (release-cadence
    live-e2e, per `docs/process/workflow.md` §"Live end-to-end
    verification"), not a Node mock (Constitution VII, VIII).
  - The foreign-extension requirement is decided explicitly: **retained**
    as a `management`-permission inventory verified by the real-browser
    test (decision recorded in arch §14.2/§14.5 + THREAT-MODEL §2.7);
    T051's manifest edit to request `management` lands at step-17 refine,
    not here (acceptance #6).

- **Gated:**
  - `scripts/lint-ticket.py` + the clarity floor gate ticket well-formedness
    (PASS at grounding).
  - `scripts/verify.sh` self-detects SKIP for the extension-tests gate (no
    `extension/run-tests.sh` yet) and the live-e2e/reproducibility gates
    (release-cadence, opt-in) — so doc + test-artefact additions keep the
    green gate green.
  - `stargate-codereview` (fresh context, blind) gates the proposal diff's
    correctness at REVIEW.
  - `stargate-redteam` (fresh context, blind) gates the proposal against
    Constitution + THREAT-MODEL — mandatory (Principle III amendment);
    runs at the start-phase redteam gate AND is re-confirmable at step 17.
  - The constitution §Governance flow gates the amendment's **approval**
    (merge to main): 7-day comment + CLEAN redteam. This is the step-17
    finish gate; the milestone `--merge` is the user's explicit step.

- **Residue:**
  - The real Mullvad Browser integration test cannot run in the hermetic
    PR environment (no Mullvad Browser in CI); it is release-cadence
    live-e2e. A regression in the externally-verified precondition between
    release runs is NOT caught at PR cadence. Mitigated by: (a) Node unit
    retained for logic over real-API values (`peerConnectionEnabled`,
    `proxyDNS`); (b) the live-e2e README + `run.sh` a human runs before a
    release tag; (c) redteam at milestones. Promote-to-gated impossible
    without a browser-in-CI; residue accepted and named in THREAT-MODEL
    §5.3/§5.4/§5.5.
  - The amendment's **approval** (merge to main) is a 7-day human
    governance step; no automated gate enforces the waiting period.
    Recorded in the ticket body + Sync Impact Report; `run-task.sh --merge`
    is the user's explicit step.
  - Refine of T034b/T051/T054/T055 to the accepted boundary is step 17
    ("only after this amendment is accepted"); if governance materially
    changes the amendment, the refine must be redone. Tracked by the plan,
    not by an automated gate.

## Acceptance

1. Propose a Constitution Principle III amendment defining hardened target-
   browser configuration as an externally verified precondition rather than
   an ordinary WebExtension guarantee. Update the Sync Impact Report.
2. Complete the mandatory 7-day public comment period and a passing fresh
   `stargate-redteam` review before approval.
3. Amend architecture, feature spec, plan, threat model, and extension
   contract to name the actual enforcement mechanism and failure UX.
4. Replace invented mock properties with a real Mullvad Browser integration
   test. Retain Node units only for logic over API values that truly exist.
5. Decide the foreign-extension requirement explicitly; if retained, T051
   must request `management` and the real-browser test must exercise it.
6. Refine and reopen T034b, T051, T054, and T055 only after this amendment is
   accepted.

## Out-of-scope

Silently failing open, shipping a handwritten mock as proof, or implementing a
privileged Firefox experiment without a separate reviewed distribution model.
