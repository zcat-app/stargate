---
id: T091
title: 'Amend the browser-hardening enforcement boundary'
status: done
created: 2026-07-11
last_updated: 2026-07-12
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
reviews: { round: 1, date: 2026-07-12, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - "2026-07-12 r1 M1 (major, CLOSED): 'confirmed for this session' runtime gate overclaimed a per-session binding the extension cannot deliver for DoH/DoT/HTTP-3 (sol-review B4). Fixed: FR-004 + arch §14.5 Failure UX + Principle III bullet 3 rewritten — hardeningOk is a pure function of peerConnectionEnabled; runtime fail-closed is WebRTC-only; DoH/DoT/HTTP-3 are release-cadence-verified with accepted residue. redteam/findings/closed/20260712-001-confirmed-for-session-gap.md"
  - "2026-07-12 r1 m1 (minor, FIXED): live-e2e grep verifies test-profile user_pref lines, not effective distribution pref state; false-REDs on lockPref/policies.json. Fixed: pref-source caveat in README/run.sh/arch §14.5; 'test profile that models the target browser's hardened defaults' wording."
  - "2026-07-12 r1 m2 (minor, FIXED): management permission fingerprint asymmetry undocumented. Fixed: THREAT-MODEL §2.7 itemizes what management exposes + compromised-Stargate fingerprint risk."
  - "2026-07-12 r1 i1 (info, FIXED): prop 1 requires network.trr.mode==5 exactly. Fixed: run.sh comment notes mode 5 is the explicitly-off sentinel."
  - "2026-07-12 r2 m3 (minor, FIXED): THREAT-MODEL §5.5 claimed test asserts network.http.http3.enable_kdtp (fabricated/unverified pref). Fixed: dropped the kdtp parenthetical; only network.http.http3.enable is asserted."
  - "2026-07-12 r3 m4 (minor, FIXED): orphan fragment 'SOCKS5/HTTP-CONNECT listeners.' left in §5.5 by the m3 edit. Fixed: deleted."
  - "2026-07-12 r3 m5 (minor, FIXED): §5.3/§5.4 still said 'actual Mullvad Browser profile' (m1-class overclaim), inconsistent with the §5.5 tightening. Fixed: both now say 'a test profile that models the target browser's hardened defaults'."
  - "redteam endorsement (r2, reaffirmed r3): the amended Principle III bullet 3 boundary is constitutionally sufficient for v1 given the named residue; no Blocker, no Major in any round after M1's fix."
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
  - Non-Direct routing is **fail-closed at runtime against WebRTC** (the
    one surface the stable API exposes): `proxy.onRequest` MUST NOT return
    a SOCKS descriptor for non-Direct routes while
    `peerConnectionEnabled != false`. The DoH/DoT/HTTP-3 surfaces are
    release-cadence-verified, NOT runtime-enforced; there is no per-session
    "profile confirmed" signal (stargate-redteam M1, 2026-07-12 — the
    pre-rework "confirmed for this session" wording is removed). Their
    post-verification drift is accepted residue (FR-004; arch §14.5;
    Principle III).
  - The amendment log at the top of `constitution.md` records the change:
    principle modified = III; **no version bump** (the project has shipped
    no binary and has no public remote — semver-on-amendments becomes
    binding at first public release; the earlier v1.1.0 bump for the JDK
    pin is marked SUPERSEDED as the same pre-release over-signalling
    error). The privacy-critical-principle redteam + 7-day comment still
    apply (Constitution §Governance) — T091 runs `stargate-redteam` as
    good practice and the maintainer opens a comment window via the
    governance PR.
  - A real Mullvad Browser integration test exercises the externally
    verified precondition against a test profile that models the target
    browser's hardened defaults (release-cadence live-e2e, per
    `docs/process/workflow.md` §"Live end-to-end verification"), not a
    Node mock (Constitution VII, VIII).
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
    release runs is NOT caught at PR cadence.     Mitigated by: (a) a future Node unit
    (T034b, step-17 refine — not yet in tree) over real-API values only
    (`peerConnectionEnabled`, `proxyDNS`); (b) the live-e2e README +
    `run.sh` a human runs before a release tag; (c) redteam at milestones. Promote-to-gated impossible
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
