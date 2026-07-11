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

- **Must hold** — no green test claims an API Firefox lacks; non-Direct
  routing remains fail-closed against a concretely verified browser profile.
- **Gated** — verification runs in the actual target browser/profile, not only
  a Node mock; foreign-extension inventory requests `management` if retained.
- **Residue** — changing Principle III requires its full governance path and
  cannot be approved by an implementation ticket alone.

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
