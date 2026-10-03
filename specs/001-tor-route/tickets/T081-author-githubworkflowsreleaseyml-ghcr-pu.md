---
id: T081
title: 'Prepare immutable reviewed release artifacts and workflow'
status: pending
created: 2026-07-04
last_updated: "2026-10-03"
source: review/sol-review.md#M7
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T002a", "T003a", "T014", "T017", "T076", "T098", "T099", "T155", "T075", "T109", "T110", "T111", "T112", "T156", "T206"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md#FR-015
  - specs/001-tor-route/spec.md#FR-016
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted"
  - "VI: Open and Auditable"
  - "VIII: Adversarial Review at Milestones"
decision_refs:
  - .specify/memory/constitution.md#iv-pinned-tested-manually-promoted-updates
  - specs/001-tor-route/contracts/foundation-boundaries.md#compatibility-and-completion
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T081: Prepare immutable reviewed release artifacts and workflow

## Context

FR-015 requires deployable final-image digest pins. The earlier task mixed generated release
artifacts with source/tag write-back, assumed registry authentication and signing used the same
mechanism, and demanded zero secrets.* references while explicitly using GITHUB_TOKEN. T156
replaces those instructions with a reviewed-candidate release contract. No publication or tag
creation is authorized merely by completing workflow implementation.

## Analysis

- Must hold: artifacts trace to the exact reviewed source, immutable content identities,
  verified inputs, explicit promotion and completed release evidence (Constitution IV/VI/VIII).
- Gated: current source-build Compose tests do not establish release artifact provenance or
  cross-host reproducibility. The release workflow must enforce its own evidence prerequisites.
- Residue: generated digests/signatures do not exist before building the candidate. Do not
  invent a circular requirement that embeds final image digests in the source that determines
  those same images. Do not assume OIDC signing authenticates registry pushes.

## Acceptance

1. Specify artifact generation and the publication boundary before code. Source-build local
   Compose remains the development entry point; generate a separate release Compose artifact
   with immutable final-image digests. The tag/source commit is never rewritten after review.
   Generated deployment/provenance manifests reference the exact source commit and are shipped
   as derived artifacts; their generation does not create a replacement source commit.
2. Author failing workflow/fixture tests before implementation. Required tagged-candidate jobs
   run current verify, online grounding and release reproducibility with explicit flags:
   STARGATE_GROUND_ONLINE=1 and STARGATE_VERIFY_REPRO=1. Required skips or missing evidence must
   block release. Preparation fixtures can run without publication credentials or real pushes.
3. Build DP, JVM CP, Tor and Tor-observer (`sidecars/tor-observer/Dockerfile`) artifacts from the
   reviewed candidate with pinned toolchains/inputs, and include the observer in the release
   reproducibility evidence; the generated release Compose pins the observer by its registry digest
   instead of init's local image ID (SECURITY-DECISIONS 2026-10-02, T191).
   Pin and record the extension archive tool/build environment identified by T111; prove the
   delivered extension bytes reproducible. Record artifact hashes, source commit, build inputs,
   SBOMs and signature/provenance verification instructions. Verify output/source agreement.
4. Demonstrate correct registry and signing authentication separately using current primary
   documentation when grounding implementation. Platform-provided short-lived registry tokens
   may be referenced; long-lived registry/signing secrets may not. Scope permissions per job to
   their demonstrated need; no zero-matches grep that rejects the explicitly permitted token.
5. Generated release Compose has digest-pinned images and no source-build directives. Test it
   against the actual topology after T134/T138, not obsolete socket-proxy services. Preserve its
   reviewed listener, volume, identity, capability and egress requirements. Update related
   operator/build/architecture documents within this ticket or add explicit blocking children;
   do not assign new work to already completed T018.
6. Security-decision rationale and release policy are reviewed before tagging. Final generated
   digests/provenance belong in the signed release manifest; the tag job does not append git
   source or mutate a tag. Refuse tag reuse that attempts to associate different source/artifacts
   with an already published release. Failed verification cannot promote a partial release.
7. Workflow preparation precedes T078/T079 so they review its final implementation. Actual
   publication separately requires their completed candidate-bound evidence, applicable live
   tests and Constitution VIII's external human review when triggered. Test rejection of stale,
   missing or mismatched review/evidence records. Do not add circular implementation-ticket deps
   between this preparation task and its final reviewers.
8. Run scripts/verify.sh and independent reviews. Acceptance of workflow preparation is not a
   claim that a release was published or that its live/reproducibility obligations were executed.

## Out-of-scope

Native-image/Mandrel delivery, additional deployment profiles, new registries/architectures,
actual tag creation or publication. Existing source Compose assertions may be reused but cannot
be weakened; new release fixtures must test the generated artifact and the selected topology.

## Notes

This pending-ticket refinement replaces the earlier quoted tasks.md workflow instructions.
The generated artifact and its source identity are distinct; both must remain auditable.

## Approved dependency reconciliation — 2026-10-03

The approved T206 owner must repair the DNS capture-integrity gate before this release-evidence consumer can complete. CP and hardening repair prerequisites remain carried through T155.
