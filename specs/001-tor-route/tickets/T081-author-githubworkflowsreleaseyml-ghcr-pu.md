---
id: T081
title: 'Prepare immutable reviewed release artifacts and workflow'
status: done
created: 2026-07-04
last_updated: "2026-10-11"
source: review/sol-review.md#M7
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T002a", "T003a", "T014", "T017", "T076", "T098", "T099", "T155", "T075", "T109", "T110", "T111", "T112", "T156", "T206"]
parallel: false
files_budget: 25
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
reviews: { round: 9, date: 2026-10-11, verdict: APPROVE }
overrides:
  - "2026-10-11 maintainer session: affected Python/shell/workflow/init checks only at source checkpoints; no full verifier or Java/Go builds locally. Future release preparation still requires the complete gate."
  - "2026-10-11 maintainer session: independent Astra/high and Luna/high ticket reviews; implementor switched to Sol/high and does not review its own work."
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
8. Run scripts/verify.sh and independent reviews (the 2026-10-11 session limits local
   source checkpoints to affected fixtures and selects independent Astra/Luna reviews;
   no full-green claim follows from those fixtures). Acceptance of workflow preparation is not a
   claim that a release was published or that its live/reproducibility obligations were executed.

9. Before implementation, record a real failing `release_init_test.sh` probe showing that
   invalid release data or unknown init arguments reach a host/Compose mutation. Then
   require the same command to pass without a mutation. `release_test.py` invokes the
   driver CLI with bounded API and recording executable fixtures: wrong source/tag,
   topology mutation, missing/stale evidence, required skips, forged approvals,
   missing/bypass protection, expired/swapped artifacts, wrong signer identity,
   failed upload and version reuse must refuse. Preparation must never dispatch a
   push/signature. Valid release init must retain host policy, identity/volume handling
   and authenticated readiness while never building. Fixture results do not establish
   real tool compatibility, apt acceptance, signatures, live evidence or publication.

## Out-of-scope

Native-image/Mandrel delivery, additional deployment profiles, new registries/architectures,
actual tag creation or publication. The extension reproducibility test may select a
pinned release runner while retaining its host default and archive assertions; the
Tor security-decision test may reconcile historical write-back comments without
weakening its fabrication guard. Existing source Compose assertions may be reused but cannot
be weakened; new release fixtures must test the generated artifact and the selected topology.

## Notes

This pending-ticket refinement replaces the earlier quoted tasks.md workflow instructions.
The generated artifact and its source identity are distinct; both must remain auditable.
The 25-file budget includes the existing T106 count-probe fixture: the common Docker
endpoint preflight must be represented by its fake daemon so its original fail-closed
assertion still runs after the T081 review finding is fixed.
The two added paths are the existing T198 and T162 pure init fixtures, whose
Docker stubs must report the local context and socket before their original
host-policy assertions can execute.
The added path is `evidence/T081-r1-r2-recovered-session.json`, a narrow extraction
of original R1/R2 session events requested for tests-first adjudication. It records
test-only edits, failing runs, production edits and passing runs for CRLF identity,
verifier builder selection and remote Docker refusal. No per-run complete source
hash was captured, and the Tor rollback runtime probe is post-fix only; the
recovered chronology does not amend the original tests-first red record.
R7 replaces the draft-visible numbered release scan after a fixture showed
an unrelated deletion moving the target draft to an already-read page. The
protected job now checks the exact tag through GraphQL and published REST
lookups twice. These reads are observational; authorized human/API writers
must coordinate with the workflow's per-version serialization, and uncertain
create or publish responses require manual reconciliation. The same R7 red
record also captures the T198/T162 pure stub failures before their local
Docker context responses were repaired. No live push-capable token check was
available in this implementation session.
Current GitHub release API behavior adds a conditional `GITHUB_TOKEN`
compatibility gate: before each write phase, compare C's workflow Git subtree
with the current default branch's workflow subtree using complete API data.
Equal subtrees permit differing commits; mismatch or unknown state refuses.
The default branch can still move after the final check, so no live-token
compatibility or atomic publication guarantee is claimed.
The R7 evidence retains all three sequential red captures. The first two
(row-shift plus T198/T162, then ambiguous write-status) moved into
`superseded` when the next failing property was recorded; their exact
commands were rerun green on the final candidate and are recorded separately
in `r7_followup_greens`. The current top-level red/green pair covers the
workflow-tree guard. This is observed fixture chronology, not a live GitHub
authorization test.
R8 found two further source-binding gaps. R9 records failing same-named-branch
and OCI-predicate fixtures before repair: every remote source guard now resolves
the `refs/tags` namespace, and the OCI inspector validates structured BuildKit
SLSA v1 local-context fields instead of searching for C anywhere in JSON.
The observed pinned-builder v1 sample grounds that schema. BuildKit's local
VCS fields are unverified hints and its materials are incomplete; the
pre/post clean source checks and signed release manifest remain authoritative.
No live release or broad verifier was run for this repair.
The tag-only red moved to `superseded` when the structured-OCI red was
captured. Its original command was rerun green on the final candidate and
retained in `r9_followup_green`; the top-level red/green pair covers the
OCI predicate. A read-only check of the retained native v1 OCI sample is
recorded separately in `r9_native_v1_sample`.
R9 independent reviews approved the exact staged implementation: Astra
(`gpt-6-astra`, high) and Luna (`gpt-6-luna`, high), source seal
`caff26c3d15fba4ea5aac6df987cca33d2ea9bb00ceb61c22acf63f5d24450b6`,
staged patch SHA-256
`789352b18b517a536bde4d0da06d981ad412bb8a95c74357a3a7edc689723a59`.
Their approval covers preparation and affected fixtures, not live publication
or the full verifier, under the session override above.

## Approved dependency reconciliation — 2026-10-03

The approved T206 owner must repair the DNS capture-integrity gate before this release-evidence consumer can complete. CP and hardening repair prerequisites remain carried through T155.
