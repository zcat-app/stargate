---
id: T081
title: 'Author `release.yml` workflow: GHCR push + image digest pin (FR-015)'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T081
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T002a, T003a, T014, T017, T076]
parallel: false
files_budget: 8
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - spec.md#FR-015
  - spec.md#FR-016
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted"
  - "VI: Open and Auditable"
  - "VIII: Adversarial Review at Milestones"
decision_refs:
  - plan.md#release-cadence (T078 redteam + T079 perf gate the tagged commit)
  - arch-spec.md#7-tor-row (NEEDS CLARIFICATION — pin at first release tag — resolved BY this ticket)
  - arch-spec.md#715-716 (signing-tool NEEDS CLARIFICATION — resolved BY this ticket in favour of cosign/sigstore)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T081: Author `release.yml` workflow: GHCR push + image digest pin (FR-015)

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the spec-kit plan that
survives `/speckit-tasks` regeneration.

**Origin:** surfaced as T015 §Analysis residue R1 — FR-015's literal clause
"Both the Debian-slim base **and** the final composed image MUST be pinned by
sha256 digest in `compose/docker-compose.local.yml`" is currently unmet for the
three Stargate-built images (DP/CP/Tor). T014/T002a/T003a all deferred to "T015
pins the final image digest"; T015 shipped using `build:` directives with
base-digest pinning inside each Dockerfile, which satisfies the *base*-pin half
of FR-015 but not the *final-image*-pin half. This ticket closes the gap. It is
a **release-blocker for FR-015**.

> **Full task body (verbatim from tasks.md):**
>
> Author `.github/workflows/release.yml` — the GHCR push + final-image digest
> pin write-back workflow (FR-015's literal "final composed image MUST be pinned
> by sha256 digest in compose/docker-compose.local.yml" clause, currently unmet
> for the three Stargate-built images; surfaced as T015 §Analysis R1). On `v*`
> tag push: (a) gate on T076's contract-test workflow passing on the tagged
> commit (FR-016 gate); (b) build the three Stargate images — `stargate-dp`
> from `data-plane/Dockerfile` (T002a), `stargate-control` from
> `control-plane/Dockerfile` (T003a), `tor` from `sidecars/tor/Dockerfile`
> (T014) — using the byte-reproducible build flags already encoded in each
> Dockerfile (T004 / arch §12.1 / §12.2; reproducibility asserted by
> T075/T075b); (c) push each to `ghcr.io/zcat-app/stargate-{dp,control,tor}:<tag>`
> (tagged, mutable) AND to `ghcr.io/zcat-app/stargate-{dp,control,tor}@sha256:<digest>`
> (immutable); (d) sign each with cosign via sigstore keyless OIDC (Principle
> IV; resolves arch §715-716 signing-tool NEEDS CLARIFICATION in favour of the
> OCI standard); (e) emit an SBOM per image (syft / equivalent); (f) render a
> release-tag artifact `compose/docker-compose.release.yml` — a digest-pinned
> variant of `compose/docker-compose.local.yml` where each Stargate-built
> service's `build:` + `image: stargate/...:local` pair is replaced with
> `image: ghcr.io/zcat-app/stargate-...@sha256:...` (the
> tecnativa/docker-socket-proxy pin already lives in
> `compose/env/local.env.example` and is preserved verbatim); (g) append the
> three final-image digest values + the SBOM URIs + the cosign signature URIs
> to `SECURITY-DECISIONS.md` (T017), unblocking T017's "final-image digest
> values" entry AND resolving arch §7 Tor row's "NEEDS CLARIFICATION — pin ...
> at first release tag" marker (T018 propagates the resolution into the arch
> spec text once T081 has produced the values). The workflow uses GitHub OIDC
> to authenticate to GHCR (no long-lived PATs — Principle VI auditable, no
> secrets in CI config); `permissions:` block scoped to `packages: write` +
> `contents: write` (SECURITY-DECISIONS.md append commit) + `id-token: write`
> (cosign keyless). The workflow does NOT push to Docker Hub (single-registry
> keeps the audit trail linear). Cross-reference THREAT-MODEL §3.1 (local
> profile — the signed+pinned images are the deployment-time trust root for
> the local profile; a future LAN/VPS profile MUST re-run this workflow with
> profile-specific threat modelling). **Release-blocker for FR-015.**

## Analysis

*(Required — `privacy_critical: true`, `complexity: medium`. Fill at `/start`
per `docs/process/analysis.md`.)*

The /start analysis should at minimum surface and resolve these design
questions (the task body picks defaults; analysis confirms or refines):

- **Pin write-back mechanism.** The task body proposes generating
  `compose/docker-compose.release.yml` as a separate artifact (not editing
  `docker-compose.local.yml` in place). Confirm this is right: the `local`
  file stays the build-from-source development variant; the `release` file is
  the deployment-time pull-verified variant. The split keeps `local` green
  under `local_compose_test.sh` (which expects `build:` directives) without
  conditional test logic. (Alternative considered + rejected: env-file-driven
  pin injection — rejected because the operator would need to manually
  populate the digest values, defeating the automation.)
- **Tag-immutability discipline.** `:<tag>` (mutable) and `@sha256:<digest>`
  (immutable) are both pushed. Renovate/dependabot MUST NOT auto-bump the
  mutable tag (Principle IV — manual promotion). The `release.yml` workflow is
  the ONLY mechanism that writes to `ghcr.io/zcat-app/stargate-*`. Confirm no
  other workflow or human push path exists.
- **cosign keyless vs. key-based signing.** Task body picks keyless OIDC
  (sigstore Fulcio CA). This binds signature identity to the GitHub Actions
  workflow identity (auditable in the provenance). The alternative (a
  long-lived cosign key in GitHub Secrets) violates Principle VI's "auditable"
  + the no-secrets-in-CI stance. Confirm keyless is the right pick + that the
  rekor transparency log entry is recorded in `SECURITY-DECISIONS.md`.
- **SBOM format.** syft emits SPDX and CycloneDX. Pick SPDX (matches the
  repo's license-header convention). Record the choice in
  `SECURITY-DECISIONS.md`.
- **Failure modes.** What happens if the SECURITY-DECISIONS.md append fails
  (e.g., branch protection on main blocks the bot commit)? The signed images
  are already in GHCR but unverified-by-record. Bright-line: workflow FAILs
  the release; images remain in GHCR (immutable, signed) but the release tag
  is not considered shipped until the SECURITY-DECISIONS.md commit lands.
  Document in §Acceptance.
- **Re-tag policy.** What happens if someone pushes `v1.0.0` twice (after
  deleting and re-pushing the tag)? GHCR digests are immutable, so a re-push
  with different bytes produces a NEW digest; the mutable `:v1.0.0` tag now
  points at the new digest, the old digest is orphaned.
  `compose/docker-compose.release.yml` rendered in the prior release still
  references the OLD digest (immutable, still pullable if not GC'd). This is
  correct behaviour (release artifacts are immutable); document.
- **Release-cadence online-gate discipline (the meta-finding).** AT-1 makes
  `STARGATE_GROUND_ONLINE=1 bash scripts/verify.sh` a release-mandatory
  bright-line. The implementer MUST wire it as a real workflow job (not a
  comment, not a manual step) that runs BEFORE the build job and whose FAIL
  halts the release. This is the systemic fix for the class of invisibility
  that let the `docker manifest inspect` defect (commit `892a1d0`) ship and
  sit unnoticed — a release-cadence gate that is never run automatically is
  a release-cadence gate that does not exist. Confirm: the job sets BOTH
  `STARGATE_GROUND_ONLINE=1` AND `STARGATE_VERIFY_REPRO=1` (the latter opts
  into the release-cadence reproducibility gate per verify.sh gate 5; both
  are release-tag-only flags by design).

## Acceptance

*(Derive from the spec at `/start`. Suggested shape — the implementer refines.)*

**AT-1 — Workflow triggers cleanly on tag.**
```bash
# Dry-run trigger against a test tag (does NOT push to GHCR; gating mode).
git tag v0.0.0-rc-test-t081 && git push origin v0.0.0-rc-test-t081
# Workflow run completes; jobs: gate-on-contract-tests PASS, build-three-images
# PASS, sign-and-sbom PASS, render-release-compose PASS, append-to-SECURITY-DECISIONS PASS.
gh run list --workflow=release.yml --limit=1
```
The tag-trigger condition asserts (each is a separate early-halt job in the
workflow; any failure stops the release before any image is built):
- **T076's contract-test workflow** is green on the tagged commit (FR-016 gate).
- **T078 redteam verdict** is CLEAN (read from
  `specs/001-tor-route/.handoffs/T078.verdict` or equivalent).
- **T079 perf verdict** is green.
- **`STARGATE_GROUND_ONLINE=1 bash scripts/verify.sh`** is GREEN on the tagged
  commit. This is the release-cadence run of the online ground-check — the
  gate that resolves every Dockerfile FROM pin AND every compose `image:` pin
  (and toolchain EOL) against live registries / endoflife.date. It is the only
  automation that catches a pruned/malformed/re-rolled digest or an EOL
  toolchain before they ship in a signed release image. **This bright-line is
  load-bearing:** the ground-check online mode silently broke for multi-arch
  Dockerfile FROM digests between T002a/T003a/T014 landing and the fix at
  commit `892a1d0` (switched from `docker manifest inspect` to
  `docker buildx imagetools inspect`); the breakage was invisible because no
  release-tag run had ever executed the online gate. Making it release-mandatory
  here closes that systemic gap — a future regression of the same class will
  halt the release loudly instead of shipping a signed-but-broken pin.
- Missing any → workflow halts before the build job.

**AT-2 — Three images pushed, signed, SBOM'd.**
For each of `stargate-dp`, `stargate-control`, `tor`:
- `docker pull ghcr.io/zcat-app/stargate-<name>:<tag>` succeeds.
- `docker buildx imagetools inspect ghcr.io/zcat-app/stargate-<name>@sha256:<digest>` succeeds (the digest is in the SECURITY-DECISIONS.md append).
- `cosign verify ghcr.io/zcat-app/stargate-<name>:<tag> --certificate-identity-regexp 'https://github.com/zcat-app/stargate/.github/workflows/release.yml@refs/tags/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com` succeeds.
- `syft` SBOM is attached as a cosign attestation; `cosign download attestation ghcr.io/zcat-app/stargate-<name>:<tag>` returns a non-empty SPDX document.

**AT-3 — Release compose variant renders and is structurally valid.**
The workflow renders `compose/docker-compose.release.yml` (commit to the tag,
NOT to main). Structural contract test (extend
`tests/contract/compose/local_compose_test.sh` or add a sibling
`release_compose_test.sh`):
- `docker compose -f compose/docker-compose.release.yml config --quiet` exits 0.
- Each of the three Stargate services has `image: ghcr.io/zcat-app/stargate-...@sha256:<64hex>` (no `build:` directive; no bare `:local` tag).
- The tecnativa/docker-socket-proxy pin is unchanged from `compose/env/local.env.example`.
- UID/GID, volumes, ports, networks, depends_on invariants from T015's M1–M13 still hold (reuse the same assertions).

**AT-4 — SECURITY-DECISIONS.md append lands.**
A commit on main (or a PR that merges) appends a section to
`SECURITY-DECISIONS.md` with: release tag, the three final-image digests (with
`docker buildx imagetools inspect` confirmation commands), the three SBOM URIs
(or cosign attestation references), the three cosign signature / rekor
transparency-log entries. Cross-references T017's rotation policy. Unblocks
T018's arch-spec §7 Tor row amendment.

**AT-5 — No long-lived secrets in CI.**
`grep -E 'secrets\.' .github/workflows/release.yml` returns zero matches (the
workflow uses `${{ secrets.GITHUB_TOKEN }}` for GHCR auth + OIDC for cosign;
no manually-managed secrets). `permissions:` block is explicit and scoped
(`packages: write`, `contents: write`, `id-token: write` — nothing else).

## Out-of-scope

- **Native-image build / Mandrel 25 digest pin.** Out of scope for this
  feature (plan.md "the JVM build is what this feature exercises"). Native
  image lands with a later feature; its digest pin follows the same T081
  mechanism at that feature's release.
- **Multi-arch builds beyond amd64/arm64.** The current Dockerfiles are
  amd64/arm64 via the base images' multi-arch indices. Adding riscv64/s390x
  etc. is a later release concern.
- **Docker Hub mirror.** Single-registry (GHCR) for v1; a Docker Hub mirror
  for discoverability is a later release concern.
- **LAN/VPS profile release workflows.** Those profiles ship as separate
  feature specs; each will need its own release.yml trigger condition +
  threat-model-specific signing/pinning review.
- **T018's arch-spec text amendment.** T081 produces the *values*; T018
  propagates them into `specs/000-architecture/spec.md` §7 and §715-716. T018
  is a separate (already-existing) ticket.

## Notes

- **Why `compose/docker-compose.release.yml` is a generated artifact, not an
  edit-in-place of `docker-compose.local.yml`:** the `local` file is the
  build-from-source development surface — `tests/contract/compose/local_compose_test.sh`
  (T015) asserts `build:` directives exist for the three Stargate services.
  In-place rewrite would break that test on the release branch. Generating a
  sibling file keeps `local` green at PR cadence and `release` green at tag
  cadence; the two never share assertions.
- **Why GHCR not Docker Hub:** (a) GitHub OIDC → GHCR auth is native
  (keyless); (b) single-registry audit trail; (c) no Docker Hub rate limits
  for unauthenticated pulls of release artefacts (GHCR serves unauthenticated
  for public packages); (d) Constitution VI (auditable) — GHCR is bound to
  the same GitHub audit log as the workflow that pushed it.
- **Why cosign keyless not key-based:** Principle VI (auditable) + the
  no-secrets-in-CI stance. A long-lived cosign key in GitHub Secrets is a
  theft target and an audit gap; keyless OIDC binds signature identity to
  the workflow run, which is in the rekor transparency log forever.
- **Surfaced by:** T015 §Analysis R1 (commit `9c8e650`); redteam finding
  follow-up; release-blocker per FR-015 literal text.
