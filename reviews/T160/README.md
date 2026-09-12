# T160 Tor security-upgrade evidence

This ticket prepares the Tor 0.4.9.12 candidate requested by the maintainer after the
[2026-09-08 security announcement](https://forum.torproject.org/t/security-release-0-4-9-12/22096).
It does not deploy or publish an image. T161 remains the mandatory live-validation promotion
blocker; T155 and the final milestone reviews remain required.

## Candidate and review

Final source snapshot: `5494521621dccc84d55ca179ad81e51e10816d23015b9dc6b6f6f738337c4130`.
The 19 intended source paths were staged, with worktree/index contents matched before review.
[Source snapshots](source-snapshots.json) retains both rounds' exact serialized manifests and
scoped diffs, including new files. [Evidence](evidence.json) retains signed primary metadata,
tests-first source/failure records, command/results and raw-artifact hashes.

Reviewer verdicts are copied verbatim. Round 1 codereview approved; independent redteam required
dependency-source exclusion and correction of a stale threat-model statement. Round 2 review
records are added after the reviewers write them. The scope budget includes 19 source paths,
seven review/evidence outputs and two paths for the original finding's later closure move (28).

Reviewers are separate fresh-context Codex agents, described by their sessions as GPT-6 based;
the precise backend revision is not exposed. These are AI reviews in one tool environment,
not the external human review required before release. Neither reviewer delegates or reads the
other reviewer's verdict/rationale. SECURITY-DECISIONS is hash-checked only by blind reviewers;
the root checks preservation of its committed history.

## Implemented protection and checks

- Authenticate official metadata and pin actual amd64/arm64 Tor package hashes independently.
- Fetch and hash-check Tor before installation. Resolve dependencies with only the immutable
  Debian snapshot enabled, then install from the private cache with downloads prohibited.
- Preserve the failing substitution/refetch/dependency regressions. Real offline APT selection
  rejects higher-/same-version dependency substitution; no inert fixture package is executed.
- Build the native image; check Tor/package version, UID 5103, configuration and helper removal.
  A real wrong-hash build fails before Tor is unpacked. Two final-source cold builds produce
  identical 96-package manifests. This does not claim final-image byte equality.
- Full candidate verification: **21 PASS / 1 release-reproducibility SKIP / 0 FAIL**. The native
  Tor two-build comparison ran separately. Required entrypoints/workspace coverage and all 193
  ticket dependencies were independently inventoried while T139 remains pending.

Round-2 local image config ID:
`sha256:dacab54a7e44b046538eea7e0da1559daf5b2bd2df9a1c7d10d9a4d8c0a9ebae`.
This identifies a local build, not a published multi-architecture manifest. Arm64 package
provenance and installer fixtures were checked; native arm64 execution was not performed.

## Live evidence and remaining work

Round-1 T032 configuration, T062 control and T058a username-less/calibration probes passed.
Two cold T058 runs failed before circuit-comparison evidence (bootstrap/CONNECT timeouts).
Those failures remain recorded; they establish neither an isolation leak nor a root cause.
Round 2 changes build source selection only: all installed package versions and sampled
Tor/libevent/libssl/libcrypto/config hashes match round 1. This is not an additional live run
or a whole-rootfs comparison. T161 must resolve the required evidence before promotion.

After reviewed T160 delivery, the recommended queue is **T139 → T161 → T135 → T137 → T136**,
then the boundary designs and remaining foundation repairs in
[the implementation plan](../../specs/001-tor-route/remaining-implementation-plan.md).
T155 precedes remaining feature work; T078/T079 and applicable external human review follow.

## Delivery

The focused source commit and subsequent lifecycle bookkeeping are recorded after delivery.
Lifecycle and reviewer artifacts are outputs; they do not change the approved source snapshot.
