---
id: T185
title: 'Lock control-plane Maven dependency identities'
status: done
created: 2026-09-29
last_updated: 2026-10-01
source: "reviews/redteam-20260929-694dbd8.md (area 3 M2, survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 9   # maven.config, checksums lock, Dockerfile, pom.xml (plugin pin), lock test, THREAT-MODEL.md, ticket, STATUS.md, evidence; raised 6→8 then 8→9 by the maintainer on 2026-10-01 (see Notes)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted Updates"   # a version string is not verification
  - "VI: Open and Auditable"
complexity: high
risk: medium
round_cap: 3
spec_refs:
  - .specify/memory/constitution.md
decision_refs:
  - "T098/T145/T176 cover the Maven wrapper distribution only"
remediates: "T098"
reviews: { round: 1, date: 2026-10-01, verdict: APPROVE }
overrides: []
aborted_attempts: [{ date: 2026-10-01, round: 3, reason: "run-task --reset", history: target/runs/T185.review-history }]
reopens: []
redteam_findings: ["20260929-003-maven-deps-unlocked"]
clarity_check: {}
---

# T185: Lock control-plane Maven dependency identities

## Context

`control-plane/Dockerfile` runs `mvn -B -DskipTests package`, and every
`scripts/stargate init` rebuilds that image (`up -d --build`). Dependencies,
plugins and annotation processors (Quarkus platform, gRPC, sqlite-jdbc with its
native library, error-prone/nullaway) resolve from Maven Central by version
string only. Falsification (2026-09-29) ran `javap` on the local Maven 3.9.14
resolver: the default checksum policy is `warn`. No pom or `.mvn/` file declares
a lock, a checksum policy or signature verification. The wrapper hash pins
(T098/T145/T176) cover the Maven binary only, and the Docker build does not
use the wrapper.

## Analysis

- Must hold: every artifact the CP build resolves (dependencies, plugins,
  processors, transitive) is verified against a committed content hash before
  it executes, in both the Docker build and `scripts/verify.sh`.
- Gated: a tampered or unlisted artifact fails the build before compilation.
- Residue: lock refresh is a deliberate reviewed change (Principle IV).

## Acceptance

1. Commit a sha256 lock covering all resolved artifacts, including plugins and
   processors, and verify it before `package` in the Dockerfile and verify.sh.
   Mismatches and unlisted artifacts fail closed. Use strict checksums too.
   Platform coverage (refined 2026-10-01, maintainer-authorised, in response
   to astra's round-2 finding): the amd64 closure is build-confirmed; the
   arm64 lock entries are emulation-derived and not build-confirmed (no arm64
   builder; nested TCG emulation could not complete within the maintainer's
   time-box); a wrong arm64 entry fails that build closed. A regression
   detects a deleted or corrupted arm64 Brotli lock entry.
2. Red before green: a docker-cadence or hermetic test tampers one artifact in
   a local repository and the build fails before compilation.
3. Document the refresh procedure. If the maintainer instead accepts HTTPS plus
   Maven Central immutability, that is an explicit `SECURITY-DECISIONS.md`
   entry, not an implicit default; Principle IV's wording must allow it.

## Notes

Maintainer decisions (2026-10-01), recorded here as maintainer-authorised:

- **Lock, not HTTPS + Central immutability.** The maintainer chose a committed,
  verified lock. Accepting HTTPS plus Maven Central immutability was rejected
  because Principle IV would need an amendment. No `SECURITY-DECISIONS.md` entry
  is required for this choice.
- **Design: option 1, Maven Resolver trusted checksums + strict checksums.**
  `control-plane/.mvn/maven.config` enables the `summaryFile` trusted-checksums
  source (SHA-256, `failIfMissing`, basedir `${session.rootDirectory}/.mvn/checksums`)
  and the `trustedChecksums` artifact-resolver post-processor, plus
  `--strict-checksums`. Option 2 (an offline repository populated by a separate
  hash-checking script) was the fallback if any live check below failed. All four
  passed, so option 1 shipped. The live evidence (2026-10-01, scratch copies of the
  reactor) was:
  (a) Already-cached tampered artifacts are rejected with "trusted checksum mismatch".
  This covered the maven-compiler-plugin jar, the error_prone_core processor, the
  quarkus-bom import POM, the reproducible-build-maven-plugin POM and a Quarkus
  `-deployment` jar resolved by the Quarkus bootstrap resolver. Each one failed
  before the artifact executed, and the plugin and processor cases failed before
  any compilation.
  (b) Plugins, POMs, project `<build><extensions>` extensions and `.mvn/extensions.xml`
  core extensions are all covered: an unlisted extension fails, and a tampered one
  fails after recording.
  (c) An unlisted artifact fails with "Missing from summaryFile trusted checksum(s)".
  (d) Both pinned Mavens work. The wrapper runs 3.9.14 (resolver 1.9.27). The
  digest-pinned Docker builder image actually runs **3.9.15**. A fresh
  in-container download from Central matched every recorded hash, and tamper and
  unlisted cases fail there too.
- **Budget 6 → 8 with a plugin pin.** The maintainer approved 8 paths: the seven
  required paths plus `control-plane/pom.xml`. There, `io.smallrye:jandex-maven-plugin`
  is pinned in `pluginManagement` at 3.6.0, the version in the lock. Its version
  previously came from repository metadata, which the lock does not cover. A
  `-X` build shows it was the only plugin resolved that way. clean, resources
  and jar come from the pinned Maven's default lifecycle bindings.
- **Residues.** Remote SNAPSHOT artifacts are not verified: the post-processor's
  `snapshots=true` also checks the reactor's own modules and breaks the build
  (tested). Only Maven Central, which is release-only, is configured. Maven
  metadata is not content-locked, but every version it can select must still
  match the lock. The lock identifies content; it does not authenticate the
  publisher (no PGP check).
- **Evidence.** The lock was recorded twice from empty local repositories,
  with `--strict-checksums` against Central, using the refresh procedure in
  `control-plane/Dockerfile`. Both recordings were identical: 1218 entries.
  The enforcing `clean verify` passes. Tests-first red/green is in
  `specs/001-tor-route/evidence/T185-tests-first.json`. Live checks ran on the
  enforcing VM (logs gitignored under `target/runs/T185-vm/`):
  - `TestStackSmoke` passed (`green-run.log`): compose `--build` of the locked
    CP image, then the full stack.
  - A `--no-cache` builder-stage build (`cp-build-plain.log`) shows "Loaded
    1218 trusted checksums" under Maven 3.9.15.
  - Re-run on the round-2 candidate with the 1220-entry lock:
    `TestStackSmoke` passed again (`green-run.log`; the round-1 run is
    `green-run-r1.log`), and the `--no-cache` builder build loaded 1220
    trusted checksums and succeeded (`cp-build-plain.log`; round 1 is
    `cp-build-plain-r1.log`).
  - Changing one locked hash (`cp-build-wrong-hash.log`) fails the image build
    with a trusted checksum mismatch on a freshly downloaded error_prone_core,
    before compilation.
- **Round 1 REWORK, astra Major: arm64 closure.** Confirmed: brotli4j selects
  `native-linux-aarch64` through a Maven `<os>` profile, and the lock had only
  the x86_64 native. A full `clean verify` recorded with
  `MAVEN_OPTS=-Dos.arch=aarch64` (with protoc kept at the linux-x86_64
  classifier so it can run on this amd64 host) added exactly two entries: the
  brotli4j aarch64 jar and POM. All protoc and protoc-gen-grpc-java classifiers
  were already locked, and netty-epoll's classifier is fixed in quarkus-netty's
  POM. With the aarch64 profile active, the enforcing `package` passes and a
  tampered aarch64 native fails with a trusted checksum mismatch. The test now
  requires both platforms' entries for the arch-selected artifacts, and the
  Dockerfile refresh procedure has an arm64 step. Limit: this is
  profile-activation emulation on amd64. No arm64 builder or binfmt emulation
  exists here, so a real `--platform linux/arm64` image build is not
  build-confirmed.
- **Round 1 REWORK, astra Minor: THREAT-MODEL §5.9.** The maintainer
  approved raising the budget 8 → 9 for `THREAT-MODEL.md` (2026-10-01,
  maintainer-authorised). §5.9 now describes the Maven lock and its
  exclusions. In the maintainer's wording, the amd64 closure is
  build-confirmed, the arm64 entries come from profile-activation emulation
  and are not build-confirmed, and a wrong arm64 entry fails that build closed.
- **Round 1 glm Minor (optional), fixed at the maintainer's request, no budget
  cost.** The test's override tripwire now also catches `-s`/`--settings` and
  `-gs`/`--global-settings` on Maven invocation lines in the Dockerfile and
  verify.sh, because a settings file can carry resolver properties.
- **Round 2 REWORK, astra Major: arm64 build probe and corruption coverage.**
  The maintainer time-boxed an emulated arm64 image build to two hours
  (13:55–15:55 UTC). I installed qemu-user-static in the disposable guest and
  ran `docker buildx build --builder default --platform linux/arm64 --no-cache
  --target builder` there (`target/runs/T185-vm/cp-build-arm64.log`). The
  pinned image's arm64 variant started (aarch64, Maven 3.9.15). After about
  17 minutes under nested TCG + qemu-user emulation, Central closed the TLS
  handshake for the first artifact download ("Remote host terminated the
  handshake"). That is an emulation/tooling failure, not a lock mismatch: no
  trusted-checksum error was reached. Per the maintainer's decision this takes
  the refine path. Acceptance 1 now states the platform coverage above, and
  the round state was reset (`run-task.sh --reset`, history archived) for a
  fresh review. The test pins the two arm64-only brotli4j entries at their
  reviewed digests (`ARM64_ONLY`), because no amd64 gate resolves them.
  Checked: zeroing the jar digest in the lock fails the test.

## Out-of-scope

Moving the CP to native image; CI toolchain pinning (T191).
