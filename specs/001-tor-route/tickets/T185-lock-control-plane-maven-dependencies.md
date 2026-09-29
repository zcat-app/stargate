---
id: T185
title: 'Lock control-plane Maven dependency identities'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 3 M2, survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 6
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
reviews: {}
overrides: []
aborted_attempts: []
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
2. Red before green: a docker-cadence or hermetic test tampers one artifact in
   a local repository and the build fails before compilation.
3. Document the refresh procedure. If the maintainer instead accepts HTTPS plus
   Maven Central immutability, that is an explicit `SECURITY-DECISIONS.md`
   entry, not an implicit default; Principle IV's wording must allow it.

## Out-of-scope

Moving the CP to native image; CI toolchain pinning (T191).
