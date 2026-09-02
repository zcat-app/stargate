---
id: T098
title: 'Make the JVM build reproducible and verify Maven'
status: done
created: 2026-07-11
last_updated: 2026-09-02
source: review/sol-review.md#M7
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T003]
parallel: true
files_budget: 6
privacy_critical: false
constitution_refs:
  - "VI: Open and auditable"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - .specify/memory/constitution.md §VI
  - specs/000-architecture/spec.md §12.2
decision_refs: []
remediates: T003
reviews: { round: 2, date: 2026-09-02, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T098: Make the JVM build reproducible and verify Maven

## Context

The parent POM does not set a deterministic build timestamp or reproducible
archive mechanism, and the Maven wrapper download lacks a checksum.

## Acceptance

1. Add a two-clean-build test that changes source mtimes and compares the JVM
   artifacts byte-for-byte.
2. Configure `project.build.outputTimestamp` and the required reproducible
   Maven/JAR settings in the parent reactor without weakening tests.
3. Add the authoritative SHA-256 for the pinned Maven 3.9.14 distribution to
   `maven-wrapper.properties`; a wrong download must fail closed.
4. Document any unavoidable native-image-only variation in `BUILD-DIFFS.md`;
   JVM bytecode itself must compare equal.
5. The reproducibility test, Maven verify, and `scripts/verify.sh` pass.

## Out-of-scope

Mandrel native-image reproducibility beyond the Constitution's best-effort
tier.
