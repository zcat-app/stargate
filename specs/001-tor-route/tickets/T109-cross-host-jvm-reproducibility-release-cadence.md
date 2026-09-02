---
id: T109
title: 'Cross-host JVM reproducibility assertion at release cadence'
status: pending
created: 2026-09-02
last_updated: 2026-09-02
source: T098 review rounds 1+2 RECOMMENDED-FOLLOW-UP (carried)
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T098, T108]
parallel: true
files_budget: 6
privacy_critical: false
complexity: medium
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §12.2
decision_refs: []
constitution_refs:
  - "VI: Open and auditable"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T109: Cross-host JVM reproducibility assertion at release cadence

## Context

`tests/reproducibility/jvm_test.sh` (T098) builds twice on the **same**
host: it proves mtime-independence, but cannot see JDK-vendor, libc,
build-user, or host-path variance. arch §12.2: "Concrete JDK
distribution (Temurin / Liberica / Zulu / Corretto) is interchangeable
for bytecode reproducibility; the CI build pins one for the release
artefact" plus a CI matrix lock. The Constitution VI tier claim — "JVM
bytecode = byte-reproducible" — is a cross-host claim; today's gate
asserts it same-host only. T081 (release.yml, GHCR push) is the natural
wiring point and is itself unblocked (T098/T099/T076 all done). Flagged
at T098's round-1 review and carried through round 2 (2026-09-02).

## Acceptance

1. At release cadence (opt-in via `STARGATE_VERIFY_REPRO=1` and/or
   wired into T081's release workflow), a second clean JVM build runs
   inside a container with a **different JDK distribution** (and
   non-root user, different base libc), and the shipped jars plus the
   fast-jar outputs compare byte-for-byte against the host build —
   masking only variance documented in BUILD-DIFFS.md (none is expected
   for the JVM tier today).
2. Absent a container runtime, the gate records SKIP via T108's
   convention — never PASS.
3. Any observed cross-host variance is either fixed (if it violates
   the byte-reproducible tier) or documented in BUILD-DIFFS.md with its
   mechanism. Toolchain metadata (`Created-By`, `Build-Jdk-Spec`) must
   not vary between distributions; if it does, that is a defect to fix,
   not variance to document.
4. The same-host `jvm_test.sh` gate and `scripts/verify.sh` stay green.

## Out-of-scope

Native-image cross-host reproducibility (Constitution Principle VI
best-effort tier). Extension-zip cross-zip-version variance (T097
round-1 follow-up note — a BUILD-DIFFS one-liner that may ride along
with T081's release docs, not this ticket's gate).
