---
id: T109
title: 'Cross-host JVM reproducibility assertion at release cadence'
status: deferred
created: 2026-09-02
last_updated: 2026-10-10
source: T098 review rounds 1+2 RECOMMENDED-FOLLOW-UP (carried)
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T098", "T108", "T155", "T156", "T217"]
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
deferred_on: T217
deferred_reason: blocked-on-new-ticket
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

## Implementation checkpoint (2026-10-10)

The cross-host comparator candidate and factual failure record are preserved
in Git stash object `2e46d1f09732a538e36ebb2608e64c6ea8878653` while T109 is
deferred; it has not been committed or discarded. The candidate's focused
shell syntax, ShellCheck, ticket-lint, and diff checks passed. The approved
cross-host comparison used identical source snapshot
`eea3aef105d442f45738c04ee2b1014a58aada5480cde8c8f2e2d9b4cbab9c5e` on
Ubuntu OpenJDK 25/glibc 2.39/uid 1002 and Azul Zulu 25 on Debian 13/glibc
2.41/uid 1002. It failed exact equality for three shipped fast-jar outputs
and one target-tree metadata file. Manifest `Created-By` and `Build-Jdk-Spec`
matched, their negative controls failed closed, and Docker absence recorded
SKIP. No whole `scripts/verify.sh` or unrelated suite was run, per the
maintainer's affected-part-only instruction.

The bounded source audit compared exact release tags Quarkus 3.33.4
(Hibernate ORM 7.2.25.Final, Byte Buddy 1.17.8) and Quarkus 3.40.1
(Hibernate ORM 7.4.9.Final, Byte Buddy 1.18.8). The 3.33.4 tag retains the
random Hibernate proxy suffix, process-global recorder proxy-key counter,
and unsorted config class generation. The 3.40.1 tag contains the fixed
Hibernate suffix (HHH-20256), Quarkus's Byte Buddy reproducibility property,
per-recorder proxy-key IDs, and sorted config generation. Its
`AbstractFastJarBuilder` still sorts transformed inputs by absolute paths;
its `SerializedApplication` still writes insertion order. The 3.40.1 tag is
outside the architecture's current 3.33 LTS contract. The captured generated
jar also differed in gRPC interceptor order and Arc synthetic-bean constructor
parameter order; those two producers' 3.40.1 behavior remains to be verified
inside T217 before a remedy is selected. Neither audited tag fixes the complete
shipped-output set, so no upgrade build was run.

T217 is the producer-repair prerequisite. Astra approved its revised plan and
ticket draft, with a second Astra review required for the concrete mechanism-
to-fix proposal before producer edits. T109 remains deferred and must not be
marked done until its exact-byte cross-host comparison passes after T217.

## Out-of-scope

Native-image cross-host reproducibility (Constitution Principle VI
best-effort tier). Extension-zip cross-zip-version variance (T097
round-1 follow-up note — a BUILD-DIFFS one-liner that may ride along
with T081's release docs, not this ticket's gate).
