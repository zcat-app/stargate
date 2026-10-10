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

The cross-host comparator candidate is preserved in Git stash object
`2e46d1f09732a538e36ebb2608e64c6ea8878653`; T217 restored only
`tests/reproducibility/jvm_cross_host_test.sh` from its third parent and did
not apply or pop the stash. The fresh producer red is bound to T217 start SHA
`bfa96dd14792ff4f6775cd7a66a3f8d593d4aa5d`, source-manifest SHA
`eea3aef105d442f45738c04ee2b1014a58aada5480cde8c8f2e2d9b4cbab9c5e`, and
comparator SHA-256
`c1b2aa29ce2accaf5a9f5f723a4770b2e68a8517b71fada8f33801dd23f0c7df`. Both
fresh builds completed: host Ubuntu OpenJDK 25/glibc 2.39 and container Azul
Zulu 25/Debian 13/glibc 2.41 under uid 1002. The comparator found four
differences: three shipped outputs (`generated-bytecode.jar`,
`transformed-bytecode.jar`, and `quarkus-application.dat`) plus
`quarkus-artifact.properties`, which is outside the release Dockerfile's
copied fast-jar tree. JAR `Created-By` and `Build-Jdk-Spec` matched. The
recorded comparator output preserves the exact hashes. A first probe could
not bootstrap because the wrapper requires `unzip`; the valid red used an
invocation-scoped Python `zipfile` shim with Unix mode restoration (SHA-256
`50fda85b89f4205c45d99f664791abc85192ab4f1bb89a34f695a0cab47fffe1`) and
then reached both builds. The invalid attempt remains under the evidence
record's `superseded` field and is not counted as producer evidence. No VM,
whole `scripts/verify.sh`, or unrelated suite was run.

The bounded source audit compared the exact Quarkus release tags `3.33.4`
and `3.40.1` (tag commit `6ce99878508d792f3c2a2a7f9520b086a1c32cab`), plus
the Hibernate ORM tags `7.2.25` and `7.4.9` (tag commit
`208bf6c64920d90a24cda739e3db46093b3962aa`). The producer findings and fixes
are:

| Shipped difference | Producer in the promoted source closure | Fix or remaining constraint |
|---|---|---|
| Hibernate cached-value / proxy suffix | Hibernate ORM `hibernate-core/src/main/java/org/hibernate/bytecode/internal/bytebuddy/ByteBuddyState.java#ByteBuddyState(ClassFileVersion)` | Quarkus 3.40.1's managed Hibernate ORM 7.4.9 adds `Implementation.Context.Default.Factory.WithFixedSuffix("hibernate")` to Byte Buddy. Hibernate 7.2.25 lacks the fixed suffix. This stabilizes Byte Buddy's generated cached accessors/field values; it is not repaired by changing source paths. |
| Recorder-generated proxy keys and recorder-value order | Quarkus `core/deployment/src/main/java/io/quarkus/deployment/recording/BytecodeRecorderImpl.java#getProxyInstance` and `createValue`; `classProxy(String)`'s independent class-name suffix remains a process-global build-time counter | The 3.40.1 recorder gives proxy keys a build-step class name plus an instance-local counter, and sorts existing recorder values by class name before serialization/preparation. The static suffix is for temporary generated class names and does not affect output bytes. |
| Config-generated classes | Quarkus `core/deployment/src/main/java/io/quarkus/deployment/steps/ConfigGenerationBuildStep.java#generateBuilders` | The 3.40.1 method uses sorted maps/sets for defaults, config mappings, and discovered service implementation names before generated class emission. |
| gRPC global interceptor order | Quarkus `extensions/grpc/deployment/src/main/java/io/quarkus/grpc/deployment/GrpcServerProcessor.java#gatherGrpcInterceptors` | The 3.40.1 method sorts discovered global interceptor names and additional interceptor build items, and uses insertion-ordered maps/sets for registered and per-client interceptors. The extracted recorder bytecode assertion checks the ordered global values `GrpcDuplicatedContextGrpcInterceptor`, `GrpcRequestContextGrpcInterceptor`, then `ExceptionInterceptor`. |
| Arc inactive-bean message fragments | Quarkus `independent-projects/arc/processor/src/main/java/io/quarkus/arc/processor/BeanGenerator.java#checkActiveMethod` | The 3.40.1 generator maps matching injection points to target-info strings and sorts them before emitting the message. The assertion checks the AuditLogService fragment before SqliteTokenState. The generated constructor descriptor matched in the original comparison; constructor-parameter order was not the mismatch. |
| Transformed archive and serialized index | Quarkus `core/deployment/src/main/java/io/quarkus/deployment/pkg/jar/AbstractFastJarBuilder.java#build`; `core/deployment/src/main/java/io/quarkus/deployment/pkg/jar/FastJarBuilder.java#writeSerializedApplication`; bootstrap runner `independent-projects/bootstrap/runner/src/main/java/io/quarkus/bootstrap/runner/SerializedApplication.java#write` | The producer sorts transformed entries by `Path.toString()` (absolute input paths), then embeds them in `transformed-bytecode.jar`. `AbstractFastJarBuilder#build` supplies transformed, generated, runner, then sorted dependency paths to `SerializedApplication#write`, which serializes that list in order and derives classpath indexes from it. Quarkus 3.40.1 retains absolute-path sorting and insertion-order serialization; the fix is the enforced `.m2` and module-path layout, with `/src` projection checked against the actual release Dockerfile's flattened module paths. |

The 3.40.1 BOM also upgrades Byte Buddy from 1.17.8 to 1.18.8. Its
Hibernate producer fix, recorder/config ordering, gRPC ordering and Arc
message ordering are dependency fixes; only the transformed archive/index
ordering depends on the relative source/cache path contract. The gRPC and Arc
assertions inspect the outputs of the same host/container comparison builds.
T217 records a valid red against its start source closure and a post-promotion
comparison; the invalid missing-`unzip` attempt is superseded and is not red
evidence. T109 itself remains deferred and incomplete until T217's approved
exact-byte gate and independent code-review gate land.

T217's plan amendment received Astra **PROCEED** on the 23-path union,
including the `CLAUDE.md` version-line correction. This is plan authorization
only, not approval of the implementation candidate. T109 remains deferred and
must not be marked done as a result of this source audit or T217's harness.

## Out-of-scope

Native-image cross-host reproducibility (Constitution Principle VI
best-effort tier). Extension-zip cross-zip-version variance (T097
round-1 follow-up note — a BUILD-DIFFS one-liner that may ride along
with T081's release docs, not this ticket's gate).
