---
id: T217
title: "Make shipped Quarkus artifacts byte-reproducible"
status: pending
created: 2026-10-10
last_updated: 2026-10-10
source: "T109 cross-host comparison 2026-10-10: shipped generated-bytecode.jar, transformed-bytecode.jar, and quarkus-application.dat differ across approved build environments"
phase: "6: Polish & Cross-Cutting Concerns"
story: "-"
blocked_by: []
parallel: false
files_budget: 18
privacy_critical: false
tests_first: []
test_for: []
constitution_refs:
  - "VI: Open and Auditable"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/000-architecture/spec.md §12.2"
decision_refs:
  - "specs/001-tor-route/tickets/T109-cross-host-jvm-reproducibility-release-cadence.md §Implementation checkpoint"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T217: Make shipped Quarkus artifacts byte-reproducible

## Context

T109's Ubuntu OpenJDK 25 versus Azul Zulu 25/Debian 13 comparison found byte differences in the shipped Quarkus `generated-bytecode.jar`, `transformed-bytecode.jar`, and `quarkus-application.dat`. Source inspection identified Hibernate/Byte Buddy proxy suffixes, Quarkus recorder/config generation order, absolute-path-dependent transformed-input sorting, and downstream serialized-index order; the captured output also varied in gRPC interceptor order and Arc synthetic-bean constructor-parameter order. Neither the latest Quarkus 3.33 maintenance candidate nor 3.40.1 fixes all observed causes, and 3.40.1 is outside the current Quarkus 3.33 LTS architecture contract. T109's cross-host gate must remain incomplete until this prerequisite preserves exact equality for shipped bytes.

## Analysis

- **Must hold:** every shipped JVM fast-jar output is byte-identical for the accepted build contract, with no output masking or undocumented variance; any enforced source/cache layout is actually used by the release workflow; build fixes preserve classpath precedence, proxy behavior, interceptor order, Arc injection, and archive/index associations.
- **Gated:** focused producer fixtures, behavior tests for changed generators/orderings, and T109's existing exact-byte comparison.
- **Residue:** other host/toolchain combinations beyond the accepted JDK vendor/libc/non-root dimensions are not claimed; any remaining path assumptions must be explicit in the build contract and release invocation.

## Acceptance

1. Add a checked-in mechanism-to-fix record for every T109 mismatch in shipped outputs, including the exact producer, dependency/tag, and repair. Specifically account for Hibernate cached-value suffixes; recorder/config-generated output; gRPC interceptor order; Arc synthetic-bean constructor-parameter order; transformed-bytecode archive order; and `quarkus-application.dat` index order. Confirm whether 3.40.1 fixes the captured gRPC and Arc differences before choosing any remedy. Do not repeat the broad release search without a concrete source lead.
2. Before changing producer behavior, submit the complete mechanism-to-fix proposal to Astra for review: exact dependency/tag and any local patch, path/cache contract and its enforcement, source/provenance, build procedure, focused tests, and final file scope. Implement only after that proposal is approved. A canonical source/Maven-cache layout is allowed only if tagged source evidence shows why it stabilizes the relevant ordering and the actual release build enforces that layout; layout alone cannot repair random generated names. A producer patch/backport must name its upstream source, exact dependency and local changes, provenance, build procedure, and maintenance boundary. If the complete remedy requires changing Quarkus beyond the current 3.33 LTS contract or exceeds the reviewed implementation/file budget, stop and submit the exact amendment or decomposed ticket proposal; do not silently alter the contract or begin an open-ended fork.
3. Add only focused regressions for the selected repair. Record red-before-green evidence before changing producer behavior. Group transformed archive and serialized-index ordering checks when they share the producer path. Add behavior checks only for changed proxy generation, interceptor precedence, Arc wiring, or classpath resolution. Do not add a second full-build comparator or normalize away bytes.
4. Preserve exact bytes for every shipped fast-jar file. The existing T109 comparator must pass for one complete pair of fresh JVM builds with different JDK vendor, libc and non-root identity. Use distinct absolute source/cache roots unless a reviewed, enforced canonical layout is the selected fix. Reuse this comparison evidence for T109 while the exact executable/toolchain source closure remains unchanged; rerun only when that closure changes.
5. Keep `quarkus-artifact.properties` out of the comparator only if source/consumer inspection confirms no release output consumes it; record that finding and the narrow exclusion in BUILD-DIFFS.md. Otherwise keep exact equality required.
6. Run only affected checks: the focused JVM producer/behavior checks, T109 comparison, and applicable syntax, ShellCheck, ticket-lint and diff checks. Do not run whole `scripts/verify.sh`, unrelated Go/extension suites, create a VM, or run live stack acceptance. Preserve command, source hash, toolchain identities, and comparison hashes with the ticket evidence.
7. Preserve the maintainer's GLM pause: do not launch GLM, commit T217, or mark it done while the pause remains. Once the pause is lifted, T217 requires matching GLM/Astra code review of the same candidate before commit. T109 remains deferred/incomplete until T217 is complete, then resumes with the exact-byte gate; do not mark T109 done merely because this ticket's harness detects or fixes defects.

## Out-of-scope

This ticket does not weaken Constitution VI, mask or whitelist shipped differences, change proxy runtime semantics, run VM/live-stack tests, or modify unrelated planes. It may edit T109's `tests/reproducibility/jvm_cross_host_test.sh` and `BUILD-DIFFS.md` only to enforce the reviewed source/cache layout or record a verified narrow exclusion for the unshipped `quarkus-artifact.properties`; exact byte comparison remains mandatory for every shipped output. Do not adopt Quarkus 3.40.1 without the required architecture reconciliation. Native-image best-effort reproducibility and extension ZIP variance remain out of scope.

## Notes

The current T109 candidate already contains the comparator and a factual failure record. Reuse those artifacts instead of writing duplicate integration infrastructure. Any chosen path-layout constraint must describe how ordinary release builds and the cross-host comparison apply the same layout, not just how one local experiment is arranged.

## Plan review

The implementation plan was reviewed by Astra and returned PROCEED after these constraints were added: a path layout cannot fix the Hibernate suffix by itself; any producer tests record red-before-green evidence; the T109 comparator is reused; and the review pause is preserved. The ticket's §Acceptance 2 is a second review checkpoint for the concrete remedy before producer edits; this plan approval does not approve an unspecified patch or out-of-contract dependency change.
