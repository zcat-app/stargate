---
id: "T226"
title: "Prepare and validate internal qualification artifacts"
status: "pending"
created: "2026-10-16"
last_updated: "2026-10-16"
source: "tasks.md#T226"
phase: "Qualification reconciliation"
story: "-"
blocked_by:
  - "T224"
parallel: false
files_budget: 14
files_scope:
  - "scripts/qualification-artifacts.py"
  - "scripts/release.py"
  - "tests/contract/workflow/qualification_artifacts_test.py"
  - "tests/contract/workflow/release_test.py"
  - "specs/001-tor-route/contracts/qualification-artifacts.md"
  - "specs/001-tor-route/tickets/T226-prepare-validate-internal-qualification-artifacts.md"
  - "specs/001-tor-route/evidence/T226-tests-first.json"
  - "specs/001-tor-route/evidence/T226-artifact-schema.md"
  - "specs/001-tor-route/STATUS.md"
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/design/qualification.md"
decision_refs:
  - "2026-10-16 reviewed qualification redesign and maintainer-authorized ticket reconciliation"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
decomposed_from: "T223"
---

# T226: Prepare and validate internal qualification artifacts

## Context

Deliver the internal candidate producer/validator and build-free topology transform consumed by
T223. This is a data/artifact boundary, not installer mutation or native load. The Sol6.1 offline
experiment disproved reuse of release image_map/verify-install unchanged: bare config IDs and
unsigned/internal release metadata refuse, and the four services omit a separately pulled helper.
Use existing release production/provenance/graph logic where justified; preserve signed releases.

## Analysis

- Must hold: trusted reviewed source-to-artifact production, finite complete closure and separate
  archive/OCI/platform/config/payload identities; no internal candidate masquerades as release.
- Gated: actual producer/validator/renderer entrypoints with controlled tools and hostile inputs.
- Residue: actual separate producer venue, image import/Compose behavior and runtime are T227/T220.

## Acceptance

1. Root specifies the closed data-only internal schema, source/dirty-overlay/mode policy, trusted
   production/observation anchor and exact finite artifact/size/member envelopes before source
   tests. Bind expected source before/after producer commands, toolchain/dependency/platform and
   payload/Go test-binary identities; a self-asserted hash list or VCS label is insufficient.
2. Establish the actual internal producer/validator CLI using controlled existing tool seams,
   then genuine behavior-specific RED before each new safety implementation. Preserve release
   rejection of unsigned/mismatched releases; never weaken it to manufacture an internal-mode RED.
3. Enumerate four services PLUS key/volume helpers, publisher/fixture/probe and A2 variant images,
   precompiled Go/probe binaries, Python/shell source/interpreters and all in-scope nested tooling.
   Missing/extra/oversized/foreign members, path traversal, symlinks/mode substitution, wrong
   platform/source/tool/payload/config mappings and shared-tag names refuse before consumption.
4. Distinguish archive SHA, OCI graph/platform manifest, image-config/Engine ID and shipped binary
   hashes. Validate the complete graph and trusted producer/source binding, not digest-prefix
   syntax. Keep a complete inventory and exact running-ID expectation for later import consumers.
5. Reuse only the bounded release topology transform with an internal image validator; preserve
   production security/networks/mounts/UIDs, remove builds and force no-build/no-pull. Verify
   existing signed release tests/identity/signature/source/tag/clean-tree guards remain unchanged.
6. Export immutable runtime-controlled inputs and exact selected candidate identity for T223;
   actual import/native init/admission ownership belongs there. No build/pull/compile/load is
   performed by this validator on the runtime venue. Producer work has no runtime credentials,
   policy or writable input channel; source fakes cannot qualify actual separation.
7. Execute focused actual-entrypoint controls for source/artifact mismatch, corrupt graph, wrong
   image namespace, incomplete helpers, topology drift and release/candidate confusion. Fixture
   parser/crypto results are labelled simulated; only T227 qualifies actual load/Compose syntax.
8. Deliver independently reviewed source/schema/evidence, then T223 integrates real mutating
   callers. This ticket can complete a working pure artifact consumer without requiring the
   future installer adapter, avoiding a circular establishment prerequisite.

## Out-of-scope

Installer/host mutations, actual Docker/native/load/pull/build/network qualification, pretending
internal metadata is a signed release, unrelated topology/version changes and benchmarks.

## Execution and evidence boundary

This is a ticket reconciliation, not authorization to execute source or native work. Root authors
and independently reviews the exact implementation/experiment plan before dispatch. New code is
spec-derived tests-first through real supported consumers: preserve genuine behavioral RED before
implementation, identical GREEN afterward and affected regressions. Missing tool/import/API/build,
invalid setup and a refusal stub are not the missing safety property's RED or healthy PASS.
Retain every original candidate, verdict, actual review/episode count and NONCOMPLIANT chronology;
new child IDs do not reset parent failures. Pure document work uses consistency/adversarial review.
No automatic native/host authority, shared-tag repair, evidence deletion, VM for convenience or
T078/T079 execution follows. Apply the applicable ticket review matrix and explicit session
exceptions honestly; advisory plan approval is not the paired implementation/delivery gate.
