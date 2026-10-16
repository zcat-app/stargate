---
id: "T227"
title: "Qualify the finite artifact and runtime platform boundary"
status: "pending"
created: "2026-10-16"
last_updated: "2026-10-16"
source: "tasks.md#T227"
phase: "Qualification reconciliation"
story: "-"
blocked_by:
  - "T224"
parallel: false
files_budget: 6
files_scope:
  - "specs/001-tor-route/tickets/T227-qualify-artifact-runtime-platform-boundary.md"
  - "specs/001-tor-route/evidence/T227-platform-protocol.md"
  - "specs/001-tor-route/evidence/T227-platform-results.json"
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
decomposed_from: "T220"
---

# T227: Qualify the finite artifact and runtime platform boundary

## Context

Before dependent native caller integration, demonstrate the selected build/runtime authority,
artifact loading and runtime completion boundary using existing pinned tools and fixtures. This
is actual finite platform qualification, not a new harness/benchmark or proof the future internal
candidate consumer already works. The platform protocol does not depend on T225/T226/T223 code.
It supplies real prerequisites those tickets cannot fabricate with source fakes.

## Analysis

- Must hold: chosen venues have no build-to-runtime mutation channel, normal runtime operations
  are supported, and uncertain requests have an acceptable retained/quarantined disposition.
- Gated: exact existing-command protocol, observed identities/results and independent review.
- Residue: finite trials can falsify semantics but cannot prove a universal asynchronous join.

## Acceptance

1. Root authors one finite protocol before any command: actual already-authorized producer and
   runtime venues/identities, immutable existing representative archive/fixture/tool pins, exact
   command/operation/child/output/time/storage budgets, expected normal observations, ownership,
   retained evidence and acceptable quarantine/terminal disposition. No current host suitability
   or separation is assumed. Obtain separate specific native/host authority where required;
   generic ticket/doc authorization is not the first-policy-mutation or capture approval.
2. Use only existing tool/CLI entrypoints and representative immutable fixtures. No benchmark,
   new runner/adapter, Docker derivative, VM for convenience or hidden dependency on future
   project consumers. Record trusted experiment ownership/pending evidence under the approved
   platform-only protocol; do not claim it implements Q3's future shared source component.
3. Verify actual producer kernel/daemon/credential/input separation and absence of a writable
   runtime channel. A producer remaining active after handoff must be unable to mutate runtime.
   Same-daemon prebuild/private tags fail this check. Record archive/OCI/platform/config/load
   identities and real offline Compose/no-build/no-pull resolution, including the helper class.
4. Demonstrate normal acknowledged create/start/exec/stop/remove and exact ownership/baseline
   restoration for the representative workload. Identify the supported operation-specific
   completion predicate in pinned semantics and observed results. Generic history, CLI death,
   quiet inventory or image equality does not establish hidden-request settlement.
5. Before lost-response injection, require an approved isolated venue with acceptable quarantine
   OR a supported separately qualified terminal procedure. Do not strand the unqualified shared
   host. Record acknowledged-grant-before-owner-loss and missing-result outcomes as uncertain,
   retaining evidence/enforcement and blocking reuse. Stop/reboot/guest destruction remain
   unqualified until their exact effects are proven; deleting a disk alone is not stop proof.
6. Numerical fixture/tool/deadline and healthy representative timing observations are evidence
   only for those paths. Preserve all actual commands/failures/setup limits. Missing capability,
   failed controls or an unsupported predicate is NO-GO, not done/qualified and not another
   successor referral. Keep this ticket unresolved with the concrete failure; revise only the
   contradicted mechanism through review before dependent native/source integration proceeds.
7. Qualify actual storage enforcement/durability for admission state and retained evidence using
   existing tools and authorized isolated resources. Bind exact roots and retained-evidence
   locations to venue, mount/device/filesystem/options, relevant non-root/privileged writer access
   and tool identities. Demonstrate the selected mechanism's enforced byte/file/inode envelopes,
   including simultaneous temporary/replacement files; declared budgets or source counters alone
   do not pass. Record normal durable publication/replacement/readback controls and bounded
   exhaustion/refusal/write-failure controls, their exact supported storage semantics and honest
   durability limits. Do not infer universal power-loss survival or inject destructive faults on
   the shared host. Missing enforcement, unsupported semantics or uncertain durability is NO-GO.
   This platform fixture does not qualify future Go ordering or every project producer. T218/T220
   must match actual roots, access and complete producer/temp envelope to this evidence before
   admission; drift or an envelope outside the qualified limits refuses until specifically
   requalified. T225 retains software precharge/ordering tests; T212 retains full-cadence storage
   qualification. No future component is needed to run these existing-tool platform controls.
8. Save sanitized protocol/results with candidate/venue/tool/fixture identities and private raw
   evidence hashes; obtain independent correctness/adversarial approval. T227 completion does
   not certify T218 readiness, T220 full A2/A7, T034a/f, full T212 cadence/cache/drain, or source
   provenance of project artifacts. Those require their own actual consumers and measurements.

## Out-of-scope

Project implementation, new test/benchmark framework, broad source/cadence proof, automatic
recovery, shared-host response-loss fault, unrelated capture, unapproved host/VM operations.

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
