---
id: "T225"
title: "Establish the shared Go qualification admission component"
status: "pending"
created: "2026-10-16"
last_updated: "2026-10-16"
source: "tasks.md#T225"
phase: "Qualification reconciliation"
story: "-"
blocked_by:
  - "T224"
parallel: false
files_budget: 18
files_scope:
  - "go.work"
  - "go.work.sum"
  - "tests/dockerowner/go.mod"
  - "tests/dockerowner/go.sum"
  - "tests/dockerowner/*.go"
  - "tests/dockerowner/cmd/docker-owner/*.go"
  - "tests/contract/go.mod"
  - "tests/integration/go.mod"
  - "specs/001-tor-route/tickets/T225-establish-shared-qualification-admission.md"
  - "specs/001-tor-route/evidence/T225-tests-first.json"
  - "specs/001-tor-route/evidence/T225-admission-schema.md"
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

# T225: Establish the shared Go qualification admission component

## Context

Deliver the canonical Go state component/public command needed by T218/T223 and T215. Reuse the
module placement already planned by T215, tests/dockerowner, so the graph has one shared public
API and no competing Go internal-boundary workaround or second canonical ledger. Private T218
reservation code is an unapproved fixture starting point, not integrated or adopted source.
T223 retains native integration; T225 owns no Docker/host-policy effect or cleanup lifecycle.

## Analysis

- Must hold: one enduring conflict domain, durable pre-effect admission, single-use candidates,
  exact manual predecessor completion, fixed deadlines and monotonic cumulative capacity.
- Gated: public Go API and actual command roles using authority-pinned private fixtures.
- Residue: filesystem quota/durability/platform/native effects remain separate T227/T220 gates.

## Acceptance

1. Root defines closed bootstrap/authorize/claim/phase/settle/manual-carrier schemas, exact operation
   identities, permitted fields, byte/file/inode/temporary maxima and overflow-safe sums before
   related source tests. No implementation begins from an empty schema or unexplained constant.
2. Establish real executable consumers in the shared Go package/command using private fixture
   authority before later safety regressions. Missing module/API/build is setup, never behavioral
   RED. No source function executes Docker, creates runtime effects or claims native eligibility.
3. Bind pinned canonical roots/enrollment/stable no-follow lock to the actual host/runtime/policy/
   UID overlap, independent of checkout, environment, candidate or boot change. Overlapping scopes
   cannot obtain separate gates. Read latest authority/state under lock; uncertainty refuses.
4. One authorization and one effectful attempt per immutable candidate; pending must be durable
   before an effect token is returned. Phase transfer requires exact prior completion, same
   original deadline and incoming owner identity. Only the current phase owner settles effects;
   no root/Python observer direct replacement, second gate, lease-expiry or cleanup takeover.
5. Require explicit bounded native/fixture-separated manual input for completed bootstrap/writer
   and later-candidate predecessor observation. Preserve immediate historical source/authority/
   directory/proof identities; no old-PID or visible-file success inference. Same-candidate retry
   and authority revisions refuse. Provisional settled bytes plus failed original command remain
   ineligible; source fixtures emulate honest external decisions and never authenticate humans.
6. Precharge all producer/writer/observer/temp byte/file/inode envelopes cumulatively before
   dispatch; preserve immutable history and exact evidence outside disposable workspace. No
   refund, deletion, fresh-root reset, unbounded scan or automatic torn-state repair. Capacity
   exhaustion refuses before effects without an arbitrary attempt-count ceiling.
7. Controlled real-command tests cover stale/concurrent admission, post-publication failure,
   state/path/mode/directory substitution, crash/owner loss, quota overflow/exhaustion, pending
   blocking across checkout/candidate, and a healthy next-candidate handoff. They prove software
   decisions only; real filesystem durability/hard quota is not inferred from fakes.
8. Deliver the public module and prepared command plus reviewed source/evidence. Both integration
   and contract modules can consume the public API without crossing internal package rules.
   The command is the prepared record-operation role, not another supervisor; Go readiness uses
   the same functions directly. T215 consumes this implementation rather than recreating it.
9. All new source follows genuine per-slice RED/identical GREEN and exact independent review.
   Carry parent T223/T218 failures and closed-episode restrictions: this child is no fresh review
   allowance. Source delivery cannot mark T218/T220/native/platform work complete.

## Out-of-scope

Docker/host/network effects, runtime cleanup, automatic human attestation/recovery, backend joins,
source release-verifier changes, relaxed native caps and live filesystem qualification.

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
