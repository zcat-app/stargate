---
id: T223
title: "Integrate prepared-artifact callers and privileged intent transport"
status: deferred
created: 2026-10-15
last_updated: 2026-10-16
source: tasks.md#T223
phase: "Foundation audit remediation"
story: ''
blocked_by:
  - "T224"
  - "T222"
  - "T225"
  - "T226"
  - "T227"
  - "T209"
parallel: false
files_budget: 34
files_scope:
  - "scripts/lib/compose.sh"
  - "scripts/subcommands/init"
  - "scripts/t209-native-live.sh"
  - "tests/contract/internal/compose/compose.go"
  - "tests/contract/internal/compose/compose_test.go"
  - "tests/contract/stargate-cli/t162_enforcement_test.sh"
  - "tests/contract/stargate-cli/t209_native_launcher_test.sh"
  - "tests/contract/stargate-cli/init_docker_test.sh"
  - "tests/contract/stargate-cli/release_init_test.sh"
  - "tests/contract/tor/port_exposure_test.go"
  - "tests/live-e2e/local-topology/native_coordinator.py"
  - "tests/live-e2e/local-topology/native_supervisor.py"
  - "tests/live-e2e/local-topology/observer.py"
  - "tests/live-e2e/local-topology/run.py"
  - "tests/live-e2e/local-topology/test_native_coordinator.py"
  - "tests/live-e2e/local-topology/test_observer.py"
  - "tests/live-e2e/local-topology/test_run.py"
  - "tests/live-e2e/local-topology/test_t220_build_binding.py"
  - "tests/dockerowner/dispatch.go"
  - "tests/dockerowner/dispatch_test.go"
  - "tests/dockerowner/cmd/docker-owner/main.go"
  - "tests/dockerowner/cmd/docker-owner/main_test.go"
  - "tests/integration/egress_observer_test.go"
  - "tests/integration/egress_consensus_test.go"
  - "tests/integration/route_down_stack_test.go"
  - "specs/001-tor-route/tickets/T223-rebuild-t220-native-effect-ownership-source.md"
  - "specs/001-tor-route/evidence/T223-tests-first.json"
  - "specs/001-tor-route/evidence/T223-consumer-map.md"
  - "specs/001-tor-route/STATUS.md"
out_of_scope:
  - data-plane/**
  - control-plane/**
  - production AppArmor profile or owner-rule changes
  - changing T209 A7 or any T220 acceptance criterion
  - host-policy mutation, Docker/native/backend qualification, network access, or live A7
  - VM creation or replacement of the existing backend
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Independent Review and Adversarial Discipline"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/design/qualification.md"
decision_refs:
  - "T220 fourth full-source whole-model reassessment, 2026-10-15"
  - "T220 acceptance 1-8 and strict T209 A7; unchanged"
  - "T222 accepted historical chronology disposition; no future tests-first exception"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
decomposed_from: T220
deferred_on: T224
deferred_reason: spec-amend
---

# T223: Integrate prepared-artifact callers and privileged intent transport

## Context and retired direction

The fourth failed T220 full-source review and all subsequent T223 rejections remain historical.
Abandon the old in-window BuildKit global-join/rebuild target as a qualification mechanism; do not
claim it passed. T225 delivers shared admission and T226 artifact production/validation. T227 must
establish the actual platform path before this dependent integration. T209 supplies final source
hardening. This ticket integrates the native callers and bounded privileged dispatch using those
components, not another backend derivative or a fresh review counter.

## Analysis

- Must hold: every actual native mutation has durable operation intent before dispatch, with
  one canonical admission domain and no in-window build/pull/compile/import fallback.
- Gated: actual entrypoints under controlled external tools, peer/phase/ACK loss and output tests.
- Residue: source fakes do not qualify the daemon, host policy, actual capture or healthy timing.

## Acceptance

1. Root first binds the exact current-candidate path/operation census and finite schemas, channel
   envelopes, deadlines and output/files budget to the implementation plan. Reuse only individually
   inspected private source; neither T222 nor this new split approves old source defects. Preserve
   all parent/child review and episode counts; obtain a bounded successor source authority before
   reopening the closed T223 episode. This ticket remains deferred until explicit reopen.
2. Integrate T225's sole Go admission mutator and T226's validated candidate at the real init,
   Compose/Go, native coordinator/supervisor, observer, T162 and A2 callers. Canonical pending
   precedes import/any effect; per-run ledgers are subordinate evidence. No independent T220 gate.
   Before/after load and each container generation match archive/OCI/config/payload/source pins.
3. Implement DQ2a's synchronous private Unix request/ACK in the existing current non-root owner:
   exact candidate/phase/peer PID-start/operation/input/deadline binding, durable intent/readback
   before one-operation ACK, bounded result/uncertainty recording. Replace root direct ledger
   writes and fchown/replace access. No arbitrary-command broker or new supervisor/daemon.
   An already-ACKed operation may arrive after owner loss; retain its uncertainty/enforcement.
4. Source controls trace nested init and full T162 request->commit->ACK->dispatch->result at the
   actual callers, including peer/phase substitution, commit/readback failure, ACK/result loss,
   root replacement, owner death and later-generation ID mismatch. Healthy controlled tools must
   reach ordinary successful execution. A worker-start receipt or final result alone is insufficient.
5. Remove all native-window builds/pulls/compiles from actual init/key/volume helpers, observer,
   recovery, Tor caller matrix, T162/A2 and reachable nested paths. Include precompiled probes and
   A2 artifacts. Update exact --build command classifiers with launchers, not an outer wrapper
   alone. An unsupported caller refuses before dispatch; no hidden source-mode fallback.
6. Preserve ordinary source/release behavior and signed release verification. Source/install and
   cadence tests remain separately owned. T218 owns its final readiness consumer/witness wiring
   after the common source capability; test common Go phase/dispatch through its actual executable
   controlled-fixture role, without claiming the absent readiness registration already executed.
7. Connect exact owned cleanup to acknowledged/qualified request predicates; unknown requests,
   torn state and lost owner/observer outcomes remain admission-blocking. Private images/caches
   are reported; no shared-tag overwrite/prune or inventory-only recovery. Provisional settled
   bytes plus failed original command cannot permit the next manual handoff.
8. Preserve named Go terminal PASS parsing, separate A2-live versus full T162 receipts, complete
   scenario/cleanup/observer result conjunction and source-plus-receipt publication. Tests use
   real validators with controlled external effects; they cannot forge native terminal receipts.
9. Genuine current-prefix RED then identical GREEN and affected regressions cover every corrective
   source slice. Exact independent whole-candidate source review precedes integration. Deliver a
   durable consumer/ownership map, including every changed actual entrypoint and explicitly omitted
   source-cadence caller. T223 completion is source delivery only, never T220/T218 native PASS.

## Out-of-scope

Actual Docker/network/host-policy qualification, production DP/CP/profile/owner rules, VM creation,
BuildKit forks, global join claims and T034f scenario/consensus acceptance. T227 owns bounded
platform evidence; T220 owns full native A2-live/A7. No source/native authority is inferred here.

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

## Historical pre-reconciliation ticket body — preserved verbatim

The body below records the superseded direction and original evidence/approvals. Active acceptance
and scope above govern new work. Historical approvals do not approve changed source or reset counts.


# T223: Rebuild T220 native effect ownership at real writer paths

## Context

T220's fourth full-source review found that the current candidate does not
implement a complete writer-to-ledger-to-finalizer protocol. This child owns
the source-level rebuild as one coherent effect-ownership boundary, rather
than one ticket per reviewer finding. The existing T220 candidate, every
failed review, and all historical tests-first records remain preserved and
unapproved. This ticket does not reset or relabel that evidence.

Root authors the exact implementation plan from the current source before
dispatch. The implementer is Luna 6/high. Fresh Astra/high and Luna 6/high
review the same exact candidate independently. Only affected-part tests run.
The established backend refusal remains in force throughout this source-only
ticket.

## Acceptance

1. Before each corrective source change, add a current-consumer falsifier for
   the exact broken property and run its genuine pre-fix selector. Bind the
   exact candidate bytes and command in `T223-tests-first.json`. A setup,
   import, fixture, backend-admission, or command-recorder failure is not RED.
   Preserve the original T220 evidence and counts unchanged.
2. Enumerate the actual writer and mutator callsites in the checked-in init,
   Compose, Go tests, Python observer, T162 harness and native run entrypoint.
   Every native mutation/effect either enters the bounded run coordinator with
   durable pre-effect ownership and exact completion/absence evidence, or
   refuses before dispatch. Read-only operations remain usable. Cover
   `exec`, `restart`, stop/recovery, helper and publisher creation, observer
   builds, volume setup, primary policy writes, probes and temporary files.
3. Use one image-effect schema that real build and Compose producers emit and
   cleanup precheck/finalizer consume. Bind private/shared tag aliases to the
   exact immutable ID, reject foreign replacement, and preserve effect history
   when an authorized rebuild or `--force-recreate` creates a new container or
   image generation. Record intent before dispatch and reconcile lost replies
   without inferring absence from the client result.
4. Repair the native T162 entrypoint's transport around its hermetic init
   falsifiers while preserving their intended exit semantics. A fake-command
   source test may exercise the shell control path and prove exact helper names
   remain unique across command substitutions; it must label every external
   effect as simulated and must not claim a T162 completion marker as live
   acceptance. Ensure all T162/run helper directories/files are receipted,
   removed only after consumers stop, and proven absent. T220 retains the real
   native T162 completion-marker requirement.
5. Repair the native supervisor's real success-publication path and preserve
   existing ordinary non-native Tor suite defaults. Tests exercise both the
   native refusal path and ordinary non-native recorder path without requiring
   native-only environment variables.
6. Exercise producer-to-cleanup, changed-generation recovery, lost-reply,
   finalizer refusal and result-publication controls through actual current
   consumers. Keep all protection-on-failure behavior and the strict T209 A7
   acceptance unchanged. Do not synthesize receipts in tests or claim backend
   terminal proof.
7. Reconcile the candidate and evidence manifest to exact current source,
   tests, dirty Compose suffix prerequisite, and every normative path required
   for the source checkpoint. The final source review covers the exact
   integrated path set; no narrow historical GREEN is represented as approval
   for expanded lifecycle code.
8. Run only affected source selectors after identical RED-to-GREEN evidence.
   Obtain independent Astra/high and Luna 6/high whole-candidate source reviews
   before T220 resumes integration. No commit, T209 A2/A7, native execution,
   host policy operation, or backend capability claim is part of T223.

## Out of scope and stop conditions

T220 remains the owner of full native/local qualification, cleanup acceptance,
backend qualification and integration. T209 keeps all A7 clauses. If source
inspection shows the strict effect model cannot be completed within this
bounded source scope, preserve the evidence and return a whole-model decision;
do not weaken acceptance, introduce an unbounded event framework, use a VM, or
create per-finding tickets.
