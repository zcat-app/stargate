---
id: T224
title: "Deliver the reviewed qualification contract and ticket reconciliation"
status: in-review
created: 2026-10-15
last_updated: 2026-10-16
source: tasks.md#T224
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: US1
blocked_by: []
parallel: false
files_budget: 32
files_scope:
  - "specs/001-tor-route/STATUS.md"
  - "specs/001-tor-route/evidence/T218-manual-tests-first-matrix.md"
  - "specs/001-tor-route/tasks.md"
  - "specs/001-tor-route/tickets/T034a-hand-driven-sc-003-measurement-on-the-re.md"
  - "specs/001-tor-route/tickets/T034f-integration-test-for-us1-acceptance-scen.md"
  - "specs/001-tor-route/tickets/T077-run-the-quickstartmd-walkthrough-on-a-cl.md"
  - "specs/001-tor-route/tickets/T078-run-the-stargate-redteam-agent-against-t.md"
  - "specs/001-tor-route/tickets/T079-run-the-stargate-perf-agent-against-the.md"
  - "specs/001-tor-route/tickets/T080-sweep-with-scriptscheck-license-headerss.md"
  - "specs/001-tor-route/tickets/T202-scoped-live-runner-fresh-vm-overlays.md"
  - "specs/001-tor-route/tickets/T209-bind-apparmor-to-running-dp-observer-hardening.md"
  - "specs/001-tor-route/tickets/T212-close-docker-verification-budgets-history-ci.md"
  - "specs/001-tor-route/tickets/T215-maintained-resource-ownership.md"
  - "specs/001-tor-route/tickets/T218-qualify-shared-egress-observer.md"
  - "specs/001-tor-route/tickets/T220-own-native-local-qualification-effects-and-cleanup.md"
  - "specs/001-tor-route/tickets/T222-dispose-t220-historical-chronology.md"
  - "specs/001-tor-route/tickets/T223-rebuild-t220-native-effect-ownership-source.md"
  - "specs/001-tor-route/tickets/T224-reconcile-t218-predecessor-completion-contract.md"
  - "specs/001-tor-route/tickets/T225-establish-shared-qualification-admission.md"
  - "specs/001-tor-route/tickets/T226-prepare-validate-internal-qualification-artifacts.md"
  - "specs/001-tor-route/tickets/T227-qualify-artifact-runtime-platform-boundary.md"
  - "specs/001-tor-route/spec.md"
  - "specs/001-tor-route/plan.md"
  - "specs/001-tor-route/remaining-implementation-plan.md"
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/contracts/t218-manual-predecessor-admission.md"
  - "specs/001-tor-route/design/qualification.md"
  - "THREAT-MODEL.md"
  - "SECURITY-DECISIONS.md"
  - "specs/001-tor-route/evidence/T224-reconciliation.md"
out_of_scope:
  - T218 source or test implementation
  - T034f/T034a live acceptance
  - T220/T209 backend, Docker, native, or host-policy operations
  - any automatic recovery, extra lifecycle ledger, relaxed refusal, or new history cap
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
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
  - "2026-10-15 maintainer-selected Option A; source-bound disposition: .scratch/reports/2026-10-15-fresh-session/T218/T224-option-a-decision-20261015.md"
  - "T218 settled-reuse design gate: Astra REWORK; Luna APPROVE-DESIGN"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T224: Deliver the reviewed qualification contract and ticket reconciliation

## Context and recorded decision

The maintainer authorized the October16 spec/design edits after falsification and independent Astra
review, then explicitly authorized editing/replacing tickets. The applied qualification contract
and design supersede same-candidate reuse/revision/quota bridges while retaining Option A's trusted
external completion observation, shared exclusion, fixed caps and unknown-state blocking.
The October15 “ok do A” remains historical; do not ask to select it again. This ticket closes
normative delivery and traceability, not implementation or platform qualification.

## Analysis

- Must hold: every old obligation has a retained owner or explicit mechanism replacement.
- Gated: exact document hashes, ticket lint, dependency/closure checks and independent review.
- Residue: working-tree edits and advisory approvals are not a committed/delivered ticket.

## Acceptance

1. Verify the October16 spec/design final manifests and independent approval records against the
   applied normative bytes or an explicitly reviewed later supersession. Preserve the original
   manual contract and security-decision bodies, failed reviews and T218/T220/T223 episode history.
2. Deliver one coherent mapping: T225 shared admission; T226 artifact producer/validator; T227
   finite platform qualification; T223 source integration/privileged transport; T218 readiness;
   T220 complete native A2-live/A7; T209 source hardening and reserved decisions. These child
   deliverables do not authorize another uncounted parent review or source episode.
3. Prove direct closure dependencies survive the T209 source/native split. Retain T202/T212/T215
   broader cadence/source-build duties, browser/human gates and all unaffected product tickets.
   Reject a dependency cycle or an accepted obligation without an executable owner.
4. Reconcile tasks prose to current ticket acceptance and regenerate STATUS from frontmatter.
   Do not mark unfinished code/native work done, reset counters, edit historical evidence JSON or
   invent runtime RED/GREEN for this normative change. Validate only affected documentation/graph.
5. Before source dispatch, use normal reviewed delivery for this exact normative/ticket package.
   Preserve the supplied independent review's advisory scope; it cannot impersonate the normal
   delivery gate. T218/T223 closed-episode resumption still needs its exact finite successor scope
   and authority; this ticket does not itself reopen it.

## Files and completion boundary

Normative spec/plan/qualification contracts/design, THREAT-MODEL, decision log, this ticket,
T209/T218/T220/T223/T225/T226/T227, affected consumer/closure tickets, the retained T218 test-plan ownership map, tasks/STATUS and a durable
reconciliation record are the bounded document scope. No implementation/test/evidence rewriting.
T224 finishes only after exact reviewed delivery; document approval is not native authority.

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


# T224: Reconcile T218 predecessor completion and reuse contract

## Context

Independent T218 feasibility reviews found that visible settled/bootstrap/
authority bytes can coexist with a later failed or uncertain post-publication
step, while the next admission currently receives no independent completion
observation. They also found that manual predecessor admission changes the
promised healthy reuse procedure and does not yet define the terminal boundary
for receipt publication. This is a contract decision, not a source defect that
can be patched by guessing.

The maintainer must choose the policy boundary on an exact reviewed candidate.
Until that decision is recorded, T218 stays deferred and the current strict
unknown/late refusal semantics remain binding. This ticket authorizes no source
implementation or tests that claim the missing behavior.

## Decision

The maintainer selected “ok do A”. Option A retains the pinned per-operation
manual predecessor contract in
[`t218-manual-predecessor-admission.md`](../contracts/t218-manual-predecessor-admission.md).
The source-bound disposition and its implementation/integration limits are
recorded in the immutable [T224 Option A decision report](../../../.scratch/reports/2026-10-15-fresh-session/T218/T224-option-a-decision-20261015.md).

## Acceptance

1. Present a concise, source-bound decision record that traces the settled,
   bootstrap, authority and observer-receipt publication failure class through
   the current writer and fresh-reader paths, preserving the exact paired
   feasibility reports and all prior T218 counts.
2. Provide the maintainer exact alternatives and consequences: (a) define a
   genuinely external per-predecessor completion/admission requirement and
   reconcile its authority carrier, evidence-root/retention bounds, repeated
   use, and receipt-publication completion; or (b) propose a different
   automatic completion boundary only if it preserves every current
   unknown/late refusal and healthy reuse guarantee. Do not treat old-PID
   absence, visible receipt bytes, a dead writer, resync, or a self-authored
   file as independent completion.
3. Obtain the explicit maintainer decision and independent review of the exact
   normative diff before changing T218/spec/plan/threat-model acceptance. If
   the decision is unavailable or the receipt boundary remains ambiguous,
   leave T218 deferred and report the exact missing choice; do not invent a
   policy amendment or begin T218 source implementation.
4. Preserve Go's single lifecycle owner, six-frame bounds, original deadlines,
   evidence/history and all unknown-state refusal. Do not add an automatic
   recovery path, a lifecycle ledger, a new actor, a raised timeout, or an
   arbitrary history cap to make reuse pass.

## Completion boundary

T224 completes only when the chosen exact contract is explicitly accepted and
its independent reviews approve the same bytes. It does not qualify source,
tests, host authority, live readiness, T034f or T218 completion.
