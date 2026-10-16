---
id: T218
title: "Qualify single-use observer readiness with shared admission"
status: deferred
created: 2026-10-11
last_updated: 2026-10-16
source: tasks.md#T218
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: US1
blocked_by:
  - "T162"
  - "T224"
  - "T223"
  - "T225"
  - "T226"
  - "T227"
parallel: false
files_budget: 20
files_scope:
  - tests/integration/egress_observer_test.go
  - tests/integration/egress_observer_readiness_test.go
  - tests/integration/egress_consensus_test.go
  - specs/001-tor-route/tickets/T218-qualify-shared-egress-observer.md
  - specs/001-tor-route/tickets/T034f-integration-test-for-us1-acceptance-scen.md
  - specs/001-tor-route/tasks.md
  - specs/001-tor-route/STATUS.md
  - specs/001-tor-route/spec.md
  - THREAT-MODEL.md
  - tests/integration/sc_egress_observer_readiness.md
  - specs/001-tor-route/evidence/T218-tests-first.json
  - scripts/t218-readiness-run.py
  - scripts/test_t218_readiness_run.py
  - specs/001-tor-route/contracts/t218-manual-predecessor-admission.md
  - specs/001-tor-route/evidence/T218-manual-tests-first-matrix.md
  - specs/001-tor-route/plan.md
  - SECURITY-DECISIONS.md
out_of_scope:
  - data-plane/**
  - compose/**
  - production AppArmor profile or owner-rule changes
  - T034f onion consensus, authenticated routed controls, scenario assertions, orchestration, and acceptance receipt
  - changes to the ControlPort implementation or tests
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "V: Honest Threat Model"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Independent Review and Adversarial Discipline"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/design/qualification.md"
decision_refs:
  - .scratch/tmp/T034f/T218-decomposition-plan-2026-10-11.md
  - .scratch/tmp/T034f/T218-R12c-refinement-plan-2026-10-12.md
  - .scratch/tmp/T034f/T218-R14j-single-lifecycle-owner-plan.md
  - .scratch/tmp/T218/T218-deadline-source-disposition-2026-10-12.md
reviews: {}
overrides:
  - date: "2026-10-11"
    by: user
    decision: "Use affected-only verification for this T218 batch; do not run scripts/verify.sh or unrelated Go/Java suites."
    reason: "The user explicitly authorized scoped verification for this batch."
  - date: "2026-10-11"
    by: user
    decision: "Use fresh Astra and Luna reviews for T218; GLM remains paused."
    reason: "The user explicitly selected Astra and Luna for this batch; this ticket-scoped override does not change the global review matrix or imply the default GLM+Astra launcher ran."
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
deferred_on: T223
deferred_reason: blocked-on-new-ticket
---

# T218: Qualify single-use observer readiness with shared admission

## Context and retired mechanisms

Retain the real observer/readiness qualification and original native controls. Replace same-
candidate reuse, repeated authority revisions, quota-image bridges and runtime compilation with
Q2–Q7's prepared artifacts, one attempt and enduring shared domain. The original Episode1 closed
uncertain; no source/test/guard/native resumption follows this ticket edit. Carry all failures,
frozen candidates, R11 extraction history and actual counters into any reviewed successor scope.

## Analysis

- Must hold: Go is the readiness lifecycle/effect/cleanup owner; Python observes the prepared
  child through the fixed witness. Shared admission cannot be bypassed by checkout/candidate.
- Gated: exact real-consumer source controls and independently reviewed source/receipt bindings.
- Residue: actual DP/helper authority, platform quota/durability, timing and live observations
  require their own reviewed evidence; source/refusal/negotiation evidence cannot supply them.

## Acceptance

1. Preserve original extraction acceptance 1–2: standalone shared observer compiles without the
   parent scenario and without uncommitted ControlPort changes, and combined source is checked.
   Use exact current repaired bytes as new evidence baselines; frozen R11 remains historical.
2. Consume delivered T225 admission, T226 artifacts, T223 adapters and T227 platform results.
   Before native admission, validate actual state/evidence roots, mount/device/filesystem/options,
   writer access and the full producer/temp byte/file/inode envelope against T227's actual storage
   enforcement/durability evidence. Drift, unsupported durability or limits outside the qualified
   envelope refuse; representative storage fixtures do not prove this consumer's software ordering.
   No dependency on completion of all T220 live work is introduced. Same-source new candidate
   still needs a distinct manual authorization and the same global exclusion/cumulative capacity.
   Failed/unknown/late state cannot be escaped by a fresh root, boot ID or directory.
3. Retain original readiness acceptance 3/5/6: exact loaded-policy matching/invariance, actual-DP
   kernel label/PID/start/namespace/cgroup identity, monitor startup/drift/cancellation, owned DP
   freeze/kill/reap/absence, SOCKS negotiation, CP loopback controls, inverse controls, continuous
   NFLOG/tuple shutdown/drain/ACK/EAGAIN/sequence/loss/counter reconciliation and exact restoration.
   Synthetic failure targets remain labelled and do not replace actual-DP native observation.
4. Retain the full original acceptance4/11 deadline and six-frame protocol equations: DI35,
   DN20/G40, Go F0-anchored D120, A15/B33/C24/D35/E8, E3/E5 cumulative/non-overlapping debits,
   A2=min(D120,F0+2s,invocation deadline), PhaseE DE=min(D120,E0+8s), exact ACK order/size/count,
   3.1s-at-4.1s discriminator and combined overrun control. D35's final <=1s is in-memory-only.
   Any detached cleanup uses min(D120,invocation deadline,entry+120s), never a renewed budget.
   These are retained targets, not proof of current enforcement or healthy platform timing.
5. Keep source/path/mode and independently expected build/helper/runner/Go binary/image identities
   under original acceptance7/8. Freeze/build outside runtime authority; the runtime runner only
   verifies and observes prepared bytes. Build evidence stays separately accounted; no source-
   to-binary link is inferred merely from listing two hashes. No mutable output changes the
   independently expected approved source identity.
6. Implement readiness use of the common Go state/phase adapter and privileged intent/ACK under
   DQ2a, with no competing coordinator dispatch or root direct state write. Establish each absent
   real Go/Python/witness consumer before its later safety RED; source models or failed setup
   cannot certify the absent path. Preserve original six-frame and owner-loss refusals.
7. Replace original reusable reservation portions only: one immutable candidate/source/authority
   and attempt, common pre-import pending, monotonic domain byte/file/inode precharge, literal
   trusted manual predecessor completion and retained original directory/evidence identity.
   No automatic repair/refund/history search/old-PID recovery or same-candidate retry. The exact
   closed new carrier/record schemas and numerical producer/temp envelopes precede source tests.
8. Write only unique private readiness candidate plus external post-exit receipt. All required
   scenario/cleanup/owner/observer outcomes must pass; provisional settled bytes after late failure
   remain ineligible. Exact source-plus-receipt independent review gates canonical publication.
   The existing canonical t.Cleanup write is a source defect to fix, not an accepted mechanism.
9. Actual native readiness runs only after source/platform and separate residual host-authority
   acceptance. Pre-init inventory/artifact checks differ from post-init production-DP checks.
   Normal opt-ins unset refuse before effects. Qualification remains independent of public onion
   workload; Tor bootstrap is not falsely described as zero sidecar network activity.
10. T034f's original failed scenario receipt, start SHA, counts and parent-only overlays remain
    unchanged. Neither this ticket nor T220 source approval passes T034f authenticated onion/
    consensus/capture acceptance, T034a DNS, T077 human timing or T209 reserved decisions.

## Scope and completion

Keep the original 20-path readiness budget, enumerate exact changed files before source dispatch,
and consume common modules through their delivered API rather than copying another admission
ledger. Go-only readiness settlement and fixed witness remain. This ticket is complete only with
all retained source AND actual native readiness evidence and exact review; no plan/source-only PASS.

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


# T218: Qualify the shared egress observer before T034f acceptance

## Current lifecycle disposition — 2026-10-15

T218 is deferred while T224 completes the exact reviewed Option A reconciliation.
Option A retains the pinned per-operation manual predecessor contract at
`specs/001-tor-route/contracts/t218-manual-predecessor-admission.md` (SHA-256
`9a8507359259a42ab4307a3493da6b28314503596ce6445d0c36b05f70ea9587`). The
maintainer's choice resolves the policy selection only. Separately, the accepted
finite recovery proposal's T218 Episode 1 closed uncertain; it grants no later
test episode, guard run, source implementation, or live operation. Paired review
of the normative documents cannot reopen that consumed authority. Preserve all
counts, failures, the strict unknown/late refusal semantics and the closed
episode. T218 source, tests, guard execution and live qualification remain
unauthorized unless a successor finite recovery proposal receives independent
review and the maintainer explicitly approves its exact scope. No formal review
cap or escalation trigger is inferred here.

## Context

The observer currently exists inside T034f's live scenario test and needs an
independently compilable qualification path before the scenario can resume.
T218 owns observer qualification; T034f remains the final authenticated onion
acceptance scenario and cannot be marked PASS by T218. This is the user-selected
single-prerequisite decomposition in the approved T218 plan.

## Analysis

- **Must hold** — shared instrument code compiles without T034f scenario source;
  host identity, effective DP label, policy invariance, monitor lifecycle,
  controls, NFLOG attribution/loss/drain, and cleanup are qualified on the exact
  standalone candidate before T218 can complete.
- **Gated** — source compilation, moved pure regressions, candidate-bound source
  and executable identity, and tests-first evidence cover code behavior and
  candidate integrity. These do not establish host/kernel authority safety or
  live packet observation.
- **Residue** — the real host's effective authority and actual-DP readiness are
  live properties. The residual unconfined helper authority remains disclosed;
  neither plan approval nor source review accepts it. No host/kernel probe may
  run until the maintainer records the separate authority decision.

## Acceptance

1. Extract the shared instrument declarations and NFLOG `TestMain` dispatch into
   `egress_observer_test.go`; move directly relevant existing unit and
   regression tests into `egress_observer_readiness_test.go`. Preserve symbols,
   comments, and existing test behavior mechanically. Keep consensus parsing,
   onion HTTP/client logic, scenario assertions, and full T034f orchestration in
   `egress_consensus_test.go`. Label existing tests as historical/retrospective;
   do not add empty, passing, or skipped readiness tests as qualification.
2. Compile the integration Go package with the parent scenario file absent and
   both ControlPort files identical to baseline HEAD in one source-only detached
   linked worktree based on preserved HEAD `f13a40cad978329974f30a91f282529289ff3e5d`.
   Preserve that original extraction as historical evidence. New repair
   baselines use exact current bytes under the staged sequence below. Apply
   and stage only the explicit T218 path/declaration overlays in that candidate. Also compile the combined T034f source and run only affected pure
   regressions; all native/helper opt-in variables are unset. Record the exact
   declaration/path ledger, hashes, commands, and outcomes.
3. Add spec-derived red-before-green regressions before repairing the named
   readiness boundaries. AppArmor lookup selects exactly one profile directory
   by exact `name`, rejects absent/duplicate/ambiguous/mismatched policy, and
   compares loaded DP raw policy to compiled unchanged source. Policy comparisons
   enforce foreign-inventory invariance and permit only the owned DP
   absent-to-enforcing-to-absent lifecycle; incomplete comparisons cannot
   authorize restoration. Bind the actual DP's exact effective enforcing label
   to normal identity checks and rechecks, without requiring it for Tor, CP, or
   inverse callers.
4. Enforce one immutable monotonic 120-second finalization deadline D120,
   armed exactly once at Go `Finish` entry; forward helper disposal cannot arm
   it. Each A–E phase uses the earlier of its A15/B33/C24/D35/E8 cap and
   remaining D120, with no renewed nested or detached deadline. Any detached
   cleanup deadline is captured once at its exact entry as
   `min(D120, invocation_deadline, detached_entry+120s)`; it creates no new
   budget past either original deadline and is never reset. Preserve the
   35-minute invocation ceiling, 20-minute native ceiling, and 40-minute outer
   Go process backstop. D35 includes the 20-second restore helper, 12-second
   identity helper, 2-second final helper-absence check, and at most 1 second
   for in-memory reconciliation/phase close-out. That last interval may start
   no child and perform no filesystem operation; any attempted operation or
   close-out overrun refuses. Batch B's exact pre/post firewall snapshots and
   four owned check/delete pairs within its approved helper budget; preserve
   exact T162 and foreign-policy comparisons. Source tests must verify these
   required caps are enforced and never renewed; implementation and that
   verification remain pending, and tests do not claim healthy real-host
   completion.
   A separately authorized live qualification tests actual timing, and any
   missed healthy-path cap requires governed reassessment without silently
   increasing a limit. Apply explicit identity-helper memory/PID bounds and
   current capability/mount checks without restoring `SYS_ADMIN`. Every
   standalone host-authority entrypoint checks the separate maintainer
   acceptance before any probe; an environment opt-in alone is not that
   acceptance.
5. Qualify actual monitor startup, repeated membership checks, drift rejection,
   and caller cancellation with owned-target cleanup/reaping/exact absence;
   qualify actual-DP freeze/kill and reaping separately. For failure
   injection that cannot safely be induced on the real DP, use only a run-owned
   synthetic target, label its limits, and retain actual-DP checks. Unknown
   membership injection must use a concretely validated owned cgroup mechanism;
   otherwise stop that case and consult the root.
6. Add an explicit opt-in `TestEgressObserverReadiness` sharing verified source,
   binary/image binding, init, and cleanup code with T034f. With unchanged
   production images/configuration and enforcing DP profile/T162 rules, it
   qualifies the actual DP's exact label and full identity read set, monitor and
   captures, distinct before/after bounded SOCKS negotiation replies, CP
   loopback controls, both exact outside-cgroup inverse controls, producer
   shutdown, complete tuple drain, UNBIND ACK/EAGAIN, sequence/loss/counter
   reconciliation, exact cleanup, and bounded monitor failure cases. The
   unauthenticated SOCKS greeting is a negotiation control, never an
   authenticated routed control. Init may start Tor native bootstrap; readiness
   is independent of the public onion workload, not a claim of zero sidecar
   network activity.
7. Keep candidate discovery Git-backed. Readiness selection requires the two
   shared observer files and T218 scope, not the parent scenario. Assert the
   discovered repository root is the explicit candidate root and clear inherited
   Git directory/worktree/index overrides for discovery commands. Extend the
   existing candidate digest/freezer to bind regular-file type and canonical
   executable state with path/content, compare index mode to filesystem mode,
   reject symlinks/unsupported types/mode mismatch, and preserve identity across
   read-only freezing. Retain the selected path/type/executable-state ledger in
   the private source receipt, validate it against actual frozen files before
   and after init, and publish only its path count and digest. Temporary nested-Git regressions exercise actual
   discovery/freezing, absent parent scenario, baseline ControlPort files,
   support-source and executable-bit mutations, and receipt identity.
8. During qualification, write only a unique private per-attempt review
   candidate outside the E5 workspace. Bind candidate, helper, source, toolchain,
   image, and effective-label identities; record fixed result categories,
   counters, and cleanup only. Persist no packet contents, unrelated host
   metadata, or credentials. The exact-source-plus-runner-receipt review gates
   publication of those approved bytes to
   `tests/integration/sc_egress_observer_readiness.md`; qualification itself
   never writes the canonical readiness path. Keep
   `sc_us1_egress_consensus.md` FAIL/NOT OBSERVED and unchanged. A readiness
   candidate, receipt, or report cannot satisfy T034f's authenticated consensus,
   continuous >=120-second onion observation, same-run authenticated
   positive/inverse controls, or final scenario review.
   Reconcile the threat-model/spec wording so pre-init UID/socket inventory
   checks are distinct from actual-DP identity qualification after init; do not
   claim every probe precedes init.
9. Preserve T034f's original start SHA, counter9, all acceptance clauses and
   failed-attempt evidence. T034f remains deferred on T218, with the separate
   residual-authority decision still required before host/kernel probes. Do not
   imply that T218 or T209 is complete or that host authority has been accepted.
   T209 remains pending for its existing downstream T077 dependency and is not
   a T218/T034f dependency. After T218 completion, T034f resumes with a new
   baseline while its original evidence remains historical/superseded.
10. Do not change production code, profile, or owner rules; do not bypass T209.
    Stop on unavailable/corrupt identity, unexplained loss, failed restoration,
    incomplete live result, or the third failed formal review round. No Docker,
    live probes, monitor/capability qualification, broad verifier, commit, or
    push is authorized by this ticket's source-only checkpoint.
11. Use the Go `TestEgressObserverReadiness` process as the sole lifecycle,
    deadline, effect, cleanup, settlement, and candidate owner. The Python
    runner is a bounded source freezer/builder/invocation observer and remains
    the child parent; it cannot perform readiness effects or decide PASS. Bind
    the launch record to the exact live parent PID/start identity/executable,
    frozen runner bytes/mode, source manifest, invocation interval, and running
    Go binary. Direct test-binary invocation or absent/invalid inherited launch
    channel refuses before authority reads or host operations. The fixed
    six-frame channel is launch record; Go FinishStart(F0,D120); exact Python
    ACK; Go PhaseE(E0,DE); exact Python ACK; Go terminal marker. Bound each Go
    record to 4096 bytes, each ACK to 512 bytes, and all six frames to 17,408
    bytes with strict order/count and no retry. Python retains both Go-origin
    anchors and the terminal echoes them exactly. ACK confirms retention only.
    FinishStart ACK and completion of every registered Go callback share
    A2=min(D120,F0+2s,invocation deadline), with no per-recipient reset; missing
    ACK closes admission and leaves safety cleanup to Go under D120. PhaseE
    handshake time is charged once to owner E3 and terminal-to-receipt
    accounting is non-overlapping. E3 is one cumulative 3-second debit for
    every non-removal E operation across Go and Python; E5 is one cumulative
    5-second debit for exact workspace removal and absence. E5 pauses E3 but
    still consumes DE wall time. An E3/E5/DE overrun or uncertain removal
    refuses the candidate and PASS. Preserve both discriminators: E3=3.1s
    refuses while total wall=4.1s remains below DE, and the separate E3 6s +
    E5 1s + E3 3s case refuses (10s exceeds DE and is not claimed to isolate
    E3). No general event stream or pending/terminal filesystem lifecycle
    ledger exists; the runner emits a bounded post-exit receipt only after exact
    child exit and candidate readback.

    Persist a cross-process reservation under one authority-pinned non-root UID
    at `<pinned-home>/.local/state/stargate/t218/reservations`; keep the
    enrollment record at the sibling path
    `<pinned-home>/.local/state/stargate/t218/reservation-enrollment-v1.json`.
    `<pinned-home>` is the canonical home path pinned by the separate authority
    record; HOME, XDG, cwd, and checkout do not select or relocate this state.
    Only an explicit
    `BOOTSTRAP_ONLY` command may create it, using directory-FD-relative,
    no-follow parent creation and exact ownership/mode/fsync/readback checks.
    The separate maintainer authority writer appends `AUTHORIZED_ENROLLED`
    under the same stable scope lock and admits it only after durable
    readback. An append, file-fsync, directory-fsync, or readback failure leaves
    the prior valid authority revision in force or makes the new revision
    invalid/rejected; it can never create partial authorization. The authority
    revision is distinct from the immutable enrollment generation. Every live
    admission rereads the latest authority revision and enrollment under that
    lock, validates current idle/settled state, and durably commits `pending`
    before any effect token; pending state
    blocks all attempts and authority transitions while host work proceeds.
    The writer refuses while pending or if enrolled root, scope, lock, or
    enrollment manifest is missing, corrupt, or uncertain. A stale invocation
    that read revision G1 before waiting for the lock must refuse if G2 is now
    current, even when G2 retains the same UID, root, scope, lock, and
    enrollment generation.
    The Go owner reacquires the same lock to settle exact owned effects. Missing,
    corrupt, partial, or uncertain enrollment/reservation state refuses; live
    code never recreates, repairs, rotates, migrates, or falls back. Missing
    state or namespace migration requires exact old-owner/effect reconciliation
    and a fresh maintainer decision. This is cooperative exclusion among
    supported invocations for the pinned UID, not malicious same-UID or
    cross-UID containment. Python never owns cleanup, settlement, or authority.

## Constitution Check

This is a lifecycle/evidence-flow clarification for T218. It does not change
Principle I payload opacity, Principle II data-plane independence, or Principle
III's actor/traffic matrix; it adds no network actor, public egress, telemetry,
or host authority. The persistent reservation is cooperative coordination for
one explicitly authority-pinned UID, not a new trust boundary or a claim of
malicious same-UID/cross-UID protection. The threat-model disclosure and
separate live authority gate remain binding (Principle V). Candidate and receipt
publication stays source-bound and manually reviewed; no automated promotion
or T034f acceptance changes (Principles IV/VI). Tests-first and independent
Astra/Luna review remain required before implementation advances (Principles
VII/VIII).

## Out-of-scope

T218 qualifies the observer and does not own T034f's onion scenario, consensus,
authenticated routed controls, acceptance receipt, or final PASS. Production
profile/owner-rule changes and acceptance of the disclosed residual host
authority are separate decisions. T209's existing pending work for its
downstream T077 dependency remains separate from T218 and T034f.

## Notes

**Governed disposition (2026-10-12): `amend-spec`.** The maintainer-authorized
protection delta is one monotonic 120-second finalization deadline shared by
observer settlement, exact helper removal, run-owned NFLOG removal and policy
ownership checks, Compose teardown/resource absence, policy restoration and
verification, workspace removal, and evidence freeze. Each phase derives its
deadline from that shared budget; exceeding any required healthy-path cap is a
sticky non-PASS and cannot be repaired by late completion. Readiness selection
and the frozen source/executable identity include
`scripts/t218-readiness-run.py`, binding file content and executable mode.
Source-only review, a separate host-authority decision, authorized live
readiness, and formal exact-source-plus-receipt review remain distinct ordered
gates; this amendment grants no host authority and does not accept residual
authority. T034f remains FAIL/NOT OBSERVED and T209 stays outside scope.

The 2026-10-12 disposition above is historical and is superseded only as to
whether document approval authorizes source resumption. The accepted finite
recovery proposal later closed T218 Episode 1 uncertain, without authorizing a
successor episode. Paired T218/spec/THREAT-MODEL/matrix approval reconciles the
Option A contract but does not resume source implementation, authorize tests or
guard execution, or permit live qualification. Any successor recovery proposal
must carry forward all counts and failures, define exact bounded work, receive
independent review, and obtain the maintainer's explicit approval before
execution. The Go single-owner plan and D120/A15/B33/C24/D35/E8 limits remain
binding if execution is later authorized. No host probes, Docker actions, policy
mutation, or acceptance of residual helper authority follow from this update.

The approved decomposition plan and its reassessment are preserved in
`.scratch/tmp/T034f/`. The historical 16-path working-tree union contains both the T218
observer changes and preserved T034f scenario work; the T218 scope above owns
only its listed files and, within shared documentation paths, the explicit
T218 prerequisite/readiness wording. The ControlPort source/tests, T034f
tests-first artifact, and T034f acceptance receipt remain parent-only overlays.
T218's live readiness checkpoints remain outstanding after source extraction
and compile-only verification.

### T218 staged executable evidence sequence — 2026-10-13 reconciliation

This clause supersedes only R14j's evidence-baseline and sequencing rules, not
its lifecycle, privacy, authority, deadlines, resource bounds or final proofs.
Frozen R11, all rejected candidates, tests, seals, RED/GREEN records and verdicts
remain unchanged historical evidence. New repairs bind exact current pre-fix
implementation bytes and executable modes, HEAD, index/working overlays and
explicit untracked source inputs in a preserved manifest before their RED.
R11 is not silently relabelled as the baseline of later implementations.

Tests-only batches may be staged between real consumer-establishment slices.
Each batch receives fresh independent Astra/high and Luna 6/high approval on
the same exact bytes before execution. Run that batch before its implementation;
rerun the identical selector after implementation and directly affected regressions.
A complete final tests-only diff is no longer required before the first
establishment implementation. There is no exemption for new safety behavior.

Executing an existing valid program that exits without its specified child,
nonce/exit observation or transaction result can falsify only that absent
establishment behavior. Prove that the program executed with valid setup, and
retain independent child/transaction observations. A missing module, missing
binary, import/build failure, invalid fixture or selector mismatch is setup
failure, never behavioral RED. Source inspection is not executed RED. An
establishment RED cannot prove later refusal, identity, deadline, witness,
reservation or settlement safety. Existing correct refusal receives honest
retrospective coverage; it is never weakened to manufacture RED.

Establish the real strictly non-native Python spawn/pipe/wait observation
consumer first, with a fixed harmless Go test-child selector, every native,
helper and authority opt-in unset, a child-written fresh nonce and exact exit.
This role uses the same production process adapter as later invocation and
emits bounded, explicitly provisional attempt-bound observation only; it can
never issue readiness eligibility, write a final readiness candidate, invoke
native/helper roles, authorize effects or update reservation state. Its first
slice implements launch/output/wait observation only, not source freezing,
build provenance, witness validation or reservation safety. The normal
readiness selector with all opt-ins unset must still refuse/skip before host
operations. Source freezing/build binding, parent/binary identity, six-frame
anchors/ACK, exit/output/receipt refusals and reservations get distinct
preimplementation assertions through the then-established real consumers.

Go owns the readiness lifecycle and live reservation transactions. Go's
explicit bootstrap-only role owns private-state directory-relative creation,
locking, durability and readback, and cannot enter readiness. Python may
explicitly dispatch that role but cannot own authority, cleanup or settlement.
A separate explicitly invoked maintainer writer appends/readbacks authority
under the same stable lock; neither Python nor readiness invokes it
automatically. Establish bootstrap creation and writer append/readback through
real Go dispatch on authority-pinned private fixtures before their later
stale/pending/concurrent/mode/no-follow/sync/crash refusal repairs. Fixture
state is selected by explicit fixture authority, never ambient HOME/XDG.
The current fake-preflight seam supports refusal/cleanup characterization;
a successful fake preflight leaves candidate unset and is not a healthy
full-readiness control. A structural owner regression proves ownership wiring
only; it does not replace runtime safety REDs through real registered effects.

All original acceptance remains mandatory: six bounded frames, retained Go
anchors and exact ACKs, exact child/source/build identity, Go-only Finish and
settlement, serialized reusable reservation and separate authority writer,
private candidates and external post-exit receipt, DI35/DN20/G40 and immutable
D120/A15/B33/C24/D35/E8 with cumulative E3/E5 and the 3.1s-at-4.1s
discriminator. Unknown/late state refuses eligibility and retry and retains
required enforcement/artifacts. No physical interruption claim is added.
No host/Docker/policy authority, live PASS, T034f acceptance or T209 completion
follows from this reconciliation or an establishment result.

The current 20-path budget adds only the manual contract, durable manual matrix, plan Constitution
Check and append-only security rationale; it preserves the historical union and parent-only overlays.

### T218 manual predecessor-admission reconciliation — 2026-10-14

The binding detailed target is `specs/001-tor-route/contracts/t218-manual-predecessor-admission.md`.
The maintainer approved this manual direction and said “run”; independent design approval is
not source/live qualification. This supersedes only R14j's no-additional-decision rule for healthy
same-generation reuse and defines the otherwise unresolved completion carrier. A deliberate
trusted-maintainer literal per-operation decision, after personally observing successful original
Go AND observer-command completion, names immutable bootstrap B, current writer W and last
settlement S independently. Visible bytes or another complete/approved file never certify the
publisher finished; failed/unknown/late observation forbids the next decision and admission.
The CLI cannot authenticate human presence or an honest malicious same-UID operator; the
existing cooperative trusted-maintainer boundary remains explicit.

Go validates exact current authority, enrollment, locked state, source/resource/evidence identities
and operation/next-operation binding before any effects. It opens at most three selected headers,
not history search. New writer W2/W3 retains the original S unchanged and provides exact BEFORE/
AFTER quota-image bridges; no immutable S must reference a future authority writer. The existing
Go authority writer may precharge only explicit capacity counters/accounting identity under the
stable lock, preserving every lifecycle/proof/owner/source/deadline/resource field. It cannot
clear pending, transition lifecycle state, settle effects, own cleanup or grant readiness.
Only the Go readiness owner commits pending and settles its effects. Missing/current-image or
stale-writer mismatches, pending and capacity uncertainty still refuse. Live code never recreates,
repairs, refunds, migrates, deletes or infers permission from old PID absence.

The pinned evidence root is `<pinned-home>/.local/state/stargate/t218/evidence`, outside active
effects and disposable workspace, created only by explicit bootstrap and bound in enrollment/
authority. Preserve immutable prior bundles and original effects-parent device/inode/UID/mode/link
facts from the original held FD. Reuse compares those to the fresh no-follow path/FD and exact
absence. Conservatively precharge all producer/observer/temporary byte/file/inode envelopes in
existing serialized reservation metadata, including quota updates and authority history; exact
closed schemas and numerical sums are mandatory in the root implementation plan before tests.
Capacity exhaustion refuses before effects, without an arbitrary fixed attempt-count ceiling.

All original six frames, bounded launch/ACK/total sizes, Go-only lifecycle ownership, retained
anchors, fixed DI35/DN20/G40/D120/A15/B33/C24/D35/E8/E3/E5 accounting, native resource/restoration
controls, private candidate/receipt distinction and host-policy gate remain required. The durable
manual tests-first matrix retains all original rows and adds the full publication/reference/quota
failure class. Tests-only and source require their own exact paired gates; affected-only checks
apply. This target does not claim any source/native/live PASS or complete T218/T209/T034f.
