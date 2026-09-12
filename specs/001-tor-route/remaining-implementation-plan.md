# Remaining implementation plan — feature 001

Updated 2026-09-12 after the foundation audit and **T156 constitution strengthening**.
Ticket frontmatter is executable; this document supplies priority within the runnable set.
Inventory after reviewed T156 delivery: **191 tickets: 129 done, 60 pending,
two deferred (T037 and T154)**. No runtime fix is delivered by the amendment.

## Decision and implementation boundary

T156 completed independent review and delivery in commit `3aac431`. It sets binding listener,
egress, isolation, auth recovery, fail-closed and aggregate-data requirements. The earlier audit
and constitution evaluation remain historical evidence; the amended constitution and
`contracts/foundation-boundaries.md` govern new work. T125 is not accepted precedent.

T154's reviewer-guidance cleanup is folded into T156 and marked deferred/decomposed, with its
blockers redirected to T156. T152 now implements the selected aggregate-only operational policy;
T148 implements certificate validity/renewal instead of leaving the policy undecided. New
T157/T158/T159 own browser blocking, finalized counter publication and stale-auth/durability.

Investigations T134/T138/T147 must create concrete implementation children and add them to T155
and affected consumers before closure. T155 gates further feature work; T078/T079 remain final
cumulative reviews. A spec decision does not imply its implementation is sound. Required tests
and live evidence remain blocking. Completed tickets keep their history.

## Ordered queue

Each arrow is a preferred execution order, with one focused ticket per implementation/review
loop. Frontmatter encodes mandatory prerequisites, not every preference in this table. Use
explicit IDs with `scripts/run-task.sh`; after each completion, consult `scripts/next-task.sh`
and choose the earliest ready entry here. T156 is complete; T139 is next and is the only runnable ticket.

| Order | Tickets | Required outcome |
|---|---|---|
| 0 — completed authoritative baseline | T156 | Amendment, downstream reconciliation and independent reviews delivered in `3aac431`. |
| 1 — gate integrity | T139 | Required scripts/module coverage and complete reviewed-source snapshots cannot silently disappear. |
| 2 — definite defects | T135 → T137 → T136 | Fix resumed peer authorization, reload deadlines and complete client/profile/site partitioning, with spec-derived regressions first. |
| 3 — foundational design | T134 → T138 → T147 | Review compliant topology, enforced observer authority and CONNECT isolation/refusal contract. |
| 4 — implement selected designs | Children created by row 3 | Implement tests-first repairs; add each child to closure AND affected consumer dependencies. Additional IDs are assigned when the design is concrete. |
| 5 — remaining foundation behavior | T148 → T143 → T149 → T158 → T152 → T153 → T150 → T151 → T157 → T159 | Peer validity/renewal, stale constants, byte accounting, finalized metrics, aggregate-only operations, startup failures, truthful UI, browser blocking and auth rollback/durability. |
| 6 — supply chain and workflow evidence | T140 → T141 → T142 → T144 → T145 → T146 → T120 → T114 | Pins, effective agent boundaries, tests-first records, integrity regressions, init diagnostics, verify log isolation and analyzers. |
| 7 — startup and integrated recovery | T123 → T124 → T132 → T121 → T126 | Real operator initialization, authenticated readiness, reconnect, shared harness and real same-target partition isolation. |
| 8 — foundation closure | T155 | Integrated constitutional probes and fresh independent cumulative foundation redteam. |
| 9 — US3 contract tests | T064 → T065 → T066 → T067 → T067a → T067b → T068 → T069 → T070 → T070a → T070b | Failure corpus, protocol responses/counters, reference IDs, Tor-down/midstream and event behavior. Ground against the new supported ingress contract first. |
| 10 — US3 implementation | T071 → T072 → T073 | Privacy-safe responses, failure mapping and advisory-only events. |
| 11 — regressions/docs | T079a → T119 → T117 → T110 → T111 → T112 | Concurrency, token fields, hardening records, image agreement, zip inputs and stale prose. |
| 12 — reproducibility/release preparation | T075 → T109 → T081 | Compared build artifacts and reviewed release machinery; publication remains separate. |
| 13 — live acceptance | T034f → T034a → T077 → T080 | Attributed network evidence, reference browser, clean-host quickstart and license/doc sweep. |
| 14 — final cumulative reviews | T078 → T079 | Completed-candidate security/privacy and performance evidence, then finding closure. |

All 60 pending IDs and the completed baseline T156 appear once. T037 stays deferred; T154 is replaced by
T156. T074 and T068a are done and retain their history. No runtime implementation starts until
T156 completes normal reviewed delivery (now satisfied); unavailable required evidence does not turn into PASS.

## Execution constraints and remaining grounding

- Every implementation follows the canonical review loop: spec-derived failing regression
  first for privacy work, current-tree `verify.sh`, fresh codereview and independent redteam
  for privacy-critical tickets. Green baseline results are not evidence for untested guarantees.
  The earlier audit recorded 20 PASS, one reproducibility SKIP and no failures; nested Docker
  and live checks were also unavailable. That is historical evidence, not a gate for new changes.
- A separately deliverable test ticket can complete only with a valid green gate. If its
  regression requires missing implementation, refine before executing: move regression and fix
  into one focused owner, mark the standalone ticket deferred/decomposed and redirect blockers.
  Preserve the failing-before-fix result in that owner; no disabled tests or red-ticket deadlock.
- T071–T073 may partly describe behavior already implemented. Ground against current source
  and contracts after foundation repairs; prove existing behavior rather than manufacture a
  rewrite. Do not claim new regressions historically preceded old implementation.
- T123 now requires the documented initialization plus Compose sequence from empty volumes,
  without test-only mount/key repairs. T123/T124 are privacy-critical because their changes
  touch deployment permissions and authenticated sidecar readiness. Their earlier proposed
  fixes remain hypotheses until T134/T138 settle the topology and authority boundaries.
- T132 must settle cold snapshots, generation monotonicity, revocation and reconnect semantics
  before choosing a re-push implementation. T148 depends on the definite T135 fix and implements the selected validity/renewal policy.
  T132 additionally depends on T159 so reconnect cannot promote stale auth content.
- Keep execution serial until T120 provides isolated verification logs. T121 follows the new
  topology so shared helpers do not institutionalize compensating setup. T126 must observe
  the real DP path and include a positive control that detects fused isolation identities.
- T157 owns the browser blocking fix and live failure-path evidence; T155 owns the live-e2e tracker
  and rechecks that evidence, including whether
  hardening/token failures cause unintended Direct traffic. The audit did not establish actual
  browser network behavior. Arrange browser/capture access, real onion targets and a second
  JVM host early; missing prerequisites keep required checks pending.
- T034f's refined namespace-attributed acceptance supersedes its old quoted host-wide capture
  instructions. Bridge-visible UDP alone is not proof of internet exfiltration; establish the
  actual selected boundary with controls. T079a's old Argon2 rationale must be grounded against
  the current HMAC contract while retaining its concurrency requirement.
- T081 now requires pinned extension build inputs, distinct registry/signing authentication,
  generated digest/provenance artifacts tied to immutable reviewed source, and no tag/source
  write-back. Workflow preparation precedes T078/T079; actual publication requires completed,
  matching review/live/reproducibility evidence and any external human review. No publication
  is part of this amendment task.
- Findings on completed tickets receive remediation tickets and explicit ownership. Historical
  review/test evidence gaps remain gaps, not fabricated approvals. Blocker/Major acceptance
  needs explicit maintainer rationale in SECURITY-DECISIONS.md; this plan accepts none.

T155 does not replace T078/T079. Each review identifies its exact candidate; later changes
invalidate affected evidence. External human security review remains required before v1.0.0.
