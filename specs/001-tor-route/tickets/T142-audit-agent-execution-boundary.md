---
id: "T142"
title: "Make agent execution-boundary claims demonstrable"
status: done
created: "2026-09-12"
last_updated: 2026-09-13
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T096", "T139", "T156"]
parallel: false
files_budget: 24
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T096"
tests_first: []
reviews: { round: 4, date: 2026-09-13, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T142: Make agent execution-boundary claims demonstrable

## Context

Finding 20260727-010: ordinary OpenCode `--auto` agents are not constrained by
reviewer-specific denies. The maintainer's 2026-09-13 instructions refine this
ticket in two steps: (1) use exactly two reviewers with isolated conversation
contexts — one OpenCode full GLM and one Codex Astra — and remove the added
Docker requirement; (2) implement the reviewer as a SINGLE GATE with support
for OpenCode and Codex: one launcher invocation, one review pass covering
correctness and adversarial security together, one fix step. The split
codereview-then-redteam phases are removed. This supersedes the container
acceptance introduced in 755a1c3; it does not amend Constitution VIII, whose
fresh independent review contexts and exact-candidate binding remain required —
the gate's two independent contexts provide them.

## Analysis

- **Must hold:** one `scripts/review-task.sh <id>` invocation starts two fresh
  native CLI sessions — OpenCode full GLM-5.3 at xhigh (native provider max)
  and Codex Astra at xhigh — each blind to the implementer's conversation and
  peer verdicts, each auditing correctness AND adversarial security/privacy in
  the same pass. Reviewers never delegate.
- **Gated:** the native launcher supplies distinct candidate copies and output
  paths, checks copies and live source against the same snapshot, retires any
  previous approval set before launching, and imports a complete
  identity-checked verdict set with the manifest written last. The strongest
  verdict in the set wins (ESCALATE > REWORK > APPROVE-WITH-FIXES > APPROVE);
  every verdict carries SUMMARY and FINDINGS. Driver regressions reject stale,
  missing, duplicate, partial and misidentified approvals.
- **Residue:** context separation is not a host security boundary. Native
  same-user processes can access host files, credentials and processes subject
  to their tool permissions. Separate copies prevent accidental interference;
  source hash checks detect persistent changes, not malicious write-and-restore.
  No credential, network, PID or filesystem containment is claimed.

## Acceptance

1. Document effective ordinary-agent and reviewer capabilities: global
   `opencode.json` permits ordinary shell/interpreter operations; `--auto`
   approves ask rules. Reviewer roles separately deny delegation and
   non-allowlisted shell actions. These maps are tool policy, not a sandbox.
2. Run exactly one `zai-coding-plan/glm-5.3` OpenCode reviewer at xhigh
   (provider reasoningEffort max) and one `gpt-6-astra` Codex reviewer at
   xhigh, BOTH running the single merged gate (`stargate-review`) in ONE
   pass. Every invocation is fresh, with no resume, fork or inherited
   implementation conversation. The retired phase argument is a hard usage
   error.
3. Use native CLI child processes with separate source copies, temporary paths
   and verdict channels. No Docker, namespace launcher or replacement
   containment setup. Preserve fail-fast reviewer permissions/no delegation;
   Codex runs without an OS sandbox, with read-only inspection instructions.
4. Add deterministic native CLI regressions for exact model/effort arguments,
   separate candidates, complete verdict import, process failure, source
   mutation rejection, stale-set retirement on re-launch, lock ownership under
   concurrent launches, and prior-round evidence surviving the round
   transition. No real credentials or model calls in contract tests.
5. Require both identities and snapshot-bound verdicts before driver advance —
   one gate for every ticket, `privacy_critical` included (the flag sharpens
   the security lane; it does not add a second dispatch). Run
   `scripts/verify.sh` and the single gate itself. Missing evidence remains
   pending; synthetic CLI tests are not real model approval.
6. Reconcile workflow, agent guidance and threat-model claims in the same
   change: the merged `stargate-review` role replaces the per-ticket
   `stargate-codereview` role (deleted); `stargate-redteam` remains the
   cumulative milestone/release sweep the Constitution names. Preserve
   historical approved commits.

## Out-of-scope

T136 routing implementation (already delivered in 3393309), deployed proxy
behavior, real exfiltration, host/container sandbox infrastructure or
broadening ordinary-agent permissions. The existing review_task_test.sh
container probes are replaced by native orchestration tests because the
maintainer explicitly removed containment from this ticket. Driver fixtures
update GLM effort to xhigh without weakening gates.

## Notes

The previous container implementation was unfinished and is superseded, not
approved or delivered. The intermediate two-phase native design (stash
`codex: stop T142 and resume T136`, restored 2026-09-13) was itself superseded
by the maintainer's single-gate order before any of its verdicts were used as
approval; stale review results must not be reused as approval.

Tests-first evidence for the single-gate restructure: the rewritten
`review_task_test.sh` (matrix shape, launcher usage, verdict channels) was run
against the restored two-phase scripts and failed — the matrix has no
`reviewers` list ("single gate requires exactly two reviewers: None") — then
passed after the implementation. The same new tests caught two real defects in
the launcher before any commit: (1) a failed re-launch left the previous
approval verdicts and manifest standing against an unchanged tree the driver
could still commit on — fixed by retiring the previous set when a new launch
starts; (2) a refused concurrent launch's cleanup rmdir'd the holder's empty
lock directory, letting a third launch through — fixed by assigning lock
ownership only after this process creates the lock. `run_task_test.sh` (12
scenarios, single-gate review) and `required_coverage_test.sh` (12 tests) are
green.

GLM effort mapping is grounded in the provider's
[Deep Thinking documentation](https://docs.z.ai/guides/capabilities/thinking):
Coding Plan xhigh maps to max. OpenCode's installed GLM-5.3 catalog has no
built-in variants, so the runner supplies an explicit xhigh variant with
`reasoningEffort: max`.

The first native launch exposed OpenCode's silent fallback from subagent-only
roles to its ordinary build agent. Both child sessions were stopped and no
verdict was imported. A new mode-selection regression failed before adding
invocation-local `mode: all` for the gate role. The installed CLI's resolved
configuration confirms that this preserves reviewer task/shell/edit denies
while making the role selectable by `opencode run`.

Codex's native read-only option failed before inspection because its built-in
bubblewrap could not configure loopback. In accordance with the maintainer's
no-wrapper instruction, the native invocation uses `-s danger-full-access`; no
OS sandbox is claimed. Separate-copy hash checks detect persistent source
mutations; reviewer instructions alone cannot constrain a malicious native
process.

Round 1 of the real single gate (snapshot 384ff96f…, OpenCode GLM-5.3 xhigh +
Codex Astra xhigh, both imported manifest-last) returned REWORK from BOTH
reviewers: one stale two-phase sentence survived in workflow.md's §"Adversarial
passes" capability bullet ("one Astra at medium for correctness or xhigh for
privacy/security") — both reviewers caught it; and Astra found a real driver
race (AUDIT-EVASION): a concurrent review-set replacement during the driver's
final verification could be outrun by the cached APPROVE and commit, because
target/ is gitignored and invisible to the source snapshot. The round-2 fix
re-validates the review set after final verification and refuses any commit
whose set was replaced or whose aggregate verdict changed; the regression
(scenario S11 in run_task_test.sh, booby-trapped verify + mid-verification
replacement) failed before the fix and passes after. The rework path also
stopped misreporting its deliberate round transition as "snapshot changed".

Round 3 (the round_cap: 3 cap) split again — GLM APPROVE, Astra ESCALATE — and the
five-way escalation menu was surfaced to the maintainer on 2026-09-13. The
maintainer authorized exactly one more round; the authorization is recorded
here rather than as a silent cap bypass. Astra's round-3 findings, none
overridden: (1) [Major] S12 proved lock-acquisition refusal but not that the
driver retains the lock through trailer capture and commit — the mandated
commit-boundary regression (with an early-unlock mutation control) was absent;
(2) [Major] the driver acquired the gate lock without owner-tracked
cleanup — catchable termination (SIGTERM) inside the critical section
stranded the lock for every later launcher and driver invocation until manual
removal; (3) [Minor] the S11 race scenario reused the lint scenario's sandbox
tag and the harness banner under-reported the scenario count.

Round 2 of the real gate (snapshot e0e8513d…) split: GLM APPROVED (both
round-1 items satisfied, security lane clean); Astra returned REWORK — its
round-1 race finding persisted because the round-2 post-verification
re-validation still left a window between validation and git commit where a
launcher retirement could land. The round-3 fix closes it by mutual exclusion:
the driver now acquires the launcher's own gate lock
(`target/runs/<id>.review.lock`) for the whole approval-consumption critical
section — final validation, trailer generation, focused commit and the done
transition — releasing it on every exit path. A launcher mid-flight makes the
driver refuse and retry; a driver mid-commit makes the launcher fail closed;
a completed replacement is what the in-lock validation reads. Regression S12
(run_task_test.sh: held lock → driver refuses without consuming the approval,
then commits cleanly after release) failed before the fix and passes after;
S11 (mid-verification replacement) is retained. Process note, recorded
honestly: the round-2 fixes were applied before the driver consumed the
round-2 verdict, so the driver's snapshot guard would have discarded it; the
deterministic REWORK transition (archive to T142-r2.verdict, round bump,
in-progress) was replicated by hand so round 3 still receives the full
disposition protocol.

Round 4 (maintainer-authorized) closed all three round-3 findings, each
regression-first: (1) the critical-section lifetime is now pinned by S13 in
review_task_test.sh — a git shim holds the driver exactly at `git commit`
while a REAL launcher invocation is refused on the held lock, the commit that
lands carries exactly the authorizing set's trailers, and an executed
early-unlock mutation of the driver (release right after the in-lock
validation, staged into the reviewed candidate) is ADMITTED at the boundary —
proving the refusal assertion is load-bearing, not decorative; (2) the driver
now owns its gate lock with owner-tracked EXIT/INT/TERM cleanup (a process
that failed to acquire never removes another's lock; `--reset` clears a
stranded lock as the documented manual recovery) — S14 pauses the driver at
the commit boundary, SIGTERMs it, and asserts the lock is released, nothing
committed, the ticket stays in-review and the gate is immediately reusable;
(3) the race scenario's sandbox tag is unique (s11race) and the harness
banner reports the true scenario count (14). Astra's "incomplete replacement"
case remains covered by the pre-existing retry scenario (failed re-launch
leaves no manifest and cannot commit). All three workflow suites and
scripts/verify.sh are GREEN.

Constitution Check: VIII's fresh independent reviews and exact-candidate
binding remain required and are provided by the gate's two independent
contexts covering both review lanes. V requires honest capability limits;
removing unsupported containment claims conforms to that requirement. VII
requires regression-first workflow changes (evidence above). No constitutional
amendment or accepted security finding is implied; the constitution's
milestone clause still names `stargate-redteam`, which remains as the
cumulative sweep role.
