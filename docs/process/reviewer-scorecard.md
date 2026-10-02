# Reviewer scorecard — Astra vs GLM-5.3-Flash

Tracks which single-gate reviewer found, missed or argued away each review
finding, so the reviewer matrix (`scripts/review-matrix.json`) is chosen on
this repo's evidence rather than public benchmarks. Maintainer decision
2026-09-28: collect from the next ticket through the end of the remaining
001-tor-route tickets, then evaluate.

**Evaluation period matrix:** `astra` = Codex `gpt-6-astra` at `high`;
`glm` = OpenCode `zai-coding-plan/glm-5.3-flash` at `xhigh` (native `max`).
If either changes mid-period, start a new period heading.

## How to record

After a ticket's driver commit lands, append its rows in the ticket's
`docs: mark TNNN done` follow-up commit — never in the ticket's own staged
candidate, so the scorecard neither consumes `files_budget` nor enters the
review scope.

- **Rounds table:** one row per review round, both verdicts, even when both
  are clean. Clean-vs-clean rounds are the denominator for miss rates.
- **Findings table:** one row per distinct Blocker/Major/Minor raised by
  either reviewer (merge duplicates that describe the same defect).
  - `astra` / `glm`: `found` (raised it) · `missed` (silent on it) ·
    `dismissed` (examined the same risk and argued it away — record the
    claim in the note; this is a worse miss than silence).
  - `disposition`: `fixed` (confirmed real and repaired) ·
    `false-positive` (falsified — give the falsifying fact) · `overridden`
    (maintainer override; link the `SECURITY-DECISIONS.md` entry if any).
  - A later-round finding that an earlier round's reviewers had the chance
    to catch counts as `missed` for them in that earlier round too: add a
    row for the earlier round.
- Nits and style comments are not rows.

## Period 1 (from 2026-09-28): astra high · glm-5.3-flash max

Tool-control change inside Period 1, after T126: GLM's `stargate-review` bash
allowlist was widened from git read commands only to read-only inspection
(`ls`, `cat`, `head`, `tail`, `wc`, `grep`, `sha256sum`, `diff`,
`git ls-files`, `git cat-file`, `git blame`). The matrix model and effort are
unchanged, so the period continues. GLM rows from the next ticket on are
recorded under the widened allowlist.

### Rounds

| Date | Ticket | Round | astra | glm |
|---|---|---|---|---|
| 2026-09-28 | T126 | 1 | REWORK (1 Major, 2 Minor) | APPROVE-WITH-FIXES (2 Minor) |
| 2026-09-28 | T126 | 2 | ESCALATE (1 Major) · 3 min | APPROVE (0) · 8 min |
| 2026-09-28 | T126 | 3 (refine) | APPROVE (0) · 2 min | APPROVE (0) · 11 min |
| 2026-09-28 | T176 | 1 | APPROVE-WITH-FIXES (1 Minor) | APPROVE-WITH-FIXES (1 Minor) |
| 2026-09-28 | T176 | 1 (post-fix re-review) | APPROVE (0) | APPROVE (0) |
| 2026-09-29 | T192 | 1 | APPROVE (0) | APPROVE (2 Minor, record-only) |
| 2026-09-29 | T183 | 1 | REWORK (2 Major) | APPROVE (0) |
| 2026-09-29 | T183 | 2 | ESCALATE (1 Major) | APPROVE (0) |
| 2026-09-29 | T183 | 3 (refine) | APPROVE (0) | APPROVE (1 Minor) |
| 2026-09-29 | T186 | 1 | REWORK (1 Major) | APPROVE-WITH-FIXES (2 Minor) |
| 2026-09-29 | T186 | 2 | APPROVE (0) | APPROVE (0) |
| 2026-09-29 | T188 | 1 | REWORK (1 Major) | APPROVE (1 Minor) |
| 2026-09-29 | T188 | 2 | APPROVE (0) | APPROVE (0) |
| 2026-09-30 | T188 | 2 (post-gitleaks rename re-review) | APPROVE (0) | APPROVE-WITH-FIXES (1 Minor) |
| 2026-09-30 | T188 | 2 (post-fix re-review) | APPROVE (0) | APPROVE (0) |
| 2026-09-30 | T188 | 2 (ticket-note re-review) | APPROVE (0) | APPROVE (0) |
| 2026-09-30 | T187 | 1 | REWORK (2 Major) | APPROVE (3 Minor) |
| 2026-09-30 | T187 | 2 | APPROVE-WITH-FIXES (1 Minor) | APPROVE (1 Minor) |
| 2026-09-30 | T187 | 2 (post-fix re-review) | APPROVE (0) | APPROVE (1 Minor) |
| 2026-09-30 | T193 | 1 (source: developer report; verdict files lost to driver defect) | REWORK (1 Major) | APPROVE (2 Minor) |
| 2026-09-30 | T193 | 2 (escalated at cap) | ESCALATE (1 Major) | REWORK (2 Major, 2 Minor) |
| 2026-09-30 | T193 | 3 (refine re-review; counter reset to 1) | REWORK (1 Major) | APPROVE (0) |
| 2026-09-30 | T193 | 4 (refine round 2) | APPROVE (0) | APPROVE (0) |
| 2026-09-30 | T194 | 1 | REWORK (1 Major) | APPROVE (0) |
| 2026-09-30 | T194 | 2 | APPROVE-WITH-FIXES (1 Minor) | APPROVE (0) |
| 2026-09-30 | T194 | 2 (post-fix re-review) | APPROVE (0) | APPROVE (1 Minor) |
| 2026-09-30 | T184 | 1 | APPROVE (0) | APPROVE (1 Minor) |
| 2026-10-01 | T185 | 1 | REWORK (1 Major, 1 Minor) | APPROVE (1 Minor) |
| 2026-10-01 | T185 | 2 | REWORK (1 Major) | APPROVE (0) |
| 2026-10-01 | T185 | 3 (refine re-review; counter reset to 1) | APPROVE (0) | APPROVE (0) |
| 2026-10-01 | T195 | 1 | APPROVE (1 Minor) | APPROVE (0) |
| 2026-10-02 | T196 | 1 | REWORK (1 Major, 1 Minor) | APPROVE (2 Minor) |
| 2026-10-02 | T196 | 2 (second launch; the first failed on a GLM provider timeout and imported no verdicts) | APPROVE (0) | APPROVE (0) |

T126 durations are wall-clock from verdict-file and launcher-log mtimes. Round 1 was not measured per reviewer; the review set took 15–19 min. GLM's review-role bash allowlist was git-only in every round, and its round-1 and round-2 verdicts both report most inspection commands rejected; see the allowlist change that follows T126.

### Findings

| Date | Ticket | Round | Sev | Finding | astra | glm | Disposition | Note |
|---|---|---|---|---|---|---|---|---|
| 2026-09-28 | T126 | 1 | Major | Live test's SIGINT/SIGTERM handler outlives the test; a later signal can tear down/exit under the next suite | found | missed | fixed | stoppable `t126TrapSignals`, stop registered to run after compose-down |
| 2026-09-28 | T126 | 1 | Minor | Blocking control-port reads bypass the advertised phase deadlines (bounded only by the 45-min suite ctx) | found | missed | fixed | per-operation sessions bounded by min(phase, 15 s); hermetic hung-transport test |
| 2026-09-28 | T126 | 1 | Minor | Principal isolation failure omits the DP/tor diagnostics acceptance #1 requires | found | missed | fixed | forensics on every live fatal path; red re-capture shows both sections |
| 2026-09-28 | T126 | 1 | Minor | Ticket Notes claim T182 "filed" while no T182 file is in the tree | missed | found | fixed | reworded; T182 lands in the `docs:` follow-up |
| 2026-09-28 | T126 | 1 | Minor | Ticket helper-reuse list omits `t059TerminalStreamStates`, which the test uses | missed | found | fixed | doc-only |
| 2026-09-28 | T126 | 2 | Major | Round-2 signal regression self-SIGTERMs the shared `go test` process; under `-tags docker` sibling suites' retained handlers `os.Exit(1)` mid-run | found | dismissed | fixed (round 3) | glm: "the only hermetic signal handler in this module is T126's own" — true only without `-tags docker`; confirmed locally: a leaked sibling-style handler kills the round-2 binary, the round-3 subprocess test survives |
| 2026-09-28 | T176 | 1 | Minor | Ticket integrity record claims the no-unzip refusal precedes creation of the download directory; `mktemp -d` runs first and the EXIT trap removes it | found | found | fixed | doc-only reword; both reviewers' evaluation probes pass |
| 2026-09-29 | T192 | 1 | Minor | Acceptance 1 cites workflow.md "step 2"; the developer rule lives in step 3 | found | found | not fixed (acceptance immutable post-landing) | astra noted it under ACCEPTANCE, not FINDINGS; change landed in the correct passage |
| 2026-09-29 | T192 | 1 | Minor | Skill residue sentence "if it cannot load the skill, it follows this file" reads self-contradictory | missed | found | open (clarity only) | no false capability claim; wording left as reviewed |
| 2026-09-29 | T183 | 1 | Major | Named skip absent from verify output: the capability-gated DNS-leak test in the mixed `tests/integration` package was only an anonymous `skip=N` (acceptance 4) | found | dismissed | fixed | glm: "capability-honest cadence… per-test skips counted in the package tail" = MET; fix: `go-workspace-gate.py` names every `test PASS:`/`test SKIP: … — reason`, regression in verify_discovery (budget 5→7 maintainer-authorised) |
| 2026-09-29 | T183 | 1 | Major | Tests-first red/green command ran a gitignored script (`target/runs/T183/probe.sh`), so the experiment was not reviewable/reproducible | found | dismissed | fixed | glm saw it and filed it as a "recommended follow-up", not a finding; fix: self-contained inline `bash -c` probe in the evidence |
| 2026-09-29 | T183 | 2 | Major | Inline probe still ran the unidentified local image `t165-qemu11:local` (no recipe, no digest) | found | missed | fixed | ESCALATE → maintainer refine: acceptance 5 requires a public image by digest; re-recorded in `debian@sha256:a99cfc51…` (trixie-slim) |
| 2026-09-29 | T183 | 1 | Minor | `t034BuildDP`'s `os.MkdirTemp("", "t034-dp")` is never removed; a DP binary accumulates in /tmp per privileged run | missed | missed | open | code unchanged since round 1; raised in round 3 |
| 2026-09-29 | T183 | 2 | Minor | (same `t034BuildDP` temp-dir leak) | missed | missed | open | |
| 2026-09-29 | T183 | 3 | Minor | (same `t034BuildDP` temp-dir leak) | missed | found | open | test-hygiene Minor under an APPROVE set; not fixed post-approval |
| 2026-09-29 | T186 | 1 | Major | Live probe replaced each negative navigation in the same tab after ≤4 s and never required a terminal result, so a delayed fallback could be cancelled by the test itself | found | missed | fixed | glm called acceptance 3 met on the same evidence; fix: one preserved tab per request, label-bound terminal error required, `delayed-null` (RED, destination capture) and `hung-proxy` (RED, incomplete) falsifiers, red/green re-recorded |
| 2026-09-29 | T186 | 1 | Minor | THREAT-MODEL residue named only the "sink treated as hostname" branch, omitting descriptor rejection → default (system) proxy with the destination name | missed | found | fixed | doc-only; glm's evaluation probe passes |
| 2026-09-29 | T186 | 1 | Minor | router.js comment and THREAT-MODEL claimed no process "root included" can listen at the sink; root can replace `/dev/null` | missed | found | fixed | reworded to the unprivileged boundary; both evaluation probes pass |
| 2026-09-29 | T188 | 1 | Major | Live probe exercised granted-access routing only in permanent private mode; acceptance 4 also needs ordinary windows with access | found | missed | fixed | glm called acceptance 4 met; fix: `ordinary-with-access` live scenario (credential-bearing SOCKS for every onion spelling, no other surface, Direct loads, no warning), green re-recorded |
| 2026-09-29 | T188 | 1 | Minor | Tamper check gated on private-window access on an unevidenced "proxy.settings needs access" claim | missed | found | fixed | falsified live: Gecko requires access only for `set`; gate dropped, readable-without-access asserted live and in a unit test |
| 2026-09-30 | T188 | 2 | Minor | THREAT-MODEL cited the pre-rename candidate package/report while ticket Note 7 named the committed package | missed | found | fixed | doc-only APPROVE-WITH-FIXES; both now cite the committed package with the superseded candidate qualified |
| 2026-09-30 | T187 | 1 | Major | `stargate status` reported a failed read, and the window while the initial ReloadTokens RPC was outstanding, as NONE ("no delivery attempted") | found | found (Minor; exec-failure half only) | fixed | PENDING now published before the RPC; absent file is UNKNOWN/50, unreadable is unavailable/20; held-DP and stubbed-docker regressions failed before the fix |
| 2026-09-30 | T187 | 1 | Major | A failed status replacement left an obsolete PENDING readable indefinitely after a terminal stale refusal | found | missed | fixed | failed write withdraws the old value and a background republisher writes the latest state; obstacle-injection regression failed before the fix |
| 2026-09-30 | T187 | 1 | Minor | Quickstart stale-conflict recovery hard-coded the default-project physical DP volume name | missed | found | fixed | resolved by Compose project + volume labels; exercised in the live rerun |
| 2026-09-30 | T187 | 1 | Minor | New `scripts/subcommands/status` had no gate coverage (not in verify.sh shell-quality discovery; no contract test) | missed | found | partly fixed | stubbed-docker JUnit case now covers vocabulary and exit codes; verify.sh discovery is outside the 14-path budget (glm re-raised in round 2; astra recorded it as advisory) and was reported as a follow-up |
| 2026-09-30 | T187 | 2 | Minor | Quickstart, data-model and comments claimed an in-flight delivery is never UNKNOWN, but a failed PENDING write leaves it UNKNOWN | found | missed | fixed | doc/comment-only APPROVE-WITH-FIXES; astra's text probe passes |
| 2026-09-30 | T187 | 2 (post-fix) | Minor | `stargate status` has no timeout on its `docker compose exec` read; a daemon wedged after preflight blocks it without output | missed | found | follow-up | outside the 14-path budget; reported to the orchestrator with the verify.sh discovery item |
| 2026-09-30 | T193 | 1 | Major | A child ignoring SIGTERM outlives the timeout in both `bounded` branches | found | missed | fixed | source: developer report; verdict files lost to driver defect. Group SIGKILL after a 1s grace; TERM-ignoring stub cases |
| 2026-09-30 | T193 | 1 | Minor | `command -v timeout` accepts a non-GNU `timeout` that signals only its direct child | missed | found | fixed | source: developer report; verdict files lost to driver defect. GNU detected via `timeout --version`; non-GNU stub cases |
| 2026-09-30 | T193 | 1 | Minor | The ticket raised its own files_budget (8 -> 9) inside the change under review | missed | found | overridden | source: developer report; verdict files lost to driver defect. Maintainer accepted the raise under the standing no-deferral rule (ticket §Notes) |
| 2026-09-30 | T193 | 1 | Minor | `docker compose version` preflight unbounded | missed | missed | fixed | source: developer report; verdict files lost to driver defect. Earlier-round row for the round-2 Minor below |
| 2026-09-30 | T193 | 2 | Major | Tests-first record did not evidence the discovery red: the retained red's pre-fix patch already contained the verify.sh fix | found | found | fixed | maintainer refine: red re-recorded against the untouched baseline (only the two test files staged), labelled a re-recording in ticket §Notes |
| 2026-09-30 | T193 | 2 | Major | GNU-`timeout` branch: post-timeout `kill -KILL -- "-$tpid"` reported a no-op; mixed tree (direct child obeys SIGTERM, descendant ignores it) untested | missed | found | false-positive | a re-runnable `term=mixed` case now exercises it and passes on all three PATH variants; GNU `timeout` observed as its own process-group leader (pgid == its pid) |
| 2026-09-30 | T193 | 2 | Minor | `docker compose version` preflight unbounded | missed | found | fixed | bounded like the other calls; `version` stub hang cases |
| 2026-09-30 | T193 | 2 | Minor | Live-residue evidence not reachable from the review candidate (`target/` gitignored) | missed | found | fixed | live results quoted in ticket §Notes |
| 2026-09-30 | T193 | 2 | Major | Early exit of a bounded call's direct child leaves a descendant holding stdout, so the read can stay open | missed | missed | fixed | earlier-round row for the round-3 Major below |
| 2026-09-30 | T193 | 3 | Major | Early exit of a bounded call's direct child leaves a descendant holding stdout, so the read can stay open | found | dismissed | fixed | glm: "no known docker CLI/compose-plugin behavior exits while leaving a descendant holding stdout". Group KILL now runs whenever the call ends; `exec-early` stub cases (exit 20, no survivor) |
| 2026-09-30 | T194 | 1 | Major | A rejection imported while final verification runs is deleted unconsumed when that verification fails or the candidate drifts, so the round cap / escalation can still be bypassed | found | missed | fixed | glm's round-1 falsification covered only the sequential and passing-verify race paths. Every invalidation now takes the gate lock and consumes a valid REWORK/ESCALATE first; S16g/S16h race cases |
| 2026-09-30 | T194 | 1 | Minor | Review-history records are mis-framed when a verdict lacks a trailing newline (Codex `-o` output): the next `===` header is appended to its last line | missed | missed | fixed | found by the developer while consuming round 1 (no data lost, only framing). Both writers newline-terminate each file; S16i case |
| 2026-09-30 | T194 | 2 | Minor | workflow.md and a run-task.sh comment claimed every review-state retirement holds the launcher lock; only invalidation does | found | missed | fixed | comment/doc fix items applied verbatim; same-round re-review |
| 2026-09-30 | T194 | 2 (post-fix) | Minor | Superseded red record 1 is internally inconsistent: its patch should fail S16i but its output omits S16i | missed | found | false-positive | that patch's S16i fixture used `truncate -s -1` on a verdict ending in a blank line, which leaves a trailing newline, so S16i legitimately passed against it (the vacuity was why the red was re-recorded) |
| 2026-09-30 | T184 | 1 | Minor | Rollback-proxy readiness wait in the release-cadence repro test is a fixed 5 s (50×0.1 s); a slow python3 start fails an honest tree with "rollback proxy did not start" | missed | found | open | fail-closed, release cadence (STARGATE_VERIFY_REPRO=1), recoverable by rerun; not fixed in the approved candidate; reported to the orchestrator |
| 2026-10-01 | T185 | 1 | Major | Lock omitted the arm64 closure: brotli4j selects `native-linux-aarch64` through a Maven `<os>` profile, so an arm64 image build fails closed on unlisted artifacts | found | missed | fixed | confirmed; aarch64 profile-activation recording added exactly the jar + POM; test requires both platforms' arch-selected entries |
| 2026-10-01 | T185 | 1 | Minor | THREAT-MODEL §5.9 not updated with the Maven lock mechanism and its exclusions | found | missed | fixed | budget 8→9 maintainer-authorised; maintainer-edited arm64 wording |
| 2026-10-01 | T185 | 1 | Minor | Static override tripwire misses `-s`/`--settings` (a settings file can carry resolver properties) | missed | found | fixed | glm marked it optional; fixed at the maintainer's request (also `-gs`/`--global-settings`) |
| 2026-10-01 | T185 | 2 | Major | arm64 closure not build-confirmed, and the platform assertion caught a deleted but not a corrupted arm64 Brotli entry | found | dismissed | fixed | glm: arm64 gap "fail-closed, disclosed, and environment-blocked (→ follow-up)". Fix: `ARM64_ONLY` reviewed digests in the test (zeroed-digest probe fails). The maintainer-time-boxed real `--platform linux/arm64` build failed on emulation (TLS handshake under nested TCG), so maintainer refine: Acceptance 1 states arm64 is emulation-derived, not build-confirmed |
| 2026-10-01 | T195 | 1 | Minor | `geckoNotificationSchemaMockRejectsRequireInteraction` exercises only the test mock, so no production mutation falsifies it | found | missed | dismissed | mock-calibration test, deliberately standalone so the schema gate is not vacuous; astra confirmed other tests (`failureNotificationIsDisplayableOnEveryFailureShape`, the strengthened notification tests, live `hardening-failure-notification-displayed`) catch a restored `requireInteraction`. Done at d79c885 |
| 2026-10-02 | T196 | 1 | Major | Observer relay: the repeat-sample window was trusted as server-registered after `SUBSCRIBED` + 1 s with no received event, so a delayed registration could let a duplicate pass while the report claimed continuous overlapping windows | found | missed | fixed | glm accepted the continuity claim (its dropped items covered carry ordering and THREAT-MODEL wording, not registration). Maintainer decision 2026-10-02 (option A tightened): every silent window in an event phase must first receive the transition; no-event phases disclosed as resting on the 1 s allowance; continuity claim removed; delayed-registration falsifier added. Done at 6228d4a |
| 2026-10-02 | T196 | 1 | Minor | `uds_dial` lost the old `timeout 2`; a wedged peer (full accept queue) blocks connect(2) and hangs the gate | found | found | fixed | `timeout 5` around the dialer; exit 124 fails the row and never counts as EACCES; fixtures S8/S9 saturate real Unix accept queues |
| 2026-10-02 | T196 | 1 | Minor | Dialer comment mislabelled exit 3 as "no socket"; a missing path exits 1 (ENOENT), exit 3 is a socket(2) failure | missed | found | fixed | comment corrected in round 2 |

T182 round 1: both APPROVE, no findings. GLM recommended call-site shape
guards for the shared partition helper (a swapped argument would still pass);
not adopted — call sites verified correct and the helper is vector-pinned.

T192 recommended follow-ups (not rows): glm flagged `AGENTS.md:131` and astra
`docs/process/analysis.md:111` as developer-role wording T192 made stale; both
fixed in the `docs: mark T192 done` commit (no-deferral). Astra's note that
analysis.md's separate-redteam wording predates the single gate is pre-existing.

T186: round 1 astra REWORK / glm APPROVE-WITH-FIXES, round 2 both APPROVE.
Durations were not measured; the round-1 set is archived in gitignored
`target/runs/T186-r1.verdict`. glm's recommended follow-up (record monotonic
run timestamps in evidence JSON so feasibility-before-implementation order is
mechanically provable) is not a row. The maintainer-directed D5/D4
feasibility matrix ran before the fix and again on the round-2 probe.

T187: round 1 astra REWORK (2 Major) / glm APPROVE (3 Minor); round 2 astra
APPROVE-WITH-FIXES (1 doc Minor) / glm APPROVE (1 Minor), then a same-round
re-review of the comment/doc fix: both APPROVE (glm 1 new Minor). The first
round-2 launch failed closed because the GLM verdict had a malformed FINDINGS
field; the launcher was re-run and no verdict was transcribed. Durations were
not measured. The round-2 pre-fix verdict archive was overwritten by the
post-fix set; its rows above come from the imported verdicts as read in the
session.

T193: four review sets. Round 1's verdict files were deleted unarchived by
`run-task.sh`'s `invalidate_reviews` when the developer changed the snapshot
before re-invoking the driver, so its rows come from the developer's report
(source: developer report; verdict files lost to driver defect); the
maintainer authorised a hand correction of the round counter to 2. Round 2
(archive preserved as gitignored `target/runs/T193-prerefine-r2.verdict`)
escalated at the cap; astra also noted the prior-round verdict was absent
from its handoff (driver defect, not a row). The maintainer chose refine;
rounds 3–4 are the refined cycle (driver archives `T193-r1.verdict`,
`T193-r2.verdict`). Durations were not measured. glm recommended aligning
`init`'s `command -v timeout` detection with `status` (out of T193's scope);
not a row, reported to the orchestrator.

T185: round 1 astra REWORK (1 Major, 1 Minor) / glm APPROVE (1 Minor);
round 2 astra REWORK (1 Major) / glm APPROVE; after the maintainer's refine
the round counter was reset (`run-task.sh --reset`, history archived in
gitignored `target/runs/T185.review-history`), and the fresh review (recorded
here as round 3) was both APPROVE with no findings. Durations were not
measured. Both reviewers relied on the mechanical GREEN report and the
recorded red/green evidence. Astra independently fetched the arm64 brotli4j
artifacts from Central and matched the lock. glm's round-3 recommended
follow-ups (not rows): a tripwire for MAVEN_OPTS/MAVEN_ARGS exports on
build lines, and the compose image-output digest once the CP image changes
(manual promotion). Reported to the orchestrator.

T184: round 1 both APPROVE (glm 1 Minor, open). Durations were not
measured. Both reviewers relied on the mechanical GREEN report and the
recorded red/green evidence; neither ran builds. glm's recommended follow-ups
(not rows): name the T184 mechanism in `specs/000-architecture/spec.md`'s
Tor row (glm itself judged the existing sentence literally true), and note
that the repro gate needs python3 on the release host. Reported to the
orchestrator.

T194: round 1 astra REWORK (1 Major) / glm APPROVE; round 2 astra
APPROVE-WITH-FIXES (1 doc Minor) / glm APPROVE, then a same-round re-review
of the comment/doc fix: both APPROVE (glm 1 Minor, falsified). The first
re-review launch failed closed because the GLM verdict had a malformed
FINDINGS field; the launcher was re-run and no verdict was transcribed.
Durations were not measured. Every imported set is in gitignored
`target/runs/T194.review-history` (the round-1 records there show the
framing defect fixed in round 2). glm's round-1 recommended follow-ups (not
rows): after a COMMIT handoff, staging the requested paths changes the
snapshot and forces a fresh review (pre-existing); `--reset` records a local
date in `aborted_attempts` while the history uses UTC (cosmetic). Reported to
the orchestrator.

T188: round 1 astra REWORK / glm APPROVE (1 Minor); round 2 both APPROVE,
then three same-round re-reviews of changed snapshots: a behaviour-neutral
rename after the pre-commit gitleaks hook flagged a generic-api-key false
positive in router.js (hooks never skipped), glm's doc-only fix item, and a
ticket-note rewording after the same false positive in the ticket text.
Durations were not measured. Both reviewers recommended that the
pre-existing `background/hardening.js` WebRTC notification defect found live
in T188 (Firefox rejects `requireInteraction`, so it is never shown) get its
own remediation ticket; not a row, reported to the orchestrator.

T183: rounds 1–2 then the refine re-review (round counter reset to 1 by
`run-task.sh --reset`; recorded here as round 3). Per-reviewer durations were
not measured. Round-1/2 verdicts are archived in gitignored
`target/runs/T183-r1.verdict` and `T183-r2.verdict`. The recorded
red/green experiment now runs in a public digest-pinned image; the earlier
local-image runs remain only under gitignored `target/runs/T183/`.

T176: first ticket under the widened GLM allowlist. GLM's verdicts record
effort `xhigh` (the period header says `max`); Astra `high`. Both still report
shell execution beyond the allowlist as denied, so their test/verify evidence
came from the mechanical report. Per-reviewer durations were not measured.

## Baseline (before Period 1 — not counted in the evaluation)

Matrix at the time: `astra` at `low`; `glm` = full `zai-coding-plan/glm-5.3`
at `max`. T181 attempt 1 artefacts: `target/runs/T181-attempt-1/`
(gitignored).

| Date | Ticket | Round | Sev | Finding | astra (low) | glm-5.3 full | Disposition |
|---|---|---|---|---|---|---|---|
| 2026-09-28 | T181 a1 | 1 | Major | 5-min readiness deadline not enforced across blocking transport calls (stall runs to the 8-min suite ctx) | found | missed | fixed |
| 2026-09-28 | T181 a1 | 1 | Major | Readiness contract test satisfied by its own diagnostic literal; recorded red fails on its own source | found | missed | fixed |
| 2026-09-28 | T181 a1 | 2 | Major | Deadline regression bypasses the real probe; no transport-level stall coverage | found | missed | fixed (attempt 2, acceptance #5) |

T181 attempt 2 round 1: both APPROVE, no findings.

**Replay of T181 attempt-1 round-1 code (2026-09-28):** identical
candidate and handoff (prior verdicts withheld), both GLM models at `max`,
two runs each. Verdicts, handoff, candidate patch and launcher:
`target/runs/T181-replay/` (gitignored).

| Model | Run | Verdict | Deadline Major | Self-match Major | Minutes |
|---|---|---|---|---|---|
| glm-5.3 | A | REWORK | dismissed ("check at :134 bounds it") | found | 6.0 |
| glm-5.3 | B | APPROVE | missed | missed (called the contract "non-vacuous") | 13.1 |
| glm-5.3-flash | A | REWORK | dismissed (same claim) | found | 8.6 |
| glm-5.3-flash | B | REWORK | missed | found (+ red-evidence Minor) | 7.5 |

Signal from the replay (one ticket, n=2 per model — suggestive only):
Flash matched or beat full GLM-5.3 on the test-integrity defect, and no GLM
run caught the blocking-call deadline defect that Astra caught at `low`.
