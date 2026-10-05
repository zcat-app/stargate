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
| 2026-10-02 | T191 | 1 | REWORK (1 Major) | APPROVE-WITH-FIXES (1 Minor) |
| 2026-10-02 | T191 | 2 | APPROVE (0) | APPROVE (2 Minor) |
| 2026-10-02 | T198 | 1 | REWORK (1 Major) | APPROVE (1 Minor) |
| 2026-10-03 | T198 | 2 | APPROVE (0) | APPROVE (0) |
| 2026-10-03 | T203 | 1 | REWORK (2 Minor) | APPROVE-WITH-FIXES (1 Minor) |
| 2026-10-03 | T203 | 2 | APPROVE (0) | APPROVE (0) |
| 2026-10-03 | T203 | 2 (post-hook metadata and FR-012 correction refresh) | APPROVE (0) | APPROVE (0) |

| 2026-10-04 | T204 | 1 | APPROVE (0) | APPROVE (1 Minor) |
| 2026-10-04 | T204 | 1 (post-timeout-fix refresh) | APPROVE (0) | REWORK (1 procedural Major, 1 Minor) |

| Date | Ticket | Round | astra | glm |
|---|---|---|---|---|
| 2026-10-04 | T205 | 1 | APPROVE (0) | APPROVE-WITH-FIXES (1 Minor) |
| 2026-10-04 | T205 | 1 (post-doc-fix and own-orphan refresh) | APPROVE (0) | APPROVE (0) |
| 2026-10-04 | T205 | 1 (caller-environment disclosure refresh) | REWORK (1 procedural Major, 1 Minor) | APPROVE (0) |
| 2026-10-04 | T205 | 2 | APPROVE (0) | APPROVE (0) |

| Date | Ticket | Round | astra | glm |
|---|---|---|---|---|
| 2026-10-05 | T208 | 1 | REWORK (1 Major) | APPROVE (0) |
| 2026-10-05 | T208 | 2 | APPROVE (0) | APPROVE (0) |

| Date | Ticket | Round | astra | glm |
|---|---|---|---|---|
| 2026-10-01 | T155 (attempt 3) | 1 | REWORK (4 Major) | REWORK (1 Major, 2 Minor) |
| 2026-10-02 | T155 (attempt 3) | 2 | APPROVE-WITH-FIXES (1 Minor) | APPROVE (1 Minor) |
| 2026-10-02 | T155 (attempt 3) | 2 (post-doc-fix refresh) | REWORK (2 Major) | APPROVE (0) |
| 2026-10-03 | T155 (attempt 4) | 1 | ESCALATE (2 Major) | APPROVE (1 Minor) |
| 2026-10-05 | T155 | 1 | APPROVE-WITH-FIXES (1 Minor) | APPROVE-WITH-FIXES (1 Minor) |
| 2026-10-05 | T155 | 1 (post-doc-fix refresh) | REWORK (1 Major) | APPROVE (0) |
| 2026-10-05 | T155 | 2 (launch failed closed: Codex login rejected, no verdict imported) | – | – |
| 2026-10-05 | T155 | 2 | APPROVE (1 Minor) | APPROVE (1 Minor) |
| 2026-10-05 | T155 | 2 (post-Minor-fix refresh) | APPROVE (0) | APPROVE (0) |

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
| 2026-10-02 | T191 | 1 | Major | agent-task bundled `agent/$TICKET` at the run's starting commit: run-task.sh moves the agent onto the feature branch before implementing, so publish would push none of the task's work | found | missed | fixed | glm reviewed the publish job only for credential exposure. Maintainer decision 2026-10-02 (option 1): `git update-ref` to HEAD after the state commit, before bundling; temporary-repository regression runs the workflow's own commit/bundle bodies and failed on the round-1 workflow. Done at a046386 |
| 2026-10-02 | T191 | 1 | Minor | `deny /proc/*/net/**` also matches `/proc/sys/net/**`, so the somaxconn allow was dead and the profile comment and THREAT-MODEL claimed a grant the DP does not have | missed | found | fixed | allow deleted, docs state the read is denied and Go falls back to its built-in constant; t162 static check rejects any allow under `/proc/<x>/net/`. Deny globs unchanged (maintainer) |
| 2026-10-02 | T191 | 1 | Minor | publish parsed the untrusted bundle (`git bundle list-heads`, `git fetch`) in the step that held `GH_TOKEN` | missed | found | fixed | glm dropped it as a vulnerability (needs a git bundle/packfile CVE) but recommended the split; separate credential-free import step, enforced by `ci_inputs_test.sh` |
| 2026-10-02 | T191 | 1 | Minor | `ci_inputs_test.sh` "exactly one git push" rule matches per physical line; the real push spans continuation lines, so the count is satisfied by `git init --quiet "$RUNNER_TEMP/push"` and a relocated continuation-style push would pass | missed | missed | open | raised in round 2 (row below); present unchanged in round 1. No runtime consequence: the agent job holds a read-only, unpersisted token. Draft follow-up returned to the maintainer |
| 2026-10-02 | T191 | 2 | Minor | same push-count precision gap as the round-1 row above | missed | found | open | confirmed: the only regex hit in code lines is `agent-task.yml:359` (`git init`). Draft follow-up returned to the maintainer |
| 2026-10-02 | T191 | 2 | Minor | The bundle regression's red on the round-1 workflow is quoted in the ticket but not captured in `T191-tests-first.json` (ci_inputs_test.sh stops at its first failing assertion) | missed | found | open | the red exists only as a scratch log (`.scratch/tmp/T191/bundle-regression-red.log`) and the ticket quote; red is deterministic by construction. Draft follow-up returned to the maintainer |
| 2026-10-02 | T198 | 1 | Major | init's deny-drop check (`! cmp -s`) accepted every non-zero cmp status, so a comparison error (2) or a missing cmp (127) passed and the downgraded profile would load | found | missed | fixed | glm traced compile/load parity and the deny-strip but not the cmp status. Reachability on the supported host is negligible (diffutils is Essential on Ubuntu); the fail-open shape was real. Maintainer decision 2026-10-03: accept only cmp exit 1; cmp exit-2/127 fixtures, red on the round-1 init (both passed the boundary, exit 20). Done at 75fa66b |
| 2026-10-02 | T198 | 1 | Minor | A failed privileged read of the af_unix feature file (e.g. uncached sudo) was reported as "is not 'yes'", diagnosing a capable host as unsupported | missed | found | fixed | refusal was already fail-closed; the read failure now prints its own "cannot read … unverified" reason, asserted by the absent-feature fixture. Done at 75fa66b |
| 2026-10-03 | T203 | 1 | Minor | Positive finite-record fixtures used the production encoder, so matching domain-endianness errors in encoder and decoder could escape calibration | found | missed | fixed | independent literal 24-byte contract vector tests encoder and decoder separately; simultaneous big-endian domain mutation fails both subtests. Done at d8aa28c |
| 2026-10-03 | T203 | 1 | Minor | Current architecture inventory still claimed zero auxiliary containers and a pending T164 observer | found | missed | fixed | inventory now identifies tor-observer and the separate publisher process inside Tor. Done at d8aa28c |
| 2026-10-03 | T203 | 1 | Minor | Compose header retained the observer raw-control mount grant removed by the implementation | missed | found | fixed | header states the finite read-only tmpfs boundary; rendered Compose is byte-identical before and after. Done at d8aa28c |
| 2026-10-04 | T204 | 1 | Minor | Listener probe Docker commands can outlive its deadline | missed | found | fixed | Real six-second child discriminates missing timeout; helper defaults to5s and cleanup calls to15s. |
| 2026-10-04 | T204 | 1 | Minor | Positive HTTP probe can accept an extra loopback listener | missed | missed | fixed | Raised on refresh; original reusable verdict path lacked exact inventory, although the actual evidence assembler checked all retained rows. |
| 2026-10-04 | T204 | 1 (post-timeout-fix refresh) | Minor | Positive HTTP probe can accept an extra loopback listener | missed | found | fixed | Synthetic extra9000 RED; final host8/guest8 PASS; one fresh management-runtime case has exactly HTTP8080 plus Narayana. Final correction was human-authorized, not re-reviewed. |
| 2026-10-04 | T204 | 1 (post-timeout-fix refresh) | Major | Repeated full verification omitted after the probe-only fix | dismissed | found | overridden | Astra explicitly accepted the recorded user direction; GLM requested an explicit orchestrator waiver or full GREEN. User then directed commit and local merge, relying on T078/T079 cumulative gates. Historical37PASS/4SKIP/0FAIL remains pre-fix; interrupted full run is not GREEN. Procedural override, not a security-risk acceptance. |
| 2026-10-04 | T205 | 1 | Minor | Harness oracle suite lacks documented or gated invocation | missed | found | fixed | README now documents the must-pass manual preflight; three oracle tests passed. No new verify.sh discovery gate claimed. |
| 2026-10-04 | T205 | 1 | Minor | Popup-delivery regression bypasses the real status handler | missed | missed | fixed | Raised in the later caller-environment refresh; original test did not kill the bad-handler mutation. |
| 2026-10-04 | T205 | 1 (post-doc-fix and own-orphan refresh) | Minor | Popup-delivery regression bypasses the real status handler | missed | missed | fixed | The same coverage gap remained in this candidate. |
| 2026-10-04 | T205 | 1 (caller-environment disclosure refresh) | Minor | Popup-delivery regression bypasses the real status handler | found | missed | fixed | Real-handler bridge passes; assigning hardeningOk=false in the opt-in branch fails the repaired test. Mutation confined to scratch. |
| 2026-10-04 | T205 | 1 (caller-environment disclosure refresh) | Major | Complete final verification under corrected caller environment outstanding | found | dismissed | fixed | Procedural closure satisfied by actual full5 GREEN37/4/0. Severity and review-stage timing narrowed/disputed; GLM's unchanged-source full3 validity argument is supported. No production defect demonstrated. |
| 2026-10-05 | T208 | 1 | Major | Live-test delivery wait accepted an acknowledgement observed after its allowance expired | found | dismissed | fixed | `awaitDelivery` returned on exit 0 before its deadline check. GLM examined the expiry logic and called the allowance arithmetic bounded (its 6a and 7 marked MET). Confirmed by the orchestrator against the code; `TestT033GateRejectsLateAcknowledgement` and `TestT033GateStatusCallsAreBoundedByTheRemainingAllowance` failed on the reviewed code and pass after the fix. Test harness only; no production code. |
| 2026-10-01 | T155 (attempt 3) | 1 | Major | Fresh cumulative redteam record promised or cited as committed but absent from the candidate | found | found | fixed | Durable record written into the ticket. |
| 2026-10-01 | T155 (attempt 3) | 1 | Major | Principal foundation harness neither preserved nor bound by the recorded snapshot | found | missed | fixed | `t155_stack.py` and hashed results committed. |
| 2026-10-01 | T155 (attempt 3) | 1 | Major | F4 did not show same-target isolation across the device and site axes | found | missed | fixed | `partition_axes_test.go` with a production-mutant red. |
| 2026-10-01 | T155 (attempt 3) | 1 | Major | Surviving redteam findings had no remediation tickets | found | missed | fixed | T196, T197, T198 filed. |
| 2026-10-01 | T155 (attempt 3) | 1 | Minor | Wire-harness defect list omitted row R3 | missed | found | fixed | |
| 2026-10-01 | T155 (attempt 3) | 1 | Minor | README cross-reference named R4 instead of R-6 | missed | found | fixed | |
| 2026-10-02 | T155 (attempt 3) | 2 | Minor | README snapshot paragraph still described the five-file candidate | found | found | fixed | GLM rated it non-blocking; Astra returned APPROVE-WITH-FIXES. |
| 2026-10-02 | T155 (attempt 3) | 2 (post-doc-fix refresh) | Major | Live evidence had no TLS-resumption or traffic-counter publication assertion | found | missed | fixed | Attempt 4 added `wireprobe resume` and, after the next item, the real-hour `GetStatus` probe. GLM had approved the same candidate. |
| 2026-10-02 | T155 (attempt 3) | 2 (post-doc-fix refresh) | Major | New remediation owners blocked only T078, not T155 (Acceptance 6) | found | missed | fixed | Maintainer upheld it for T196 and T198. |
| 2026-10-03 | T155 (attempt 4) | 1 | Major | Claimed `GetStatus` coverage measured CP persistence, a separate data path | found | missed | fixed | Maintainer chose refine; authenticated real-hour probe with an active-hour-export mutant red. |
| 2026-10-03 | T155 (attempt 4) | 1 | Major | Approved filing plan conflicted with unchanged Acceptance 6 | found | missed | fixed | Maintainer replaced Acceptance 6 verbatim (refine). |
| 2026-10-03 | T155 (attempt 4) | 1 | Minor | Device, site and profile partition vectors had no committed independent provenance | missed | found | fixed | Python HMAC transcript added to the results record. |
| 2026-10-05 | T155 | 1 | Minor | Evidence omitted the two isolation limits the contract requires T155 evidence to state | found | missed | fixed | Sentence added to the README Evidence index. |
| 2026-10-05 | T155 | 1 | Minor | `partition_vector_provenance` transcript cited by the test was missing from the rewritten results record | missed | found | fixed | Dropped by the developer's rewrite of the record; re-executed (identical output) and restored. |
| 2026-10-05 | T155 | 1 (post-doc-fix refresh) | Major | `t155_stack.py` exited 0 on an interrupted or incomplete run (only `Exception` caught; no completion guard) | found | missed | fixed | GLM had walked every check call site in round 1 and approved twice. Mandatory-check completion guard with regression `test_t155_stack.py`; F2 carried forward by a mechanical comparison, no rerun. Present since attempt 3; earlier rounds of both reviewers missed it. |
| 2026-10-05 | T155 | 2 | Minor | Non-zero `docker compose down` exit ignored by the repaired entrypoint | found | missed | fixed | Fixed before commit, red before green; both reviewers had returned APPROVE. |
| 2026-10-05 | T155 | 2 | Minor | Mandatory-list drift guard did not cover a check recorded at module level | missed | found | fixed | Latent; test now requires none exists, with detector controls. |


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

T198: round 1 astra REWORK / glm APPROVE, round 2 both APPROVE. Durations were not
measured; round verdicts are archived in gitignored `target/runs/T198-r1.verdict` and `T198-r2.verdict`. The
developer's own pre-review findings (init's false fresh-install key note, folded as F1;
the Compose `subpath` floor, F2 Info) and the independent wording evaluation's items are
not reviewer rows. glm's round-2 recommended follow-up (re-record the docker-tier T162
leg against the strict round-2 gate on the next guest session) is not a row.

T203: round 1 Astra REWORK (2 Minor), GLM APPROVE-WITH-FIXES (1 Minor);
round 2 both APPROVE, followed by a same-round refresh with both APPROVE.
All three rounds/sets used actual Codex CLI **0.160.0**, model `gpt-6-astra`,
effort `high`, and OpenCode **1.18.33**, model `zai-coding-plan/glm-5.3-flash`,
effort `xhigh` (native `max`). Per-reviewer durations were not measured. Native
sets, verdicts and append-only history are retained in gitignored
`target/runs/T203/ordinary-round1/`, `ordinary-round2/`,
`ordinary-round2-refresh/` and `target/runs/T203.review-history`.

The first round-2 commit attempt failed the secret-scanning hook because four
file SHA-256 metadata values were misclassified from their artifact path names.
Explicit SHA-256 objects preserved every exact digest and path association;
the hook then passed without a bypass or scanner exception. Astra's round-2
nonfinding follow-up recommendation about FR-012's old observer mount claim
was corrected before commit as a T203-created documentation orphan; no follow-up
ticket deferred it, and it is not a finding row. These changes required fresh
same-round review. The driver could not run fresh pre-review verification from
`in-review`; the user approved a one-time recovery to `in-progress`, preserving
the original baseline, round 2 and all review history. Normal driver verification
and fresh native reviews then passed; no driver code, round reset, fabricated
verification cache or stale approval was used. Final implementation: d8aa28c.

Separately, the user-requested pre-gate advisory review was a fresh **Codex child
(backend model not exposed)**. It identified two Majors in the unfinished candidate:
a malformed Dockerfile instruction and cookie I/O outside the promised total
attempt budget. Work stopped; the user authorized both repairs and exact reserved
wording. Both were fixed and evidenced before ordinary round 1. They are retained
in the ticket and `target/runs/T203/independent-change-review.md`, excluded from
the ordinary-review denominator and never counted as ordinary reviewers' misses.
T203 does not close T155 or the cumulative milestone and external human release
review obligations.


T204: driver consumed the refreshed REWORK into round2. No round2 reviewer was
launched: the user explicitly instructed “fuck it commit and merge” and confirmed
“ok if focused check passed commit the test too”. The final test-only correction,
focused evidence and lossless SHA256 metadata formatting were committed through a
human override with actual archived GLM REWORK/Astra APPROVE trailers and normal
hooks. No fresh pair approval or full gate was fabricated. Actual native CLI
versions for both launches: Codex0.160.0/OpenCode1.18.33; matrix models/efforts
unchanged. T155, T078/T079 and release gates remain separate.

T205: all three round-1 sets and round 2 are recorded above. Actual tools for
all four launches were Codex **0.160.0** (`gpt-6-astra`, `high`) and OpenCode
**1.18.33** (`zai-coding-plan/glm-5.3-flash`, `xhigh`, native `max`). Durations
were not measured. Complete imported sets/verdicts/prompts are retained in
`target/runs/T205/ordinary-round-1/`, `ordinary-round-1-refresh/`,
`ordinary-round-1-refresh2/`, `ordinary-round-2/` and the append-only
`target/runs/T205.review-history`. Native log copies are explicitly partial.

The first full driver verification was RED36PASS/4SKIP/1FAIL: workflow S8b
exit141/tree mismatch; exact failing child location was not retained. One
unchanged focused workflow rerun passed all16 scenarios. Full2 and documented
AWF full3 passed37/4/0. Full4 failed36/4/1 in the unchanged scanner fixture:
an exported caller signoff function changed `command -v git` into a
self-referential controlled-path link. The exact exported-function control
reproduced all7 failures; no-function and nonexported-loader controls passed.
The first workflow failure remains unattributed; its rerun is not root-cause
proof. All full and focused attempts remain retained/disclosed.

A fresh user-requested advisory falsification found that the original
popup-delivery test passed both correct and bad-handler source. The bounded
bridge passed correct source and failed the mutation. That advisory used
Node18, one selected test and47 exclusions; it is separate from ordinary
review. The developer independently executed the repaired test and retained
correct/mutant scratch runs. Final identical-command tests-first GREEN passed
85/85; full5 was an actual normal round-2 driver GREEN37/4/0 under the corrected
caller setup, including scanner and workflow gates. Both round-2 reviewers
marked both prior items SATISFIED. The final APPROVE freshness check reused
that actual GREEN because executable content was unchanged; no optional full6,
manual status recovery, manual verification-cache write, gate suppression or override.
The signed implementation is `fb8ae64` with actual round-2 APPROVE trailers.

Astra's procedural Major is retained as an unfinished closing requirement that
was subsequently fulfilled, with severity/timing disputed and no demonstrated
production defect. GLM's full3-validity argument was supported, while its
zero-finding test-integrity conclusion was narrowed by the executed mutant.
The `dismissed` column records GLM's explicit review-stage argument; it does
not dismiss the closing obligation or the finding as a whole. The user
conditionally authorized surviving bounded rework after objective falsification.

GLM's original nonfinding legacy-key-reader comment recommendation was a direct
own-change orphan and was corrected under the existing pregrant, not deferred
through a new ticket. Its broader run.sh stdout recommendation concerns
baseline-identical T197 inventory/automation wording. Scanner hardening and the
qualified SIGPIPE hypothesis remain outside this change; no follow-up was filed.

The focused browser run passed19/19 with all10 actual processes exited; its
preliminary Direct-fixture RED18/19 remains separately disclosed. The measured
zip is the historical executed package: it contains the previous, unused
`background/router.test.js` member. All eight execution-bound source hashes
remain identical, but the package is not an all-member match to finalized test
source. No unaffected browser run was repeated. API-visible cleanup and the
development pin do not establish forensic erasure or stable/full-profile release
certification. Constitution VIII impact remains a repair inside existing
runtime/storage/request boundaries; T155, T190, T197, T200, T206, cumulative
milestone and external human release obligations remain separately owned.

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

T208: rounds 1 and 2 are recorded above. Actual tools for both launches were
Codex **0.160.0** (`gpt-6-astra`, `high`) and OpenCode **1.18.33**
(`zai-coding-plan/glm-5.3-flash`, `xhigh`, native `max`). Durations were not
measured. Round 2 had no findings from either reviewer. Verdicts are retained
in `target/runs/T208-r1.verdict`, `target/runs/T208-r2.verdict` and the
append-only `target/runs/T208.review-history`. Both driver verifications were
GREEN, 37 PASS / 4 SKIP / 0 FAIL. Both reviewers reported read-only
inspection: neither ran builds or tests, and neither could compare the
contract wording with the approved draft, which is not in the candidate.

Not findings, recorded for the maintainer: both reviewers suggested keeping
approved wording or its digest with "apply verbatim" acceptances, and a
mechanical check tying the integration module's mirrored 250 s literal to the
contract row; GLM asked that the saved live procedure's go-test timeout be
confirmed above the 37 m worst case (the T208 wrapper used 80 m); both
deferred to `stargate-perf` the resource occupancy of the longer pending
window. No tickets were filed for these.

T155: the rounds of attempts 3 and 4 (2026-10-01 to 2026-10-03) are recorded
above from the append-only `target/runs/T155.review-history`; they were not
entered earlier because the ticket did not land. For the 2026-10-05 rounds the
tools were Codex **0.160.0** for round 1 and its refresh and **0.160.1** for
round 2 and its refresh (the CLI updated itself between them; `gpt-6-astra`,
`high`), and OpenCode **1.18.33** throughout
(`zai-coding-plan/glm-5.3-flash`, `xhigh`, native `max`). The first round-2
launch failed closed before any verdict: Codex returned HTTP 401
`token_invalidated` and "The 'gpt-6-astra' model is not supported when using
Codex with a ChatGPT account"; the maintainer restored access and the set was
launched again unchanged. Durations were not measured. Driver verification was
GREEN three times, 38 PASS / 4 SKIP / 0 FAIL. Both reviewers reported
read-only inspection without raw live artefacts; Astra reproduced the round-1
Major and the round-2 Minor by executing the entrypoint block in memory with
inert stand-ins. Verdicts are retained in `target/runs/T155-r1.verdict`,
`target/runs/T155-r2.verdict` and the review history.

Not findings, recorded for the maintainer: GLM noted that README R-1 names
`tests/integration/sc003_dns_leak.md`, which does not exist until R-1 first
runs, and that a reviewer or evaluator running `git write-tree` outside a
read-only brief (it happened twice in this ticket's advisory passes) may merit
a hardening note in the reviewer contract. No tickets were filed for these.
