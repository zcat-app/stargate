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

T182 round 1: both APPROVE, no findings. GLM recommended call-site shape
guards for the shared partition helper (a swapped argument would still pass);
not adopted — call sites verified correct and the helper is vector-pinned.

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
