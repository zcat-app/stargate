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

### Rounds

| Date | Ticket | Round | astra | glm |
|---|---|---|---|---|

### Findings

| Date | Ticket | Round | Sev | Finding | astra | glm | Disposition | Note |
|---|---|---|---|---|---|---|---|---|

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
