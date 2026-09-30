---
id: T193
title: 'Gate scripts/subcommands/status in verify and bound its docker read'
status: in-review
created: 2026-09-30
last_updated: 2026-09-30
source: "maintainer decision 2026-09-30 session: remediate two gaps T187's reviewers flagged (orchestrator-verified in code) instead of deferring them"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T187"]
remediates: T187
parallel: false
files_budget: 9   # ticket + generated STATUS.md + evidence/T193-tests-first.json
                  # + scripts/verify.sh + scripts/subcommands/status
                  # + tests/contract/workflow/shell_quality_test.sh (START grounding: the
                  #   shell-quality discovery regression lives here, and its discover() copy of
                  #   verify.sh's rule goes stale with this change; verify_discovery_test.sh is
                  #   the Go-workspace gate's test and is not touched)
                  # + control-plane .../runtime/StargateControlPlaneTest.java (stubbed-docker status tests)
                  # + specs/001-tor-route/quickstart.md (status exit-code table, if a new code is added)
                  # + specs/001-tor-route/data-model.md (8 -> 9: its status sentence maps an
                  #   unreadable read to exit 20, which a timed-out read no longer is;
                  #   user-authorized, no deferral — fix own orphans)
privacy_critical: true   # release-critical operator shell + verification-gate coverage (Principle VII strictest category)
tests_first: []
test_for: []
constitution_refs:
  - "VII: Tests-First for Privacy-Critical and Contract Code"   # "Required coverage cannot disappear through ... workspace omissions"
complexity: low
risk: low
round_cap: 2
spec_refs:
  - scripts/verify.sh
  - scripts/subcommands/status
  - scripts/subcommands/init
  - specs/001-tor-route/quickstart.md
decision_refs:
  - "Maintainer decision 2026-09-30: file a focused T187 remediation ticket and run it before T184 (no deferral into T191)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T193: Gate scripts/subcommands/status in verify and bound its docker read

## Context

T187 (b6dde00) added the operator command `scripts/subcommands/status`. Its
reviewers flagged two gaps that T187 did not fix; the orchestrator confirmed
both in the code on 2026-09-30:

1. **Gate coverage.** `scripts/verify.sh` shell-quality discovery (lines
   ~132-144) lints every tracked `scripts/*.sh` plus two named extension-less
   entrypoints, `scripts/stargate` and `scripts/subcommands/init`.
   `scripts/subcommands/status` has no `.sh` suffix, so it gets neither
   `bash -n` nor the scoped ShellCheck. The comment above the discovery says
   "A new shell file added under scripts/ is gated automatically — no gate
   edit needed", which T187 made false.
2. **Unbounded read.** The status command's `docker compose exec` read has no
   timeout. `scripts/subcommands/init` bounds its docker probe with coreutils
   `timeout` plus a portable fallback (init ~lines 620-640); `status` does
   not, so a Docker daemon that hangs after preflight blocks the operator's
   status command with no output.

## Analysis

- Must hold: every tracked shell entrypoint under `scripts/subcommands/`
  (except the `.keep` placeholder) is discovered by the shell-quality gate
  without a per-file edit, and the gate comment states the actual rule. The
  status read is bounded and a timeout yields a defined, documented exit
  code and a static message, never partial or unvalidated state.
- Gated: `tests/contract/workflow/shell_quality_test.sh` runs verify.sh's
  OWN Gate 1c block (extracted like verify_skip_convention_test.sh does) in a
  sandbox repo: an extension-less `scripts/subcommands/` file with a syntax
  error must FAIL the gate, `.keep` must stay excluded, and against the real
  tree the gate's logged coverage must include `scripts/subcommands/status`.
  Its hand-copied `discover()` rule is replaced by the gate's own output so
  the test and gate cannot drift. Stubbed-docker status tests in
  `StargateControlPlaneTest` hang each docker call after the PATH check
  (`compose version`, `info`, `compose ps`, `compose exec`) with GNU
  `timeout`, without it and with a non-GNU one on PATH, with TERM-obeying,
  TERM-ignoring and mixed process trees (direct child obeys, a background
  descendant ignores), and require a bounded exit with no stub process left
  alive.
- Design: one `bounded` helper in `status` (GNU coreutils `timeout -k`, else
  a bash watchdog; both signal the call's whole process group, SIGTERM then
  SIGKILL after a 1s grace, so no descendant — TERM-ignoring or not — keeps
  the command-substitution pipe open). A non-GNU `timeout` (busybox signals
  only its direct child) takes the watchdog. Compose calls go through the lib's
  `compose_run` in a child bash so the timeout can bound them without
  duplicating the compose identity. Any bounded call timing out exits 70 with
  a static message; `STARGATE_STATUS_TIMEOUT` (positive integer seconds,
  default 10) is validated at the edge. data-model.md's status sentence gains
  the timeout outcome.
- Residue: whether the real Docker CLI/compose plugin actually terminates on
  the timeout signal (the stub cannot show it) — checked with a real `docker`
  CLI against a socket proxy that withholds replies (results quoted in
  §Notes; harness under the gitignored target/runs/T193-live/).

## Acceptance

1. Tests first: a discovery regression that fails at the current `verify.sh`
   (an extension-less `scripts/subcommands/` entrypoint is not gated), and a
   stubbed-docker status test where the exec read hangs, which fails at the
   current `status`. Record red before green with
   `scripts/test-first-evidence.py`.
2. `scripts/verify.sh` discovers `scripts/subcommands/*` (excluding `.keep`)
   and the named entrypoints; the discovery comment matches the behaviour.
3. `scripts/subcommands/status` bounds its docker read the same way `init`
   bounds its probe (timeout with the portable fallback); a timeout exits with
   a distinct documented code and a static message. (Refined, maintainer-
   authorised 2026-09-30: the bound covers every docker call after the PATH
   check, including the `docker compose version` preflight, and holds for a
   mixed process tree — direct child obeys SIGTERM, a descendant ignores it —
   exercised by a re-runnable `term=mixed` test case.)
4. The quickstart status table documents any new exit code.
5. `scripts/verify.sh` is green and its shell-quality row covers
   `scripts/subcommands/status`.
6. (Refined, maintainer-authorised 2026-09-30.) The tests-first record's red
   is captured against the untouched task baseline with only the two test
   files staged, failing on both the discovery assertion and the hang cases;
   green is recorded on the full candidate with the identical probe command.

## Out-of-scope

Other subcommands' behaviour; the T187 status-file design; changing the
shell-quality rule set (the four scoped ShellCheck codes).

## Notes

**History (not a verdict).** Review round 1 ran on snapshot `3a85fd4a…`.
Per the developer's report: astra returned REWORK with 1 Major — a child
ignoring SIGTERM outlives the timeout in both branches; glm returned APPROVE
with 2 Minors — `command -v timeout` accepts a non-GNU `timeout`, and the
ticket raised its own files_budget inside the change under review. The round-1
verdict files were deleted unarchived by the driver's `invalidate_reviews` on
the snapshot change (driver defect, to be fixed in a separate ticket). The
maintainer authorised the round-2 correction of the driver state (2026-09-30).

**History (not a verdict), round 2.** Review round 2 ran on snapshot
`28d6e0e8…`; the driver archived its verdicts at `target/runs/T193-r2.verdict`,
preserved verbatim as `target/runs/T193-prerefine-r2.verdict` because the
refined cycle's round 2 reuses that archive name. astra returned ESCALATE (refine) with 1 Major —
the tests-first record did not evidence the discovery regression (the
retained red's pre-fix patch already contained the verify.sh fix) — and noted
the prior-round verdict was absent from its handoff. glm returned REWORK with
2 Majors — (1) in the GNU-`timeout` branch the post-timeout group KILL
(`kill -KILL -- "-$tpid"`) was reported to be a no-op and the mixed tree
(direct child obeys SIGTERM, descendant ignores it) untested; the `term=mixed`
test case now exercises it — and (2) the same missing discovery red; plus 2
Minors — the `docker compose version` preflight was unbounded, and the live
residue evidence was not reachable from the candidate. The driver escalated at
the round cap.

**Refinement (maintainer-authorised 2026-09-30).** The maintainer chose
*refine*: Acceptance 3 is extended to the `compose version` preflight and the
mixed tree, and Acceptance 6 pins the red capture. files_budget stays 9. The
round counter was reset through `run-task.sh --reset` and the ticket restarted
from START.

**History (not a verdict), refined cycle round 1.** Ran on snapshot
`6be188e8…` (driver archive `target/runs/T193-r1.verdict`). astra returned
REWORK with 1 Major — when the direct child of a bounded call exits before
the deadline, a surviving descendant holding stdout is not cleaned up in
either branch, so the read can stay open; glm returned APPROVE with no
findings.

**Tests-first record.** The red in `evidence/T193-tests-first.json` is a
re-recording against the untouched baseline (only the two test files
staged), made after the original baseline red had been overwritten by a
later rework capture, and re-recorded once more on 2026-09-30 after the
refined round-1 test additions. It is not the original run: the original
baseline red (discovery assertion failing, exec hang) and the intermediate
reds are not retained. In the current red the shell-quality test fails its
discovery assertions (the gate reports `[PASS] shell-quality — 4
entrypoint(s)` with a syntax-broken extension-less subcommand present) and
the status hang cases, including the early-exit case, do not end within the
bound.

**Live results (real docker 29.1.3 CLI + compose v5.1.4 plugin through a
socket proxy that stops forwarding once the request stream contains the
pattern; `STARGATE_STATUS_TIMEOUT=3`; target/runs/T193-live/live-r4.out, run on
the refined round-2 candidate).**

```
timeout no-hang                rc=30   1s  token delivery: PENDING (...)
timeout hang /info             rc=70   4s  token delivery: state unavailable (Docker did not answer within 3s; nothing is claimed)
timeout hang /containers/json  rc=70   3s  (same message)
timeout hang /exec             rc=70   3s  (same message)
fallback no-hang               rc=30   4s  token delivery: PENDING (...)
fallback hang /info            rc=70   5s  (same message)
fallback hang /containers/json rc=70   6s  (same message)
fallback hang /exec            rc=70   7s  (same message)
leftover docker/compose processes: none
```

"fallback" runs with a PATH holding only docker, bash and sleep (no
`timeout`). `compose version` makes no daemon request, so the proxy cannot
hang it; its bound is covered by the stubbed test only.

**Budget.** The files_budget raise 8 -> 9 (data-model.md orphan;
`shell_quality_test.sh` in place of `verify_discovery_test.sh`) is accepted by
the maintainer under the standing no-deferral rule (fix own orphans).
