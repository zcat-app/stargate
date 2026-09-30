---
id: T193
title: 'Gate scripts/subcommands/status in verify and bound its docker read'
status: pending
created: 2026-09-30
last_updated: 2026-09-30
source: "maintainer decision 2026-09-30 session: remediate two gaps T187's reviewers flagged (orchestrator-verified in code) instead of deferring them"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T187"]
remediates: T187
parallel: false
files_budget: 8   # ticket + generated STATUS.md + evidence/T193-tests-first.json
                  # + scripts/verify.sh + scripts/subcommands/status
                  # + tests/contract/workflow/verify_discovery_test.sh
                  # + control-plane .../runtime/StargateControlPlaneTest.java (stubbed-docker status tests)
                  # + specs/001-tor-route/quickstart.md (status exit-code table, if a new code is added)
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
- Gated: `tests/contract/workflow/verify_discovery_test.sh` regression that
  a new extension-less file under `scripts/subcommands/` is discovered;
  stubbed-docker status test for the hang path.
- Residue: none known beyond what the review gate finds.

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
   a distinct documented code and a static message.
4. The quickstart status table documents any new exit code.
5. `scripts/verify.sh` is green and its shell-quality row covers
   `scripts/subcommands/status`.

## Out-of-scope

Other subcommands' behaviour; the T187 status-file design; changing the
shell-quality rule set (the four scoped ShellCheck codes).
