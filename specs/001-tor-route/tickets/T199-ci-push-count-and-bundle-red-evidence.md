---
id: T199
title: 'Count continuation pushes; bundle-ref red; verify CI toolchains'
status: pending
created: 2026-10-02
last_updated: 2026-10-03
source: "T191 round-2 review (GLM, two Minors), confirmed by the T191 developer's falsification; maintainer approved filing 2026-10-02. Item 3 from the T155 attempt-4 redteam (area 3 m7, survived falsification), maintainer approved 2026-10-03"
phase: "Foundation audit remediation"
story: ''
remediates: T191
blocked_by: []
parallel: true
files_budget: 5   # ticket + STATUS.md + tests/contract/workflow/ci_inputs_test.sh + evidence/T199-tests-first.json;
                  # + .github/actions/setup-toolchain/action.yml (item 3, T155 attempt 4)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: low
risk: low
round_cap: 2
spec_refs:
  - .github/workflows/agent-task.yml
  - tests/contract/workflow/ci_inputs_test.sh
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T199: Count continuation pushes; bundle-ref red; verify CI toolchains

## Context

T191 (a046386) moved the CI agent's only push into a separate token-holding step of
`.github/workflows/agent-task.yml`. The workflow guard in
`tests/contract/workflow/ci_inputs_test.sh` counts pushes per job by matching
`\bgit\b.*\bpush\b` on single code lines (`:197-198`). The real push spans continuation
lines (`git -c … \` then `push --quiet …`) and is never matched. The one hit the test
counts is `git init --quiet "$RUNNER_TEMP/push"`, a path. A later change that moves a
continuation-style push into the agent job would therefore pass the guard.

T191 round 2 also added a temporary-repository regression proving the bundle carries
`refs/heads/agent/$TICKET` at the result commit. `ci_inputs_test.sh` stops at its first
failing assertion, so the committed round-2 red in `evidence/T191-tests-first.json` shows
the token-step check, not the bundle-ref check. The bundle red exists only as a quote in
the T191 ticket and a scratch log.

## Acceptance

1. `ci_inputs_test.sh` joins shell continuation lines before matching, and counts a push
   only for a `git … push` command (not a path containing `push`). Add fixtures, red
   before green against the current test:
   - the continuation-style push moved into the agent job must be rejected;
   - a second continuation-style push in any job must fail the exactly-one-push check;
   - the shipped workflow still passes, with exactly one counted push, in the push step.
2. `ci_inputs_test.sh` reports every failing assertion before exiting nonzero. Capture
   `python3 scripts/test-first-evidence.py red T199` with the T191 bundle-ref fix reverted
   by a staged temporary mutation of `agent-task.yml` (bundle created before
   `agent/$TICKET` is moved; never committed), so the durable red shows the bundle-ref
   assertion failing alongside the Acceptance 1 fixtures. Revert the mutation and capture
   green with the identical command.
3. (T155 attempt 4, area 3 m7; Constitution IV "a version string ... is not verification")
   `.github/actions/setup-toolchain/action.yml` pins Go, JDK, Python and Node by version string
   only. Verify each toolchain download against a pinned checksum (or digest) before use, and
   make `ci_inputs_test.sh` fail on a toolchain pinned by version only (red on the current
   action, green after). Whether a setup action verifies checksums internally must be shown
   from its pinned source, not assumed.

## Out-of-scope

Any change to `.github/workflows/agent-task.yml` behaviour or to token separation; the
`repo_url_test.sh` look-alike-name idea (maintainer: Info). Item 3 changes only how
`setup-toolchain` obtains and verifies the same toolchain versions, not which versions or
which workflows use it.
