---
id: T199
title: 'Count continuation pushes; bundle-ref red; verify CI toolchains'
status: pending
created: 2026-10-02
last_updated: 2026-10-05
source: "T191 round-2 review (GLM, two Minors), confirmed by the T191 developer's falsification; maintainer approved filing 2026-10-02. Item 3 from the T155 attempt-4 redteam (area 3 m7, survived falsification), maintainer approved 2026-10-03. Items 4-5 from the T155 r5 cumulative redteam (area 3 m1 gitleaks half, survived falsification 2026-10-05; area 3 m2 increment, Info), maintainer approved 2026-10-05"
phase: "Foundation audit remediation"
story: ''
remediates: T191
blocked_by: []
parallel: true
files_budget: 7   # ticket + STATUS.md + tests/contract/workflow/ci_inputs_test.sh + evidence/T199-tests-first.json;
                  # + .github/actions/setup-toolchain/action.yml (item 3, T155 attempt 4)
                  # + .github/workflows/verify.yml (item 4) and .github/workflows/docker-cadence.yml (item 5), T155 r5, maintainer-approved 2026-10-05
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
  - .github/workflows/verify.yml
  - .github/workflows/docker-cadence.yml
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
4. (T155 r5 cumulative redteam, area 3 m1 gitleaks half, Minor, survived falsification
   2026-10-05; maintainer approved filing 2026-10-05; Constitution IV) The `secret-scan`
   job in `.github/workflows/verify.yml` runs `gitleaks/gitleaks-action` pinned by commit;
   nothing checks the gitleaks binary that action obtains against a committed digest.
   (a) Show from the action's source at the pinned SHA how it obtains gitleaks (version,
       URL, any cache restore) and record it in this ticket. Neither the reviewer nor the
       falsifier read that source; the cross-run cache concern is unconfirmed until this
       is done.
   (b) Following from (a): if the action does not verify the binary against a digest it
       ships, or restores it from a cross-run cache, the job runs a gitleaks binary checked
       with `sha256sum -c` (or an equivalent digest check) against a committed digest before
       execution, with no cross-run cache restore. If (a) shows the action already does
       both, record that and keep the pinned action.
   (c) Following from (a): `ci_inputs_test.sh` fails on a downloaded executable used without
       a hash check, red on the current workflow and green after; if (a) made (b) a no-op,
       the test instead pins the verified behaviour it relies on.
5. (T155 r5, area 3 m2 increment, Info; maintainer chose "Owners for two, rest no ticket
   (Recommended)" 2026-10-05) `.github/workflows/docker-cadence.yml` filters its triggers on
   `sidecars/**`, `**/Dockerfile`, `compose/**` and itself, so changes to `data-plane/cmd/tor-health-publisher/**` (compiled into the Tor image since
   T203) and `data-plane/cmd/tor-observer/**` (compiled into the observer image by
   `sidecars/tor-observer/Dockerfile`) do not trigger it, although its header says it covers
   sidecar sources. Add both paths to the `push` and `pull_request` filters.

## Out-of-scope

Any change to `.github/workflows/agent-task.yml` behaviour or to token separation; the
`repo_url_test.sh` look-alike-name idea (maintainer: Info). Item 3 changes only how
`setup-toolchain` obtains and verifies the same toolchain versions, not which versions or
which workflows use it. Item 4 changes only how the `secret-scan` job obtains and verifies
gitleaks, not the scan configuration (`.gitleaks.toml`) or which events run it. Item 5
changes only the path filters of `docker-cadence.yml`, not what the job runs.
