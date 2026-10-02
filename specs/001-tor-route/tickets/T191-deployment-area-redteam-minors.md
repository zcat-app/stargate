---
id: T191
title: 'Resolve surviving deployment-area redteam minors and audit gaps'
status: done
created: 2026-09-29
last_updated: 2026-10-02
source: "reviews/redteam-20260929-694dbd8.md (area 3 minors and T155 reconciliation gaps that survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 34   # raised 14 -> 20 for T155 attempt-2 additions (maintainer-approved 2026-10-01): docker-compose.local.yml, local_compose_test.sh, quickstart.md, a docs URL lint, t162 SKIP fixture, THREAT-MODEL.md; 20 -> 34 maintainer-confirmed 2026-10-02 (paths and reasons under Implementation notes)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/wire-auth.md
  - specs/001-tor-route/contracts/foundation-boundaries.md
decision_refs:
  - "foundation-boundaries.md:87-90 (T164): verified local build plus local image ID for the observer"
  - "Maintainer approval 2026-10-02 (T191 orchestrated session): SECURITY-DECISIONS entries A (observer image identity) and B (Tor repository erratum) and the T081 Acceptance 3 wording, as independently evaluated in .scratch/tmp/T191/sd-eval.md; F1 folded into T191; files_budget 34 confirmed"
reviews: { round: 2, date: 2026-10-02, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T191: Resolve surviving deployment-area redteam minors and audit gaps

## Context

Surviving items from the 2026-09-29 cumulative redteam area 3 and the T155
reconciliation gaps, after falsification. Falsified or already-accepted items
(Tor version removal per the T099 rotation decision, observer shared UID per
contract, CP exec /tmp per T129) are out of scope except where wording is listed.

## Analysis

- Must hold: each item is fixed with a discriminating check or corrected text;
  no gate records PASS for work that did not run.
- Gated: `scripts/verify.sh`, compose contract tests.
- Residue: items needing a maintainer decision are recorded in SECURITY-DECISIONS.

Property map (START, 2026-10-02):

| Item | Must hold | Gate that catches it | Residue no gate catches |
|---|---|---|---|
| 1 | The observer accepts only the current `cp.pub`; init re-syncs its copy from `stargate-keys` by write-tmp + rename on every run, including a complete (6:2) install | `init_docker_test.sh` (docker): rotated `cp.pub` reaches the observer copy; wire R9 (live, mutate opt-in): stale copy refused, refreshed copy accepted, no observer restart | R9 needs a live stack (VM evidence) |
| 2 | The DP profile grants only the procfs reads the static Go DP performs and denies `/proc/*/net/**`; the DP still starts | `t162_enforcement_test.sh` docker tier: confined UID 5102 gets EACCES on `/proc/self/net/tcp`, unconfined control reads it | DP start and absence of new AppArmor denials need a real kernel (VM) |
| 3 | A skipped wire row or the t162 docker tier prints a line-start `SKIP:` | `verify_skip_convention_test.sh` runs both real scripts through verify's own `run_cmd` | none |
| 4 | Versioned runners, exact JDK/Python/Node, no Maven cache, a path-gated docker-cadence workflow | `ci_inputs_test.sh` (static) | GitHub cannot be run locally; the new workflow is unexercised until pushed |
| 5 | Comments state the truth | review | none |
| 6 | Token-bearing jobs do not persist credentials; only a post-agent step pushes `agent/$TICKET`, from a repository the agent cannot configure; opencode's last-matching bash rules deny `git push*` and exfiltration commands | `ci_inputs_test.sh` (static, last-match semantics as measured on opencode 1.18.33) | deny rules match command text; an allowed interpreter bypasses them, so the credential boundary carries the push property |
| 7 | No CP-writable `stargate-tor-config` mount, volume or init step | `local_compose_test.sh`, `init_docker_test.sh` | none |
| 8 | The smoke test brings the stack up only through `scripts/stargate init` | docker cadence compile check; live VM run | live only |
| 9, 10 | SECURITY-DECISIONS and T081 wording | maintainer-approved text only | none |
| 11 | Every service with `build:` has `pull_policy: build` | `local_compose_test.sh` | none |
| 12 | Every `github.com/<owner>/stargate` URL in `*.md`/`*.html` uses `zcat-app` | `repo_url_test.sh` | none |

Maintainer decision (2026-10-02): item 6 is resolved with **bash deny rules for the CI
job**, not a risk acceptance.

## Acceptance

1. Observer trust anchor: key rotation (wire-auth §6.2) and init refresh the
   observer's `cp.pub` copy atomically; extend the R9 rotation test to the observer.
2. DP AppArmor: narrow `/proc/**` read to what the Go runtime needs and deny
   `/proc/*/net/**`; prove the DP still starts and host socket tables are denied.
3. Inter-plane R1–R9: skipped runtime rows emit a `SKIP:` line (or become a
   separately accounted gate) so verify.sh never records PASS for them.
4. CI: add a docker-cadence job for sidecar/Dockerfile changes; pin JDK/Python/Node
   exactly; remove or lock-bind the Maven cache.
5. False comments: Dockerfile "digest pinned in compose" claims, init "no outbound
   except image pulls", env example "compose-internal" ports; state the truth
   and where final-image pinning happens (T081).
6. opencode adapter (July finding 010): correct the `scripts/agent-cli/opencode.sh`
   CI-safety comment and the inert `--no-auto` hint; add bash deny rules for the
   CI job or record an explicit maintainer risk acceptance.
7. Remove the orphan CP-writable `stargate-tor-config` mount, volume and init
   step, and update the expected volume set in the compose tests.
8. Stack smoke test: delete the stale T131 compensations in
   `tests/integration/stack_smoke_test.go` (pre-provisioned keys, Tor-first
   bring-up, keys mkdir), relying on the real init path.
9. Observer provenance: add a SECURITY-DECISIONS entry reconciling T138's
   "verified provenance" wording with the T164 local-image-ID model, and name the
   observer image in T081's acceptance.
10. Wording: SECURITY-DECISIONS T099 rotation note says removal happens on every
    Tor release; quickstart avoids shell-history token exposure.


Added 2026-10-01 from the T155 attempt-2 redteam (`reviews/redteam-20261001-79d49e9.md`),
maintainer-approved:

- Item 2 addition (A3-M7): until the rule is narrowed, THREAT-MODEL §3.1
  (THREAT-MODEL.md:273) states that the host-netns DP (`compose/docker-compose.local.yml:29`)
  can read the host's `/proc/self/net/{tcp,tcp6,udp,unix,arp,route}` under
  `/proc/** r` (`compose/apparmor/stargate-dp:25`). The fix adds
  `deny @{PROC}/*/net/** r` and is proven by a confined UID-5102 helper getting EACCES on
  `/proc/self/net/tcp`, with an unconfined positive control.
- Item 3 addition (A3-M3): `scripts/verify.sh` (SKIP detection at :95-96 matches only
  line-start `SKIP:`) also reports the docker tier of
  `tests/contract/stargate-cli/t162_enforcement_test.sh` as SKIP (its :86 prints
  `OK: …; SKIP[docker] packet falsifiers` and exits 0); add a regression fixture for this
  output shape alongside the R1–R9 case.
- Item 4 addition: pin the runner image instead of `runs-on: ubuntu-latest`
  (`.github/workflows/verify.yml:30,73,93`; `agent-task.yml:78,145`).
- Item 6 addition (A3-M5): the token-bearing run job (`agent-task.yml`, `contents: write`
  at :150, checkout at :160) sets `persist-credentials: false`; only `agent/$TICKET` is
  pushed, in a separate post-agent step; opencode config denies `git push*`; the MERGE
  prompt's `git push origin $FEATURE_BRANCH` (`scripts/run-task.sh:1149`) is not reachable
  from the CI agent. Item 6's risk-acceptance alternative does not cover this direct-push
  path. `ci_inputs_test.sh` requires `persist-credentials: false` in token-bearing jobs and
  the push deny rule.

11. `compose/docker-compose.local.yml` sets `pull_policy: build` on `stargate-dp` (:25),
    `stargate-control` (:62) and `tor` (:96), each of which declares `build:` plus
    `image: stargate/<name>:local`; without it a plain `up`/`pull` pulls
    `docker.io/stargate/*:local` from an unrelated third-party account.
    `tests/contract/compose/local_compose_test.sh` fails any service with `build:` lacking
    `pull_policy: build`. (A3-M1)
12. `specs/001-tor-route/quickstart.md:28` clones `https://github.com/zcat-app/stargate.git`
    (was `zcatapp`, which returns 404 and is claimable); a docs lint asserts every
    `github.com/<owner>/stargate` URL in `*.md`/`*.html` uses owner `zcat-app`. Becomes a
    Major at public release. (A3-M6)

## Implementation notes (2026-10-02)

**Budget, 20 -> 34, maintainer-confirmed 2026-10-02** (first raised under the 2026-10-01
pre-grant rule). Every touched path, with its reason:
fixed overhead: this ticket, `STATUS.md`, `evidence/T191-tests-first.json`. Item 1:
`scripts/subcommands/init`, `scripts/lib/compose.sh`, `contracts/wire-auth.md` (spec_refs §6.2),
`tests/contract/compose/inter_plane_wire_test.sh` (R9), `tests/contract/compose/wireprobe/wireprobe.go`
(observer probe for R9), `tests/contract/stargate-cli/init_docker_test.sh`. Item 2:
`compose/apparmor/stargate-dp`, `tests/contract/stargate-cli/t162_enforcement_test.sh`,
`tests/contract/compose/profileprobe/main.go` (procfs read probe), `THREAT-MODEL.md`. Item 3:
`tests/contract/workflow/verify_skip_convention_test.sh` (plus the wire and t162 scripts above).
Item 4: `.github/workflows/verify.yml`, `.github/actions/setup-toolchain/action.yml`,
`.github/workflows/docker-cadence.yml` (new), `tests/contract/workflow/ci_inputs_test.sh`.
Item 5: `sidecars/tor/Dockerfile`, `compose/env/local.env.example` (and init). Item 6:
`.github/workflows/agent-task.yml`, `scripts/agent-cli/opencode.sh`, `opencode.json`. Item 7:
`compose/docker-compose.local.yml`, `tests/contract/compose/local_compose_test.sh`,
`tests/contract/stargate-cli/fixtures/fixture-compose.yml`; orphans made stale by the removal:
`specs/001-tor-route/data-model.md` (§6 row), `tests/integration/stream_isolation_test.go` and
`tests/integration/onion_load_test.go` (comments/skip text naming the removed volume). Item 8:
`tests/integration/stack_smoke_test.go`. Items 9/10: `SECURITY-DECISIONS.md` and the T081 ticket
(maintainer-approved wording, 2026-10-02). Items 10/12: `specs/001-tor-route/quickstart.md`. Item 12:
`tests/contract/workflow/repo_url_test.sh` (new). 34 is under twice the dispatched budget of 20;
it is above twice the original 14.

**Decisions within acceptance.**
- Item 1: one helper, `refresh_observer_cp_pub` (`scripts/lib/compose.sh`), copies `cp.pub` into
  the observer key volume by write-tmp + rename, as the observer UID with the `stargate-ipc` group,
  no capability, no root, no network. init uses it on every run (fresh, upgrade and complete
  installs); R9 sources the same helper, so the live row exercises production code.
- Item 3: the gates now print a line-start `SKIP:` naming what did not run (verify.sh unchanged).
- Item 4: Go is pinned to `1.26.3` explicitly, because the pinned setup-go reads only `go 1.26`
  from `go-version-file` and takes the newest patch; the test keeps it equal to go.mod's
  `toolchain`. The setup-go module/build cache is disabled with the Maven cache: same class
  (a cache saved by any default-branch run, including an agent run, is restored by later verify
  runs). The docker cadence is a separate workflow because GitHub path filters are per workflow.
- Item 6: the push moved to a separate `publish` job on a fresh runner rather than a later step
  of the agent's job. A later step would share the runner with anything the agent left running
  and with the agent-written `.git` (hooks, config), so the token could leak to it. The agent job
  now holds only `contents: read`, never persists it, and uploads a bundle; publish accepts only
  `refs/heads/agent/$TICKET`. Step outputs from the agent job are passed through `env:` (they
  are forgeable via `$GITHUB_OUTPUT`). The adapter's `--no-auto` hint is made true (the adapter
  now honors `AUTO_APPROVE`) rather than deleted. The deny rules were measured on opencode
  1.18.33 (`opencode debug agent build --tool bash`): `git push origin agent/T1`, `true && git
  push`, `git push --force origin main`, `curl`, `wget`, `nc`, `env`, `printenv` were denied;
  `bash -c 'git --version'` and `git status` ran, confirming the rules are pattern-level only.
  CI pins opencode 1.18.32.
- F1 (maintainer decision 2026-10-02, folded into T191): Compose interpolation lets a
  `STARGATE_OBSERVER_IMAGE` in the shell override the env file, so init now refuses to run with
  that variable in its environment (exit 10, before host policy, volumes or containers; before
  its own scoped assignment for the early DP stop). Hermetic red/green regression in
  `tests/contract/stargate-cli/t162_enforcement_test.sh`; the false init comment ("operator-
  supplied image is refused") now states the behaviour.
- Item 12: append-only review records (`reviews/`, `redteam/`) quote the old URL as evidence
  and are excluded from the lint.

**Round 2 (maintainer decision 2026-10-02, option 1 after the round-1 REWORK).**
- Astra R1 Major: `run-task.sh` moves the agent onto the feature branch before implementing,
  so `agent/$TICKET` still named the run's starting commit and publish would push nothing of
  the task. The agent job now points `agent/$TICKET` at HEAD (after the state commit) before
  bundling. Regression in `ci_inputs_test.sh` runs the workflow's own commit and bundle step
  bodies in a throwaway repository that reproduces the branch transition; on the round-1
  workflow it failed (bundle at the base commit, implementation absent).
- GLM R1 follow-up: publish now parses the untrusted bundle in an "Import agent branch" step
  with no credential; only the push step holds the token (checked by `ci_inputs_test.sh`).
- GLM R1 Minor: `deny /proc/*/net/**` also matches `/proc/sys/net/**`, so the somaxconn allow
  was dead. The allow is deleted, the deny globs are unchanged, and the profile comment and the
  THREAT-MODEL T191 paragraph now say the read is denied and Go falls back to its built-in
  constant. t162's static check rejects any allow under `/proc/<x>/net/`.
- `repo_url_test.sh` look-alike repository names: Info, not part of this round.

**Evidence.**
- Tests-first: `specs/001-tor-route/evidence/T191-tests-first.json`, red at baseline `c5a93f0`
  (each item's hermetic gate failing on the missing property), green on the implemented
  candidate; that pair is kept under `superseded`. The current red adds the F1 regression
  (`observer image override returned 60, want 10`), and the current green was captured with
  F1, both SECURITY-DECISIONS entries and the T081 change in place; round 2 adds a further
  red (t162 dead-allow check, ci_inputs token-step check) and green. The bundle regression's
  red on the round-1 workflow is recorded separately because ci_inputs_test.sh stops at its
  first failing assertion: bundle `refs/heads/agent/T1` at the base commit, result commit
  different, implementation not exposed.
- Live, disposable QEMU guest (Ubuntu kernel 6.8.0-142, Docker 29.1.3, Compose 2.40.3,
  Go 1.26.3, TCG), candidate transferred as `git ls-files` of the staged tree; logs in the
  gitignored `target/runs/T191-vm/guest-evidence/`:
  - G1: real `stargate init` with the narrowed profile, exit 0; DP running under
    `stargate-dp (enforce)`, 127.0.0.1:8881 listening. Wire gate with mutations: R2-R9 PASS;
    R1 SKIP (CP socket not yet bound right after init), reported by the new `SKIP:` line.
    Mutant with `refresh_observer_cp_pub` a no-op: R9 FAIL "the running observer still refuses
    the rotated CP after the §6.2 refresh". The observer then refused the stale pin, a rerun of
    `stargate init` (complete 6:2 install) refreshed it, and the observer accepted the CP.
  - G5, settled stack: R1-R9 all PASS, no `SKIP:` line.
  - G3: `TestStackSmoke` through the real init path PASS (application bytes from the reference
    onion, then T132 DP-only recovery), 360 s.
  - G2: t162 docker tier with the candidate profile PASS, including EACCES on
    `/proc/self/net/tcp` and `/proc/thread-self/net/tcp` under the profile with an unconfined
    read as positive control, and the profiled gRPC and snapshot tests. Red: the pre-T191
    profile fails with "profiled DP read host socket table /proc/self/net/tcp".
  - Kernel log over the whole session: 0 AppArmor denials for profile `stargate-dp`. The 28
    denials are self-signal denials of t162's renamed test profiles (its signal rules name
    `peer=stargate-dp`), present with the old profile too.
- No extension or browser surface changed, so no browser run was needed.

## Out-of-scope

Tor package-closure pinning (T184); Maven lock (T185).
