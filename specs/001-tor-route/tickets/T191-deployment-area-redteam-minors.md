---
id: T191
title: 'Resolve surviving deployment-area redteam minors and audit gaps'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 3 minors and T155 reconciliation gaps that survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 20   # raised 14 -> 20 for T155 attempt-2 additions (maintainer-approved 2026-10-01): docker-compose.local.yml, local_compose_test.sh, quickstart.md, a docs URL lint, t162 SKIP fixture, THREAT-MODEL.md
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
reviews: {}
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

## Out-of-scope

Tor package-closure pinning (T184); Maven lock (T185).
