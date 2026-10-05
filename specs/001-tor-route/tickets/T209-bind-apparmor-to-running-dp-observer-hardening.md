---
id: T209
title: 'Bind DP AppArmor to the running DP; assert observer hardening'
status: pending
created: 2026-10-05
last_updated: 2026-10-05
source: "T155 r5 cumulative redteam (index tree d6f46b9b): area 3 M1, narrowed to Minor by falsification 2026-10-05 (core is a duplicate of 989b8f9 A3-m4, 79d49e9 A3-M2 and the 694dbd8 moby verdict; one increment is new), area 3 m3 (survived as Minor), and the T191/T203 stale-statement orphans of area 3 m5/m6 moved here by the maintainer (\"Split to T209 (Recommended)\", 2026-10-05); maintainer approved filing as one deployment-confinement ticket 2026-10-05"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: false
files_budget: 21  # ticket + STATUS.md + evidence/T209-tests-first.json (overhead);
                  # scripts/subcommands/init + its hermetic test under tests/contract/stargate-cli/ (named at START);
                  # tests/contract/stargate-cli/t162_enforcement_test.sh (docker tier);
                  # tests/live-e2e/local-topology/connect_refusal.py + test_connect_refusal.py;
                  # tests/contract/compose/local_compose_test.sh;
                  # tests/live-e2e/local-topology/observer.py + test_observer.py;
                  # specs/001-tor-route/quickstart.md; THREAT-MODEL.md;
                  # specs/000-architecture/spec.md (§9.1 steps 5 and 7, §9.2: init's new step and its exit code);
                  # specs/001-tor-route/contracts/foundation-boundaries.md (only if the maintainer's decision in Acceptance 4 changes the contract);
                  # Acceptance 8 (maintainer's "Split to T209"): data-plane/Makefile, data-plane/Dockerfile, control-plane/Dockerfile,
                  # compose/env/local.env.example, tests/live-e2e/local-topology/README.md (quickstart.md and local_compose_test.sh already counted above)
                  # + the test file holding Acceptance 8's grep check, if it is not one already counted (named at START)
                  # SECURITY-DECISIONS.md (Acceptance 9, only with maintainer-approved wording); 20 -> 21 was raised for this path by
                  # the T155 developer and reported to the maintainer on 2026-10-05 (not a maintainer-approved raise)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/foundation-boundaries.md
  - specs/001-tor-route/quickstart.md
  - specs/000-architecture/spec.md
  - THREAT-MODEL.md
decision_refs:
  - "2026-10-05 maintainer: \"Fold in, one new ticket\" (T155 r5 survivors; the running-DP AppArmor increment and the observer hardening assertions become this ticket)"
  - "2026-10-05 maintainer: \"Split to T209 (Recommended)\" (the T203 orphans and the Dockerfile/Makefile comments of area 3 m5/m6 are Acceptance 8 here, not T197)"
  - "2026-10-05 maintainer: \"Stale SD entry to T209 (Recommended)\" (Acceptance 9; the SECURITY-DECISIONS wording stays reserved for the maintainer)"
  - "SECURITY-DECISIONS 2026-09-20 (T162): the host administrator and Docker daemon are trusted; direct Compose starts are unsupported (read, not changed, by this ticket)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T209: Bind the DP's AppArmor confinement to the running DP; assert the observer's hardening

## Context

Two deployment-confinement gaps survived the T155 r5 cumulative redteam and its
falsification as Minor, and the maintainer moved a set of stale deployment statements here.
Nothing in this ticket is a fail-open on the measured host.

**Running-DP label.** `scripts/stargate init` verifies the `stargate-dp` profile, the
af_unix feature file and the owner rules on the kernel that runs `init`, before Compose
starts the DP. After the start nothing reads the label the DP actually runs under: not
`init`, not the DP, and no test. On the measured host (a rootful local Engine on an Ubuntu
AppArmor kernel) the falsifier found no gap: `init` refuses without the feature file, and
Docker refuses to start a container whose named profile is not loaded. The gap is a Docker
daemon that does not share `init`'s kernel (a remote context, Docker Desktop's VM, possibly
rootless Docker). `init` then verifies the wrong kernel. Per the falsifier's reading of
moby 28.5.2 source (29.x, which the project measured on, was not read), a daemon whose host
lacks AppArmor drops `apparmor=` without an error, and `docker inspect .AppArmorProfile`
still reports the requested name. The falsifier also recalled, without reading the source,
that moby's host-support check is false when dockerd runs with `container` set in its
environment or without `/sbin/apparmor_parser` (a nested dockerd on the same kernel). That
is unconfirmed; Acceptance 1 covers it either way. The only running-DP label check in the
tests, `tests/live-e2e/local-topology/connect_refusal.py`, reads that inspect field. No
document says the daemon must be rootful and local. In the placements the falsifier could
reason through, the browser cannot reach such a DP and `init` exits 50; nothing was run.
AppArmor is the only control on the host abstract-socket channel (THREAT-MODEL §3.1), which
is why this is filed and not left as Info.

**Observer hardening keys.** `contracts/foundation-boundaries.md` names "read-only
root/publication mounts and dropped capabilities" among what enforces the T203 observer
authority boundary. Compose sets `read_only`, `cap_drop: [ALL]` and
`no-new-privileges:true` on `tor-observer`, but the hardening loop in
`tests/contract/compose/local_compose_test.sh` covers only `stargate-dp`,
`stargate-control` and `tor`, and `tests/live-e2e/local-topology/observer.py` records the
observer's `CapEff`, `NoNewPrivs` and security options as evidence without asserting them.
Removing any of the three keys would pass every gate. (`network_mode: none` and the absent
Docker socket are already asserted for the observer.)

**Stale statements (Acceptance 8).** `data-plane/Makefile` says the build is "Verified by
tests/reproducibility/data_plane_test.sh (T075)" and the two plane Dockerfiles say "T015
pins this image's output digest in compose/docker-compose.local.yml"; the test does not
exist yet and Compose uses `:local` tags (done T191 item 5 fixed only the Tor Dockerfile).
`compose/env/local.env.example` and `tests/live-e2e/local-topology/README.md` still
describe the observer reading Tor's control socket with a cookie, and the quickstart still
gives a volume `subpath` as the reason for its Engine/Compose floor; T203 removed both.

The core claim "the DP does not check its own confinement" was raised and falsified in the
694dbd8, 79d49e9 and 989b8f9 passes against SECURITY-DECISIONS 2026-09-20 (T162). This
ticket does not reopen that decision; Acceptance 4 asks the maintainer whether the
constitution requires more.

## Analysis

- Must hold: on a supported deployment `init` reports success only when the running DP
  process carries the enforcing `stargate-dp` label, read from the kernel and not from
  Docker's configuration record; the supported daemon scope is stated; a Compose or
  deployed observer missing any of its three hardening keys fails a gate; the named build
  and observer statements say what is true.
- Gated: `scripts/verify.sh` (hermetic `init` tests, `local_compose_test.sh`,
  `test_observer.py`, `test_connect_refusal.py`); docker tier of `t162_enforcement_test.sh`.
- Residue: the docker-tier and live checks need the disposable guest (live-e2e README
  section 2). Daemon placements declared unsupported are not tested. moby 29.x behaviour
  and rootless behaviour are unverified and stay stated as such.
  The label is read when `init` runs; a later `$COMPOSE restart stargate-dp` (quickstart) is
  not re-checked, which is part of what Acceptance 4 decides.

## Acceptance

1. After Compose start, `init` reads the running DP's label from the kernel on the invoking
   host (`/proc/<DP .State.Pid>/attr/apparmor/current`, falling back to `attr/current`),
   after binding that PID to the DP container (for example by its cgroup path) so a
   remote daemon's PID cannot match a local process, and requires `stargate-dp (enforce)`;
   on mismatch, an unreadable file, a PID that is not the container's or a missing PID it
   stops the DP and exits with the host-boundary code (60 proposed, matching quickstart
   step 2's "A failure exits 60 with the DP stopped"; confirm at START). Tests first: a
   hermetic test with a stubbed inspect and proc read fails before the change for each
   case and passes after, with a positive control that passes. Record red and green with
   `scripts/test-first-evidence.py`. Architecture §9.1 (steps 5 and 7) and §9.2 describe
   the new step and its exit code.
2. Docker tier: the real DP image started with `--security-opt apparmor=unconfined` is
   detected by the same check (red before green). `docker inspect .AppArmorProfile` is not
   accepted as evidence of confinement anywhere in `init` or the live harness:
   `connect_refusal.py`'s `AppArmorProfile` assertion gains the kernel read, with a
   `test_connect_refusal.py` case in which the inspect field says `stargate-dp` and the
   kernel label does not. The added kernel check is a verdict that does not depend on
   `assert` (T189 item 6), whichever of the two tickets lands first.
3. Supported daemon scope. Maintainer stop point: the quickstart prerequisites and
   THREAT-MODEL §3.1 are to state which Docker daemons are supported. The drafted
   direction is "rootful, on the invoking host's kernel; Docker Desktop, rootless and remote
   daemons unsupported", but that scope and its exact wording are the maintainer's: stop and
   return the draft sentences before writing either file. Quickstart step 2's "verifies
   both before starting it" is made true for what `init` checks after this ticket.
4. Maintainer decision, recorded in this ticket before any code for it. The question is a
   constitutional reading, not a preference: whether the Deployment Model ("The proxy MUST
   refuse startup when these conditions are not met") and Principle III ("Enforce the
   actor/destination matrix against a compromised application process") require the DP
   itself to refuse to serve when it does not run under its profile (reading its own label
   before the first SOCKS method, which needs a profile rule for that one file), as T168
   did for the IP boundary, or whether the installer check of item 1 satisfies them, as the
   694dbd8, 79d49e9 and 989b8f9 passes read SECURITY-DECISIONS 2026-09-20 (T162). This
   ticket does not decide it, and a finding acceptance cannot waive a principle. If the
   reading is "required", stop: it changes `foundation-boundaries.md`, the AppArmor profile
   and data-plane code, needs a raised budget and tests-first, and any SECURITY-DECISIONS
   wording is the maintainer's.
5. `local_compose_test.sh`'s hardening loop includes `tor-observer`; removing any one of
   `read_only`, `cap_drop: [ALL]` or `no-new-privileges:true` from that service fails the
   test (red before green by a staged temporary mutation of the Compose file, never committed).
6. `observer.py` `assert_boundary` fails when the deployed observer's `ReadonlyRootfs` is
   false, `CapDrop` lacks `ALL`, or `/proc/<pid>/status` shows `NoNewPrivs: 0` or a non-zero
   `CapEff`; `test_observer.py` covers each case with a passing control.
7. Live: on the disposable guest, `run.py` and the docker tier of
   `t162_enforcement_test.sh` pass on the final candidate; SKIP is not PASS; reruns are
   disclosed with counts.
8. (T155 r5, area 3 m5 comment half and m6 T203 orphans (env example, local-topology README, quickstart Engine-floor reason), Minor; maintainer's "Split to T209
   (Recommended)", 2026-10-05) `data-plane/Makefile`, `data-plane/Dockerfile` and
   `control-plane/Dockerfile` no longer say the DP build is "Verified by" a test or that
   "T015 pins this image's output digest in compose"; they name T075 (data-plane
   reproducibility gate) and T081 (release image digests) as the pending owners. A grep
   check fails on "pins this image's output digest". `compose/env/local.env.example` and
   `tests/live-e2e/local-topology/README.md` describe the post-T203 observer (no Tor-state
   mount, no cookie, the health publication read by `--check-ready`).
   `specs/001-tor-route/quickstart.md` gives "the Compose file mounts a volume `subpath`" as
   the reason for the Engine/Compose floor; the Compose file has no `subpath` since T203.
   State a reason that is true of the current Compose file, or state the floor as the
   retained minimum without a reason; whether the floor itself changes is the maintainer's.
   `tests/contract/compose/local_compose_test.sh` checks the stated reason against Compose
   unconditionally (today it skips the check when no `subpath` exists). Quickstart wording
   needs maintainer approval: stop and return drafts before writing it.
9. (T155 Acceptance 1 closure re-check of redteam finding 20260727-001, 2026-10-05; maintainer
   approved 2026-10-05, "Stale SD entry to T209 (Recommended)") The SECURITY-DECISIONS entry
   "2026-07-16 — docker-socket-proxy mechanism removed (T094a)" still states in the present
   tense that the control plane observes Tor through Tor's cookie-authenticated ControlPort
   (`tor:9051`) and that this is "a strictly narrower observation surface". Neither holds
   since T164 and T203: the shipped torrc has no ControlPort (a ControlSocket inside Tor's
   own state volume), and neither the CP nor the observer holds the cookie or mounts Tor's
   state. No later entry supersedes that text. Maintainer stop point: the log is append-only
   and its wording (a `Superseded by:` line on the old entry and any new entry) is reserved
   for the maintainer. Stop and return drafts; write nothing to `SECURITY-DECISIONS.md`
   without that approval.

## Out-of-scope

Reopening SECURITY-DECISIONS 2026-09-20 (T162) or changing the trust placed in the host
administrator and Docker daemon, beyond what the maintainer decides under Acceptance 4;
DP self-refusal code unless Acceptance 4 is answered that way; supporting Docker Desktop,
rootless or remote daemons; the Tor sidecar's network boundary (T197 item 5 and T078);
the CI gitleaks binary and the `docker-cadence` path filter (T199 items 4-5); the THREAT-MODEL
banner and §5.9 wording and `CLAUDE.md` (T197 item 6);
the reproducibility gate itself (T075) and release digests (T081); any change to the
AppArmor profile's existing rules or to the owner iptables rules.
