---
id: T198
title: 'Gate init on af_unix mediation; truthful init and quickstart'
status: done
created: 2026-10-01
last_updated: 2026-10-03
source: "T155 attempt 3 cumulative redteam (candidate 989b8f9): A1-M2 (narrowed Minor), A3-m1, A3-m5; all survived falsification"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 9   # ticket + STATUS.md + scripts/subcommands/init + init test + THREAT-MODEL.md + quickstart.md + compose test + SECURITY-DECISIONS note if the maintainer wants one
                  # raised 8 -> 9 (+1 more if the maintainer wants the SD note), pre-granted (rule 2026-10-01):
                  # evidence/T198-tests-first.json (fixed overhead); tests/contract/stargate-cli/t162_enforcement_test.sh
                  # (orphan: the new gate refuses its hermetic wrong-owner leg and docker-tier installer leg first)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - THREAT-MODEL.md
  - specs/001-tor-route/quickstart.md
decision_refs:
  - "SECURITY-DECISIONS 2026-09-20 (T162): direct compose starts are unsupported; init verifies the host boundary"
  - "Maintainer approval (2026-10-02, T198 orchestrated session): THREAT-MODEL §3.1 DRAFT A and quickstart prerequisite DRAFT B verbatim from the independent wording evaluation, plus the init step-2 sentence; no SECURITY-DECISIONS note; F1 folded into T198; F2 recorded as Info, covered by the Compose >= 2.26.0 floor"
  - "Maintainer decision (2026-10-03, T198 round 2): fix the cmp fail-open and the read-failure message; init comment aligned to §3.1; DRAFT A parenthetical replaced with the approved text naming what each method shows"
reviews: { round: 2, date: 2026-10-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T198: Gate init on AppArmor unix mediation; truthful init table and quickstart facts

## Context

1. The host-network-namespace data plane's abstract Unix-socket egress block is enforced only
   by AppArmor `deny unix` rules (`compose/apparmor/stargate-dp`); Landlock sets filesystem
   and net scopes only and seccomp does not filter `connect`. `init` checks only that the
   profile is `(enforce)`. On a kernel without AppArmor `network.af_unix` mediation, the
   parser loads the profile silently with those rules downgraded (reproduced with a simulated
   features file, not a real kernel). THREAT-MODEL.md:288 is unscoped and the measurements are
   Ubuntu 6.8 only. (A1-M2; needs a compromised DP plus a host abstract-socket relay.)
2. `scripts/subcommands/init:664-677` prints the control plane as `HEALTHY 127.0.0.1`; it
   has `network_mode: none` and its health is not checked. (A3-m1)
3. Quickstart says Docker Engine 25 (compose uses `volume.subpath`, Engine 26), "seven
   volumes" (ten are defined) and keys "all 0600" (public keys 0644, pepper 0640). (A3-m5)

## Analysis

- Must hold: init refuses a host that cannot enforce the documented boundary, and printed
  facts are checked facts.
- Gated: init/compose contract tests; live init on the disposable guest.
- Residue: a real kernel without af_unix mediation is needed to prove the refusal live.

### Grounding (START, 2026-10-02)

- Workstation (Ubuntu 24.04, 6.8.0-142, parser 4.0.1): `features/network/af_unix` is a file
  containing `yes`. Compile-only (`-Q -K -S -M <features>`): the live features copy and the
  same copy without `network/af_unix` both print "deny unix socket rule not enforced, can't be
  downgraded"; only the copy without it prints "downgrading extended network unix socket rule
  to generic network rule", and the compiled output differs. `--Werror`, `--Werror=all` and
  `--Werror=rule-downgraded` all return 0 for both, so a Werror load cannot be the gate; the
  falsifier's rc=1 came from its synthetic 5.4 ABI lacking network mediation altogether.
- The downgrade warning is in the parser's `dev` warning class (printed only with
  `--warn=dev`/`all`), so matching it would be fragile. Gate shape instead: read the feature
  file through the same privileged reader as the other host-policy checks, then compile the
  profile (`-Q -T -K -S`, as root like the load) with and without its two `deny unix` lines
  and refuse if the outputs are equal (the denies were dropped). Both run after the existing
  DP stop and before the load (exit 60, nothing loaded, no Compose).
- Compose defines nine named volumes (the source said ten; `local_compose_test.sh` pins
  nine). Key modes are `KEY_PRIVATE_MODE=0600`, `KEY_PUBLIC_MODE=0644`, `PEPPER_MODE=0640`
  (`scripts/lib/compose.sh`). The quickstart's expected status output is an orphan of item 2.
- Residue: no real kernel without af_unix mediation is available, so its refusal is shown with
  a bind-mounted feature file, and its downgrade with a `parser.conf` policy-ABI pin and copied
  feature sets. The compile check proves the policy lacks the denies, not that a kernel would
  fail to deny: on the 6.8 guest the kernel still denied an abstract connect under a policy
  compiled without them.

## Implementation and evidence (2026-10-02)

- `scripts/subcommands/init`: `unix_mediation_available` and `unix_denies_compiled` run in
  `install_host_boundary` after the DP stop and tool checks, before `apparmor_parser -r`; each
  refusal names af_unix and exits 60. `verify_tor` records the probed port; `print_status`
  prints `RUNNING`/`READY` states observed by `wait_healthy` and `verify_tor`, and the CP's
  Bind column is its `docker inspect` network mode (`none`).
- Tests: `tests/contract/stargate-cli/init_t198_test.sh` runs the real init with
  stubbed host commands for absent / `no` / empty feature and a deny-dropping compile (each:
  60, DP stopped, no load, nothing past the boundary) plus a positive control; runs the real
  `print_status`; and runs init's compile check with the installed parser against copies of
  the kernel's features with and without `network/af_unix`.
  `tests/contract/compose/local_compose_test.sh` pins the quickstart's volume count, key and
  pepper modes and the Engine floor for `volume.subpath` to compose and `scripts/lib/compose.sh`.
  `t162_enforcement_test.sh` (orphan): its wrong-owner leg and docker-tier installer leg now
  pass the af_unix gate so they still test what they name; the wrong-owner leg asserts it.
- Tests first: `specs/001-tor-route/evidence/T198-tests-first.json` (red: pre-fix init passes
  the absent-feature host and stops at keygen, exit 20; the first red with an earlier test
  version is kept under `superseded`).
- Live (QEMU guest from `guest-t182`, Ubuntu 24.04.5, Linux 6.8.0-142, parser 4.0.1, Docker
  29.1.3, Compose 2.40.3; logs in `target/runs/T198-vm/`, gitignored):
  - Kernel `raw_data` of the profile loaded by `apparmor_parser -T -r` equals the `-Q -T -K -S`
    output byte for byte, with the live features and with a copy lacking `af_unix`.
  - Under the installer-loaded profile an abstract-socket connect by UID 5102 fails with
    `connect: permission denied`; the unconfined control exchanges bytes.
  - Real `scripts/stargate init` (run 1, candidate before the root compile): positive rc=0 with
    the new table; feature absent (empty dir bind-mounted over `features/network`) rc=60;
    feature `no` rc=60; `parser.conf` `policy-features=kernel-5.4-vanilla` rc=60; each refusal
    left the loaded profile's `raw_sha256` unchanged and the DP exited; recovery rc=0. The
    new test passed on the guest; `STARGATE_TEST_TAGS=docker t162_enforcement_test.sh` passed.
  - Run 2 (final candidate, init sha256 `d6cee517…`): the same six phases with the same
    results (positive and recovery rc=0, the three refusals rc=60 with the loaded profile
    unchanged), the new test passed, and the docker-tier T162 test passed (installer leg exit
    20, abstract channel denied with a byte-exchange control). Parity and abstract-dial probes
    re-recorded in `guest-evidence/manual-probes.txt`. No browser run: no acceptance item
    involves the browser.
- Maintainer decisions (2026-10-02): THREAT-MODEL §3.1 and the quickstart prerequisites carry
  the approved DRAFT A / DRAFT B text verbatim (from an independent wording evaluation), and
  init step 2 the approved refusal sentence. No SECURITY-DECISIONS note.
- F1 folded (maintainer): on a fresh install `generate_keys` printed "provisioned observer
  identity without replacing existing CP/DP keys or pepper." although it had just generated
  them. T198's new quickstart step 3 contradicts that line, so it is an orphan this ticket
  makes stale. Init now prints "generated new CP/DP keys, pepper and observer identity." for a
  fresh install and keeps the old line for the observer-only upgrade; `init_t198_test.sh`
  checks both modes.
- F2 (Info, maintainer): Compose 2.25 accepts but ignores `volume.subpath`, which would mount
  all of `stargate-tor-state` into the observer (expected outcome: no READY, init exit 40). It
  gets no separate ticket; the approved Compose >= 2.26.0 prerequisite covers it. Neither init
  nor a test checks the Compose version.
- Tests first (final): one probe, `bash tests/contract/stargate-cli/init_t198_test.sh`, red on
  the HEAD init (14 failures across the af_unix refusals, positive control, key-generation
  notes, status table and missing compile check), green on the final candidate; the two
  earlier reds are kept under `superseded`. The test was renamed from
  `init_unix_mediation_test.sh` when F1 was folded in and reports every failing leg.
- Note on DRAFT A's evidence parenthetical: the copied feature sets show both the generic-rule
  downgrade and the dropped denies; the 5.4 vanilla policy-ABI pin shows the dropped denies
  (equal compiled output) with the parser reporting the unix rules "not enforced". The
  maintainer approved (2026-10-03) the replacement parenthetical that says so.

## Round 2 (2026-10-03)

- Round 1: Astra REWORK, one Major: `! cmp -s` accepted every non-zero cmp status, so a
  comparison error (2) or a missing cmp (127) passed the compile check. GLM APPROVE, one Minor:
  an unreadable feature file was reported as "is not 'yes'".
- Fix: `unix_denies_compiled` passes only when both compiles succeed and cmp exits exactly 1;
  equal output returns 1 and any failure returns 2, and both refuse (exit 60) with distinct
  messages. `unix_mediation_available` returns 2 for an unreadable file, which refuses with
  "cannot read ... AppArmor af_unix mediation is unverified". The init comment now matches
  §3.1 (AppArmor is the only control; the parser accepts the profile without error but drops
  the denies) and no longer claims `(enforce)` is shown.
- Tests: `init_t198_test.sh` adds cmp exit-2 and exit-127 fixtures (each 60, DP stopped, no
  profile load, nothing past the boundary) and asserts each refusal's reason. Round-2 red on
  the round-1 init: both cmp fixtures passed the boundary (exit 20) and the unreadable-file
  reason was missing; the three earlier reds are under `superseded`.
- Live check (2026-10-03, same guest, run 3, final round-2 init sha256 `59fdb82a…`, candidate
  tar `1f8193ac…`): real `scripts/stargate init` positive rc=0 with the new table (loaded
  profile raw_sha256 `fc9a61b5…`); with an empty dir masking `features/network`, rc=60 with
  "cannot read … af_unix mediation is unverified", the loaded profile unchanged and the DP
  exited. Logs: `target/runs/T198-vm/guest-evidence/guest-evidence-r2.tar`,
  `candidate-3.manifest`. That positive run kept existing keys; the fresh-install note is
  covered by the hermetic test only.

## Acceptance

1. `init` refuses (before starting the data plane) when
   `/sys/kernel/security/apparmor/features/network/af_unix` is absent or not `yes`, or when
   loading the profile downgrades its unix rules; test with a fixture of each shape, and a
   positive control on the supported host. The quickstart prerequisites and THREAT-MODEL §3.1
   state the requirement and scope the Ubuntu-only measurements (wording changes to
   THREAT-MODEL need maintainer approval).
2. The init status table prints only observed states; the control plane row reports no
   network bind.
3. The quickstart prerequisites and volume/key-mode statements match the compose file.

## Out-of-scope

Requiring Landlock ABI 6 (it would refuse the measured Ubuntu 6.8 host, ABI 4); T191 items.
