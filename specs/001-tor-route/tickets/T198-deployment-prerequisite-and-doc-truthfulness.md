---
id: T198
title: 'Gate init on af_unix mediation; truthful init and quickstart'
status: pending
created: 2026-10-01
last_updated: 2026-10-01
source: "T155 attempt 3 cumulative redteam (candidate 989b8f9): A1-M2 (narrowed Minor), A3-m1, A3-m5; all survived falsification"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 8   # ticket + STATUS.md + scripts/subcommands/init + init test + THREAT-MODEL.md + quickstart.md + compose test + SECURITY-DECISIONS note if the maintainer wants one
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
reviews: {}
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
