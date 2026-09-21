---
id: "T170"
title: "Permit Go self-signals and trusted-host DP lifecycle signals"
status: done
created: "2026-09-21"
last_updated: 2026-09-21
source: "T163 independently booted Ubuntu VM: AppArmor signal denials"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T162", "T168"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
decision_refs:
  - "specs/001-tor-route/tickets/T163-verify-packet-level-topology-boundaries.md"
remediates: "T162"
tests_first: []
reviews: { round: 1, date: 2026-09-21, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T170: Permit Go self-signals and trusted-host DP lifecycle signals

## Context

T163's independently booted Ubuntu VM (Linux 6.8.0-139-generic, AppArmor,
Landlock ABI 4, Docker 29.1.3) exposed a gap hidden by the earlier nested-host
runs. The production `stargate-dp` profile has no signal permissions. Kernel
audit records show denied send/receive of Go's `urg` and `rtmin+1` self-signals,
and denied receipt of `term`/`kill` from `runc` and `unconfined`. The DP cannot
complete its all-thread restriction installation, and Docker cannot stop it.
The run `T163-20260921-002710` reached no packet verdict; cleanup required
unloading the profile before removing the disposable DP container.

This is a focused repair under CONTRIBUTING's surgical-change rule. The Go
runtime must coordinate its own threads, and the existing trusted host must
be able to stop/restart its DP (Constitution II/III). Neither operation grants
the DP an IP origin or cross-plane management capability.

## Analysis

- **Must hold:** Go self-signals work under the enforcing production profile;
  required process confinement completes before serving. Trusted Docker/host
  peers can deliver INT, TERM and KILL. Signal sending to other profiles remains
  denied, independently of ordinary Unix ownership permission.
- **Gated:** write a live Docker regression before the profile change. Use the
  actual production DP image for startup and lifecycle checks, and a controlled
  same-UID signal-zero target to distinguish AppArmor denial from DAC or a
  nonexistent process. Missing helpers/setup errors never count as denial.
- **Residue:** cumulative packet captures and final DNS-channel closure remain
  T163's obligation; this ticket does not close them.

## Acceptance

1. Preserve a failing-before-fix live regression: the real DP cannot complete
   its SOCKS method exchange under the old profile, and host lifecycle signals
   are denied. Record the actual kernel/profile/environment and result.
2. Permit self-profile signaling and receive-only INT/TERM/KILL from the tested
   trusted host peers (`unconfined`, `runc`). Do not grant sending to those peers,
   arbitrary external signal reception, extra networking or new file access.
3. Under the enforcing profile, the production DP returns its exact SOCKS method
   reply after confinement installation. INT and TERM produce graceful exit 0;
   restart repeats startup; KILL succeeds with exit 137. A same-UID, visible
   target accepts signal zero from an unconfined control, while the profiled
   helper returns the specific kernel permission denial. No production security
   override is a supported bypass.
4. Document the trusted-host/self-profile distinction in the foundation contract
   and THREAT-MODEL in this change. Keep all IP/Unix fabric restrictions intact.
5. Run the live regression, `scripts/verify.sh`, both native reviewers, and the
   driver-controlled commit. T163 then resumes its full evidence sweep.

## Out-of-scope

DP/CP network permissions, Unix fabric or file allowlists, seccomp/Landlock
mechanisms, routing/authentication behavior, CP signal authority, and T163 closure.

## Execution record (2026-09-21)

The live regression was written and run before the profile change. On the
Ubuntu VM it reported `startup_method_reply=False` and
`signal_succeeded=False` for TERM, then correctly failed cleanup under the
old enforcing profile. Recovery unloaded the profile and removed the
disposable container; that recovery did not turn the result green. Kernel
records independently show denied Go `urg`/`rtmin+1` self-signals and
`term`/`kill` from `runc`/`unconfined`.

The old profile SHA-256 was
`57ae3a538c2b1ac18a4b2569f4ed906d9d92225094f37f335bac603e17db82fb`.
The repaired profile is
`d9e5a57253d357fb0af1010df5550c1582cc33afc6fb010f9f41e101e1e13803`.
The unchanged regression then passed: startup after confinement on every run,
host USR1 denial, TERM/INT exit 0, KILL exit 137, and same-UID signal-zero
control success versus specific permission denial under the production profile.
The fixture removed its container/profile and did not modify IP/Unix policies.

This used Linux 6.8.0-139-generic, Landlock ABI 4, amd64, Docker 29.1.3 and
Go 1.26.3. The real production image was
`sha256:46015820884045a6a53e598ff3f060f921783b66df3bf442be3f9896e24060a1`.
Its extracted DP binary SHA-256 was
`4679b0891a49e6b41e06712b2d4f205139ead3e6df2b9a32aa37124bf20338a8`,
identical to the pinned-toolchain source build. Raw local evidence remains
under `target/live-e2e/T170-20260921/`; no packet-matrix closure is claimed here.
