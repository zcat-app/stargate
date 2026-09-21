<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T163 packet evidence

## Outcome and approved scope

The final run `T163-20260921-024737` passed the complete Local deployment matrix
and cleanup with 29 valid captures and zero kernel drops. Its runner is the
byte-identical T171 code committed as `3519d91`. The legacy timeout experiment
also passed as `T163-legacy-20260921-030213`. Exact identities and earlier failed
attempts are preserved below.

On 2026-09-21 the maintainer replied **"vm is approved"** after receiving the
complete result and proposed host-scope wording. The foundation contract now
permits an independently booted Linux VM or bare-metal host, preserving every
packet/control, per-family, restart, signal/lifecycle and mandatory-confinement
failure/recovery obligation. This report establishes the measured guest boundary;
it makes no physical-NIC, hypervisor or untested kernel/architecture claim.

## Environment and source

The 2026-09-21 run uses an independently booted Ubuntu Linux VM with its own
kernel, systemd, Docker daemon, host network namespace and AppArmor policy.
The Local Compose DP uses that guest's host network namespace; Tor uses its
Docker bridge. QEMU runs in a temporary tooling container on the workstation.
The tested host kernel is the guest kernel, not the tooling container's kernel.
The virtual NIC and hypervisor are part of this test environment. This is not
a bare-metal or physical-NIC measurement.

| Component | Measured version or identity |
|---|---|
| Guest kernel | Linux `6.8.0-139-generic`, amd64 |
| Required restrictions | Landlock ABI 4; AppArmor and seccomp available |
| Docker | `29.1.3` |
| Compose | `2.40.3+ds1-0ubuntu1~24.04.1` |
| Go | `go1.26.3 linux/amd64` |
| VM | QEMU `11.0.3`, TCG, four virtual CPUs, 6 GiB RAM; initial runs used two CPUs |
| Native image builder | BuildKit `v0.32.2`, remote Buildx driver |
| Runtime source | `a0585ac`, including landed T167/T168/T169, plus the byte-identical T170 runtime inputs committed as `f09eb30`; the final T171 harness bytes committed as `3519d91`, with identities below |

The Ubuntu 24.04 cloud image was downloaded from the official release directory.
Its SHA-256 was
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`;
the checksum manifest's signature verified against the installed Ubuntu cloud
image keyring. The temporary BuildKit image resolved to
`moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8`.

The checked-in Dockerfiles were built by that native builder and loaded into
the guest daemon. `BUILDX_BUILDER=t163-native` selects it for the installer's
ordinary `compose up --build`; the Compose deployment and probes run in the
guest. The installer's existing `STARGATE_HEALTHCHECK_TIMEOUT=300` option allows
more time for startup under emulation. T171 separates the 30-second helper-process
budget from unchanged 0.8-second probe socket operations; recorders still require
valid readiness and clean capture.
An earlier emulated build attempt was canceled at Compose build,
before packet validation, and its temporary project/rules/profile were cleaned
up. That attempt is not counted as a packet result.

The original deployment runner SHA-256 was
`92ccb93c9c7c77c4413fd47c13170b140a6943441ba1df8d62744eaec1034d18`.
The first T171 runner candidate SHA-256 was
`a02916931dfd0339a660646f69157390008810227529e842fffe9086971574ae`;
its focused regression source SHA-256 was
`7d8ec1b501cfa715d3ee49d986fac38dc3acedd0481411ff7959945469e0b1ea`.
The new timeout experiment SHA-256 is
`2fb3e82907e8ab14d8e5eb22a16c71bca57d1a2b66e9f89cc2a694fdfd68be18`.
The initial cached production DP binary was also reproduced byte for byte with
Go 1.26.3, `GOWORK=off`, `CGO_ENABLED=0` and the Dockerfile's build flags;
both SHA-256 values were
`4679b0891a49e6b41e06712b2d4f205139ead3e6df2b9a32aa37124bf20338a8`.
The first freshly rebuilt guest DP image was
`sha256:46015820884045a6a53e598ff3f060f921783b66df3bf442be3f9896e24060a1`;
its extracted binary has that same SHA-256. The T170 AppArmor profile SHA-256 is
`d9e5a57253d357fb0af1010df5550c1582cc33afc6fb010f9f41e101e1e13803`.
No network/file policy or process-confinement code changed for this host.
Before the four-CPU run, all 132 tracked non-Markdown files under the runtime,
deployment, scripts and relevant contract/live-test paths matched the checkout
byte for byte. The local SHA-256 manifest is
`target/live-e2e/T163-vm-evidence/runtime-inputs.json`, with SHA-256
`ee048d80537ea12a32a68c238e3dda6b6089b2cb42e781d35fd9e601a70a99db`.
After the successful T171 run, the same 132 paths again matched exactly.
The updated manifest is `runtime-inputs-T171.json` in that evidence directory,
with SHA-256
`7ba58b48cfe03d95e2f07467911f5513dd5719b15666bc355caf3a11d5be91fc`.
The first T171 candidate's image after re-init was
`sha256:2475350941bbf63542eae0c0ac4922ed27750376a250c0deb8dd3b678b8a7625`;
its extracted DP binary again matched the same
`4679b0891a49e6b41e06712b2d4f205139ead3e6df2b9a32aa37124bf20338a8`
SHA-256. `host-provenance.txt` records the selected Go 1.26.3 toolchain,
host-tool/kernel content hashes, and cleanup checks: zero remaining containers,
OUTPUT policies restored, no test AppArmor profile, recorder or namespace.

## Enforcing-profile signal and lifecycle evidence (T170)

T170's regression first failed against the old profile, including startup and
host TERM delivery. The unchanged regression passed after the profile repair:
each real DP startup completed confinement and returned the exact method reply;
host USR1 was denied, TERM/INT exited 0 and KILL exited 137. Repeated startup
covered restart. A visible same-UID target accepted signal zero from the
unconfined control, while the profiled helper received a specific permission
denial. This used the same guest kernel, Docker and Go versions and the profile
hash above. The production binary matched the final packet run's binary.
See [T170's execution record](../tickets/T170-repair-apparmor-signal-lifecycle.md)
and the local `target/live-e2e/T170-20260921/` red/green artifacts.

## Legacy timeout discrimination — measured

`legacy_timeout_probe.py` creates a temporary veth peer that silently drops TCP.
An unrestricted UID reaches that peer; the DP UID is dropped in the source
namespace's OUTPUT chain. Both connects raise `TimeoutError`. Source and veth
recorders must be ready, decode successfully, exit cleanly and report zero
kernel drops. The OUTPUT counter independently proves the filtered attempt.

At `T163-legacy-20260921-001347`, and repeated with the first T171 candidate at
`T163-legacy-20260921-020923`, the measured result was:

| Observation | Routed then dropped | Filtered before emission |
|---|---:|---:|
| Connect result | `TimeoutError` | `TimeoutError` |
| Source (`any`) SYN count | 1 | 0 |
| Egress veth SYN count | 1 | 0 |

The owner DROP counter increased by one. Both recorders reported zero kernel
drops. The fixture removed its namespace, veth and OUTPUT rule/chain afterward.
This closes acceptance 1 with actual socket and packet results; the older
synthetic timeout example is not the sole evidence.

## Earlier nested-host result

Before the full VM work, `T163-20260920-225945` passed the complete suite from a
shallow `/repo` checkout at `a0585ac` in a disposable nested Docker 29.8.1 host.
Its 29 captures had zero kernel drops. Listener, IPv4 packet controls, mediation,
Tor caller/socket recreation, owner-loss/restart, re-init and confinement
failure/recovery passed; routed IPv6 was unavailable and only its refusal and
loopback checks were measured. This remains evidence for that earlier host and
runner, not proof of the later VM's AppArmor/runtime behavior. The VM exposed the
additional T170/T171 defects below; neither the nested pass nor a failed VM run
is substituted for the final corrected VM result.

## Complete deployment matrix

The VM run `T163-20260921-002710` failed before captures. Kernel audit
records show the production AppArmor profile denying Go self-signals `urg`
and `rtmin+1`, and lifecycle `term`/`kill` received from `runc` and
`unconfined`. Docker could not stop the DP during cleanup. Removing the
profile allowed the disposable deployment to be removed. This is a real
profile/lifecycle defect, repaired by T170; that failed run is not closure evidence.

After T170's focused regression passed, the two-CPU run
`T163-20260921-010358` passed listener reachability/refusal but stopped when a
positive TCP probe process exceeded its 2.8-second launch/operation deadline.
Run `T163-20260921-011622` passed the IPv4 source/egress matrix with all controls,
zero marked DP packets and owner DROP delta 3, then exceeded the same process
deadline on the forwarder positive control. Both attempts failed overall and
cleaned up their deployments. A launcher timeout was never counted as denial.

The VM was then cleanly shut down and booted with four virtual CPUs. The next
run used `nice -n -10` for the test runner and its probe children. This is test
scheduling priority, not a production security override; the Docker daemon and
deployed services kept their ordinary scheduling. Run `T163-20260921-013220`
again exceeded the 2.8-second helper budget after listener checks and cleaned
up. T171 addresses the harness startup/fixture lifetime issue; these three
attempts remain failed results.

With the first T171 candidate, run `T163-20260921-015428` completed with exit 0, including cleanup.
The measured results were:

| Phase | Observed result |
|---|---|
| Listener | Exact SOCKS method reply on `127.0.0.1:8881`; non-loopback and `::1:8881` refused |
| Initial IPv4 source/egress | All TCP/UDP/DNS positive controls visible; zero marked DP packets; owner DROP delta 3 |
| Loopback mediation | Unrestricted forwarder/resolver controls succeeded; DP attempts denied |
| Tor Unix fabric | Available caller matrix passed before and after socket recreation |
| IPv4-only, IPv6-only and both owner jumps removed | Admission continued; production-confinement helpers emitted zero marked traffic and could not use the loopback forwarder/resolver; owner DROP delta 0 |
| DP restart with both jumps absent | Admission and all confinement/mediation assertions passed again |
| Re-init | Owner rules restored and service resumed |
| Required feature failure | Denying each of `landlock_create_ruleset`, `landlock_restrict_self` and `seccomp` caused startup refusal before serving; each recovery passed |
| IPv6 | No routed egress path; listener refused; loopback resolver controls and confined denial passed |
| Recorders and cleanup | All 29 captures decoded and exited cleanly, zero kernel drops; deployment/profile removed and firewall snapshots restored |

The IPv4 source recorder used `any`, and the egress recorder used the guest's
`enp0s2`. The capture manifest SHA-256 is
`ff254ae0240b241ab22054557bd07f17056299c6c310ad7a4f449432c646c3df`.
Raw captures and aggregate summaries are retained locally under
`target/live-e2e/T163-vm-evidence/`. They are not committed.

These measurements distinguish the real DP's listener/startup/restart behavior
from UID-5102 attack helpers calling the production confinement code. A SOCKS
method reply establishes negotiation reachability, not authenticated destination
bytes or a completed Tor circuit. No routed IPv6, arm64, newer Landlock ABI,
bare-metal/physical-NIC, browser-fallback or release result is claimed. The
approved host-scope refinement above replaces the former physical-host wording
while preserving these limits and all packet assertions.

## Final-candidate follow-up

Before T171 commit, a new regression demonstrated that a fixture I/O failure
after a working positive control could falsely count as denial. Both forwarder
and resolver cases failed first. The corrected harness propagates those errors
into phase failure after cleanup; all 17 focused tests passed. The earlier
candidate's approvals were invalidated. The earlier VM pass remains evidence
for its recorded bytes; it is not relabeled as a run of the correction.

The corrected runner SHA-256 is
`e9131771fab1e47cec3242a2716e6d26280f3c15f34b934dee80cca733d3f6da`;
the focused test source SHA-256 is
`a26d70e61ed53ce2fb11f8ee51f08d668734d25f6990ee8ffc0b8b6a58c45a11`.
All 132 runtime/deployment/test paths matched the guest before its new run.
The final source manifest `runtime-inputs-T171-final.json` has SHA-256
`69e3f860b9cd69d7f29a70931ae4ccf8548f326d83d3b705a9b479a7ffb2177f`.
Run `T163-20260921-024737` passed the complete sequence with exit 0, including
all refusal/recovery phases and cleanup. All 29 captures were valid with zero
kernel drops. Its `capture-manifest.json` SHA-256 is
`c665c3bb6d511260e95cd989c2b2c303a3fea9f820178aa4d9b0045a774a5f58`.
The matrix above passed again on these corrected bytes. The legacy experiment
also passed again as `T163-legacy-20260921-030213`: both paths timed out,
both captures saw one routed SYN and zero filtered SYNs, and the owner DROP
counter was one. The guest used the same kernel, four-CPU configuration,
toolchain and scheduling settings.
The final image was
`sha256:2c258064a1b265370be3c80e1a19e69b7ad09688396bc5e22df1763f05eb4d32`;
its extracted DP binary again matched
`4679b0891a49e6b41e06712b2d4f205139ead3e6df2b9a32aa37124bf20338a8`.
`final-cleanup-provenance.txt` confirms zero remaining containers, capture
processes, test AppArmor profiles or timeout namespaces. Existing firewall
policies/rules matched the original snapshots after ignoring traffic counters;
Docker had additionally initialized an empty IPv4 raw table with ACCEPT policies
and no rules. No packet-permitting exception was left by either experiment.

The complete suite was invoked from the guest checkout with these settings.
The incidental account-specific cache paths are normalized to `$HOME` for
publication; the toolchain, build flags and measured byte identities are unchanged.

```sh
export PATH=/usr/local/go/bin:$PATH
export GOPATH="$HOME/go" GOCACHE="$HOME/.cache/go-build"
export GOTOOLCHAIN=go1.26.3 CGO_ENABLED=0
export BUILDX_BUILDER=t163-native STARGATE_HEALTHCHECK_TIMEOUT=300
export STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 PYTHONUNBUFFERED=1
nice -n -10 python3 -B tests/live-e2e/local-topology/run.py
```

The separate timeout experiment uses the same live/disposable opt-in:

```sh
python3 -B tests/live-e2e/local-topology/legacy_timeout_probe.py
```
