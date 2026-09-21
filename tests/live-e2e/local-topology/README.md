# Local topology packet evidence (T163 / T168)

This suite exercises the checked-in Local Compose deployment in the host and Tor
namespaces. Run it on a **dedicated, disposable Linux Docker host** with root,
AppArmor, Landlock ABI >= 4, seccomp TSYNC, `tcpdump`, `ip`, `ss`, IPv4/IPv6 iptables, and Go. It installs the production
owner rules and AppArmor profile, then restores the initial firewall snapshots
and removes its project/profile. Do not run it on a workstation or a shared host.
The tool intentionally refuses a pre-existing `stargate-dp` profile or owner rule.
An independently booted Linux VM is an approved host for T163: it must run the
real deployment and enforcement in its own kernel and namespaces. Record whether
the host is a VM or bare metal; VM results do not establish physical-NIC or
hypervisor behavior.

```sh
set -e
STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 \
  python3 tests/live-e2e/local-topology/run.py

# Acceptance 1: both connects time out; only the routed SYN is captured.
STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 \
  python3 -B tests/live-e2e/local-topology/legacy_timeout_probe.py
```

The timeout comparison creates a temporary veth pair and network namespace.
An unrestricted UID reaches a peer that silently drops TCP; the DP UID hits an
OUTPUT owner DROP before emission. Both must raise `TimeoutError`, but source
and veth captures must see only the unrestricted SYN, and the owner counter
must record the filtered attempt. It removes its own rules and fixture;
evidence stays under `target/live-e2e/T163-legacy-*/`. This is retrospective
discrimination evidence for the old probe, not a historical tests-first claim.

The runner uses the real `scripts/stargate init` and Local Compose file. Its
packet probes execute as UID 5102 in the same **host network namespace** as the
deployed DP. `tcpdump` records on `any` (source namespace) and on the actual
IPv4/IPv6 route interface to documentation-only targets. Each capture includes
unrestricted-UID TCP, UDP, and UDP/53-shaped controls with distinct destination
markers, followed by DP-UID attempts. A missing recorder, missing pcap, bad
decode, kernel packet drops, absent positive control, or insufficient DROP-counter delta fails the
run. TCP connect timeout alone has no verdict role: a filtered SYN and a routed
SYN dropped later can both time out. The controls make those paths distinguishable.

The runner also checks the real `127.0.0.1:8881` SOCKS5 method exchange,
non-loopback listener refusal, IPv6 `::1` refusal, a host-loopback forwarding
service and dummy resolver, and the existing Tor socket caller matrix before
and after Tor restarts. A SOCKS5 method reply proves admission/transport only;
it does not claim that Tor completed an upstream circuit or returned destination
bytes. The socket matrix's real control-socket reply is its positive control.
The same run now calls `observer.py` after the DP topology phases. It checks
the actual CP and observer identities, network modes, mounts and image source
label; places a fixed-output probe in CP's disposable config volume; and requires
an authenticated finite health reply there. A CP-namespace packet capture
requires a visible loopback positive control and no packet to Tor control.
It tests invalid caller and command inputs against a fake Tor control socket
only after stopping the disposable Tor container. Each refusal must leave the
fake's command log unchanged. The fake records command names without retaining
cookie bytes. With the deployed CP monitor running, the same listener then
drives valid, malformed and timed-out samples plus observer loss and recovery.
The DP event consumer must record the exact STARTED, HEALTHY and UNHEALTHY
transitions without repeats or invented STOPPED, CRASHED or RESTARTED events.
The event sequence's positive STARTED control fails if CP never samples.
Tor and observer restart recovery and application log and CP-state raw-marker
scans are part of this result. Finally, a disposable token is loaded through CP's normal reload;
with CP stopped and Tor natively healthy, DP must authenticate and return
destination bytes through the real Tor sidecar. A structural or fake-boundary pass alone is not a
production namespace result. Raw evidence stays under the same ignored
`target/live-e2e/T163-*` directory and is consumed by T165/T155.

The observer verdict selftest runs in the ordinary contract gate:
`python3 -B -m unittest discover -s tests/live-e2e/local-topology -p test_observer.py`.
T124 still owns the Tor-native healthcheck's cold-bootstrap behavior. That
healthcheck runs inside Tor's TCB and grants no CP-facing control command.

T168 adds a second phase which removes IPv4 only, IPv6 only and both owner
jumps. The actual Compose DP must continue admitting safely, including after
`docker compose restart stargate-dp`. Re-init must restore the owner rules.
The attack helper is a static Go test executable built from the same candidate;
it calls production `confinement.Apply` before attempting TCP/UDP/DNS, listener
reuse and Fast Open. It runs as UID 5102 in the DP network namespace. A separate
`docker exec` process would not inherit the DP's filters and is not used to
claim process confinement. Exit 77 means an observed kernel permission denial;
startup failure, crash, unknown errno and missing helper all fail the suite.
The captures retain unrestricted positive controls; owner DROP counters are
required only in the initial owner-rule phase. Loopback resolver denial is also
checked for IPv6 even when no routed IPv6 capture is possible.

Test-only Compose seccomp overrides separately make `landlock_create_ruleset`,
`landlock_restrict_self` and `seccomp` unavailable. Each must cause the real DP
to exit with the fixed confinement error before admission; removing the override
must restore service. No such policy override is a supported operator bypass.
The installer/AppArmor and Unix fabric requirements remain unchanged.

T171 separates helper startup from network-operation timing: ordinary and
confined helper processes have a finite 30-second budget, while the ordinary
probe's socket operations still use 0.8 seconds. Process expiry, missing
completion markers and unknown confinement exits fail the run. Forwarder and
resolver workers start after capture readiness, remain available through both
bounded probes, drain queued attempts, and stop before captures close. Setup
or probe failure also joins workers and closes recorders. Fixture I/O errors
invalidate the phase even after a successful positive control. A slow interpreter
must not expire the positive fixture or become a denial result.

The historical 2026-09-20 `RuleAbsentStartup` run **failed** when both jumps were
removed and SOCKS admission remained active under T162's installer-only boundary.
T168 replaces that dependency with required process confinement and refines the
acceptance in the same reviewed change: auxiliary rule loss now requires safe
continued service; unavailable required confinement requires refusal. The old
failure is retained in T163's execution record. That nested-host repair alone
did not close T163. The final independently booted VM result and approved
evidence scope are recorded in the [T163 report][t163-evidence].

If the host has no IPv6 route to `2001:db8::77`, the suite reports IPv6 as
unsupported only after checking that `::1:8881` refuses SOCKS5 and that the
IPv6 owner rule is present. When a route exists, IPv6 receives the same packet
and forwarder captures as IPv4. The test does not claim internet reachability
from packets addressed to documentation ranges.

Captures stay in `target/live-e2e/T163-<UTC timestamp>/`. They can contain the
test host's source IP, so keep them local and out of prompts/commits. The
contract gate runs the fail-closed recorder and decision selftests, including
the legacy experiment's import, packet controls, owner-counter parsing,
child outcomes and cleanup with privileged I/O replaced by fixtures:
`bash tests/contract/compose/topology_capture_test.sh`. A green `verify.sh`
without the live run proves those decision rules, not packet-level closure.
ARP is L2 traffic outside owner-match filtering; the packet claim here covers
TCP/UDP/IP only, with that residual stated in `THREAT-MODEL.md` §3.1.

The T168 scoped run on 2026-09-20 passed the full sequence on a disposable nested
Docker 29.8.1 host with Linux 6.8.0-124-generic, Landlock ABI 4, amd64. All 29
capture summaries had zero kernel drops. IPv6 had no routed egress path, so only
its loopback/refusal results are claimed. See T168's execution record and
`THREAT-MODEL.md` §3.1 for the measured scope and remaining T163 obligations.

The final T163 VM run on 2026-09-21 passed on Ubuntu Linux 6.8.0-139-generic,
amd64, Landlock ABI 4, Docker 29.1.3 and Compose 2.40.3. All 29 captures were
valid with zero kernel drops, including rule-loss/restart and mandatory-feature
failure/recovery. Routed IPv6 was unavailable; its loopback/refusal controls
passed. The [measured report][t163-evidence] records source identities, commands,
earlier failures, legacy-timeout discrimination and the remaining scope limits.

[t163-evidence]: ../../../specs/001-tor-route/analysis/T163-packet-evidence.md

## AppArmor signal lifecycle (T170)

On the same dedicated disposable host, with the real DP image built from the
candidate and no loaded `stargate-dp` profile, run:

```sh
STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 GOTOOLCHAIN=go1.26.3 \
  python3 -B tests/live-e2e/local-topology/apparmor_signals.py
```

This loads the production profile, starts the real DP on `127.0.0.1:18881`,
and requires its exact SOCKS method reply after process confinement. A public
test pepper and an empty token store suffice for this negotiation-only check;
it does not claim authenticated forwarding. Host USR1 must be denied. Docker
TERM and host INT must exit gracefully with code 0; restart repeats startup;
Docker KILL must exit with code 137 while the profile remains enforcing.

A separate static test helper uses host PID visibility and a same-UID dummy
target to isolate the signal-peer boundary. The unconfined control must pass
signal zero; the profiled helper must observe EPERM/EACCES, not a missing target
or launch failure. These helper options are test controls, not production
deployment settings. The test removes its container and profile. Recovery after
an old-profile cleanup denial still fails the test; unloading the profile cannot
turn a failed lifecycle check green.
