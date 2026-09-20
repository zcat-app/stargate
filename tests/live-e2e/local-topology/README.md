# Local topology packet evidence (T163 / T168)

This suite exercises the checked-in Local Compose deployment in the host and Tor
namespaces. Run it on a **dedicated, disposable Linux Docker host** with root,
AppArmor, Landlock ABI >= 4, seccomp TSYNC, `tcpdump`, `ip`, IPv4/IPv6 iptables, and Go. It installs the production
owner rules and AppArmor profile, then restores the initial firewall snapshots
and removes its project/profile. Do not run it on a workstation or a shared host.
The tool intentionally refuses a pre-existing `stargate-dp` profile or owner rule.

```sh
STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 \
  python3 tests/live-e2e/local-topology/run.py
```

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
CP health through the reserved sanitized observer is T164/T165's scope.

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

The historical 2026-09-20 `RuleAbsentStartup` run **failed** when both jumps were
removed and SOCKS admission remained active under T162's installer-only boundary.
T168 replaces that dependency with required process confinement and refines the
acceptance in the same reviewed change: auxiliary rule loss now requires safe
continued service; unavailable required confinement requires refusal. The old
failure is retained in T163's execution record. T163 remains open for cumulative
and physical-host evidence; this scoped nested-host repair does not close it.

If the host has no IPv6 route to `2001:db8::77`, the suite reports IPv6 as
unsupported only after checking that `::1:8881` refuses SOCKS5 and that the
IPv6 owner rule is present. When a route exists, IPv6 receives the same packet
and forwarder captures as IPv4. The test does not claim internet reachability
from packets addressed to documentation ranges.

Captures stay in `target/live-e2e/T163-<UTC timestamp>/`. They can contain the
test host's source IP, so keep them local and out of prompts/commits. The
contract gate runs only the fail-closed recorder and decision selftests:
`bash tests/contract/compose/topology_capture_test.sh`. A green `verify.sh`
without the live run proves those decision rules, not packet-level closure.
ARP is L2 traffic outside owner-match filtering; the packet claim here covers
TCP/UDP/IP only, with that residual stated in `THREAT-MODEL.md` §3.1.

The T168 scoped run on 2026-09-20 passed the full sequence on a disposable nested
Docker 29.8.1 host with Linux 6.8.0-124-generic, Landlock ABI 4, amd64. All 29
capture summaries had zero kernel drops. IPv6 had no routed egress path, so only
its loopback/refusal results are claimed. See T168's execution record and
`THREAT-MODEL.md` §3.1 for the measured scope and remaining T163 obligations.
