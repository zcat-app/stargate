---
id: "T163"
title: "Verify packet-level topology boundaries with capture controls"
status: deferred
created: "2026-09-13"
last_updated: 2026-09-20
source: "specs/001-tor-route/analysis/T134-local-topology.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T162", "T167", "T168"]
parallel: false
files_budget: 10
privacy_critical: true
complexity: "high"
risk: "medium"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/spec.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
decision_refs:
  - "specs/001-tor-route/analysis/T134-local-topology.md"
remediates: "T134"
tests_first: []
deferred_on: "T168"
deferred_reason: "blocked-on-new-ticket"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T163: Verify packet-level topology boundaries with capture controls

## Context

T134 demonstrated the candidate-A boundary mechanisms at prototype level
(privileged-container host-sim). The foundation contract requires the actual proof
against production namespaces: "Test actual packets in source and egress namespaces
with positive capture controls; NAT absence and connect timeout are insufficient."
This ticket delivers that evidence suite for the T162 topology, replaces the
non-discriminating TCP-timeout probe (audit M1), and rewrites the threat-model
gap language the repair retires.

## Analysis

- **Must hold:**
  - Every isolation assertion ships with a positive capture control proving the
    capture can see traffic when it is allowed — absence of packets is only
    evidence when presence is demonstrated on the same setup — and every recorder
    fails closed: readiness, clean-exit and decode checks invalidate the phase on
    failure; a missing/undecodable pcap never reads as "zero packets"
    (T134 §4 pattern, round-3 review).
  - Probes cover TCP, UDP and DNS-shaped (UDP/53-shaped to a documentation
    address) emission from the DP's identity in the source namespace and observe
    the egress interface(s) of the real deployment, **including the
    loopback-forwarder mediation probe** (an unrestricted loopback forwarder must
    be unusable by the DP identity; T134 A.9 pattern).
  - Both IP families are exercised or explicitly refused/documented per the
    constitution's per-family validation rule.
  - Required confinement failure is fail-closed: no SOCKS or management response
    before successful process restriction installation. T168 makes owner rules
    defense in depth; their loss must preserve zero independent IP emission and
    valid service across the supported restart paths. A warning cannot substitute
    for either measured property (foundation-boundaries.md, T168 refinement).
  - Fabric-success assertions require complete, upstream-derived results and are
    shown to reject authentication-only, timeout and dead-endpoint fixtures
    (T134 A.4f pattern); no assertion passes on absence of evidence.
  - No test weakens a contract to make the scheduler advance (Principle VII).
- **Gated:** the T162 suites continue to pin the topology shape and carry the
  atomic enforcement falsifier; this ticket adds the production-environment
  evidence breadth and its documented invocation path.
- **Residue:** live Tor circuit behaviour, real-browser fallback and integrated
  foundation validation stay with T126/T157/T155 and the release-cadence checks;
  physical-host proof is bounded by the environments where the suite is run.

## Acceptance

1. The suite demonstrates the discrimination gap it closes: the legacy
   TCP connect-timeout probe (audit M1) is shown unable to distinguish a filtered
   from a routed-dropped path, while the capture-based probes discriminate both
   directions (evidence preserved; the legacy probe is retired or annotated
   non-discriminating — no post-hoc "RED-first" claim is made for this ticket,
   which runs after T162).
2. A runnable, documented suite (contract or live-e2e layer, wired into
   `specs/001-tor-route/live-e2e/README.md` or the contract tree as appropriate)
   asserts from the production deployment namespaces: loopback reachability through
   `127.0.0.1:8881` (SOCKS5 positive control), non-loopback refusal, zero
   TCP/UDP/DNS-shaped packets emitted by the DP identity onto the egress
   interface, loopback-forwarder mediation closure, and T162's available socket
   caller matrix (DP→SOCKS succeeds; CP→SOCKS and both planes→raw-control fail,
   including after Tor recreates its socket). T164 implements CP→sanitized
   health; T165 tests that deployed observer path. Each negative is paired
   with a positive control on the same capture or socket fixture.
3. Per-family validation: IPv4 and IPv6 each either pass the same assertions or the
   unsupported family is refused/documented per the deployment contract.
4. Fail-closed confinement verification (T168's authorized mechanism refinement):
   remove IPv4 only, IPv6 only and both auxiliary owner jumps in a disposable
   deployment. Require continued loopback admission and zero independent IP
   packets/loopback mediation from confined DP probes, including Compose DP restart.
   Initial init and re-init install/verify owner rules. Separately make required
   kernel restriction installation unavailable and require startup refusal before
   SOCKS or management serving, then restore it and verify recovery. Logs or health
   warnings never substitute for these observed results. Preserve the historical
   RuleAbsentStartup failure below; it predates the process boundary.
5. The embedded-resolver DNS channel elimination is demonstrated (no resolver
   reachable from the DP's position; the T125 accepted DNS side channel is closed).
6. THREAT-MODEL.md §3.1/§5.8 verification status is updated with the MEASURED
   results (the mechanism text itself landed with T162 in the same reviewed change
   as the topology — Constitution V; T163 does not author mechanism descriptions),
   and SECURITY-DECISIONS.md records the retired T125 DNS-side-channel acceptance;
   no other posture claims change.
7. `bash scripts/verify.sh` GREEN on the exact candidate.

## Out-of-scope

Production topology changes (T162), CP Tor authority (T138), live Tor circuit or
real-browser evidence (T126/T157, release cadence), T155 integrated validation,
constitution amendments.

## Notes

The prototype pattern to industrialize is T134 analysis §4/§7 (uid-separated
attempts, `tcpdump` on the egress interface filtered to `tcp or udp`, kernel
counter cross-check, positive-control phase). The ARP observation from T134
(L2 frames are not gated by owner-match) should be recorded in the threat model as
a stated, bounded residual rather than re-litigated.

The six Docker-cadence Tor suites that still speak the removed TCP 9050/9051
endpoints are migrated by T162; this ticket consumes that landed transport and
does not duplicate the migration. Its scope is the production-namespace capture
and fail-closed measurement evidence.

## Execution record (2026-09-20, open)

The T163 recorder tests were authored first. Their initial run failed because
the `run` implementation was absent (`ModuleNotFoundError`), then passed after
the recorder/decision code landed. This is a new-harness red/green sequence,
not a retrospective claim that T162 first failed these tests. A forwarder
fixture stall was then exposed by a socket test that failed before its receive
lengths were fixed. A recorder cleanup test then failed before peer-recorder
cleanup was added; the contract gate passed all six tests afterward. The
deterministic repository gate then reported 25 PASS, one release-cadence SKIP,
zero FAIL on the staged candidate.

The live suite was attempted in disposable Docker hosts whose network
namespace contained the real Local Compose deployment. The first host could
build images but its private cgroup namespace prevented container start; a
second host using the host cgroup namespace passed a nested `hello-world`
control. Both that host and a `vfs` storage variant built the real images,
then `scripts/stargate init` exited 30 at Compose startup, before packet
capture. Their local daemon/Compose state showed the CP's nested key mount
failing under its read-only config-parent volume. An independent two-volume
`docker run --read-only --network none` on the workstation daemon reproduced
exit 125 at `/etc/stargate/keys`; a keys-only control reached CP application
startup. This establishes T167's mount blocker, not T163's packet properties.
The workstation's firewall was not changed; all disposable Docker hosts and
their AppArmor profiles were removed after these attempts. The ignored local
diagnostics remain under `target/live-e2e/T163-*/`.

At that defer point there was no TCP/UDP/DNS packet capture, rule-absence
admission, resolver, or full Tor fabric result. T167 repaired the CP mount
and passed review, allowing the resumed live suite below. The T125
DNS-side-channel decision remains open until the full evidence and admission
checks pass.

## Resumed execution (2026-09-20, deferred on T168)

After T167 commit `e33dc3b`, the disposable nested Docker host started the
checked-in Local Compose stack. Its first run proved IPv4 source/egress
positive controls and zero DP-identity TCP/UDP/DNS packets (DROP delta 3),
then exposed a harness parser defect: `tcpdump` says `1 packet captured` for a
single packet. A new test failed before the parser accepted that singular
summary, then the seven-test contract gate passed. That run's evidence is
`target/live-e2e/T163-20260920-161333/` (ignored and local).

The second run passed IPv4 source and egress capture controls, loopback
forwarder mediation, dummy resolver refusal, loopback-only listener checks,
and the real Tor caller matrix before/after socket recreation. IPv6 had no
egress route in that host; `::1:8881` refused SOCKS5. The run **failed** its
RuleAbsentStartup probe: after both IPv4 and IPv6 owner jumps were removed,
the running DP still returned the SOCKS5 method reply. The exact local result
and captures are under `target/live-e2e/T163-20260920-161720/`; cleanup
restored the firewall snapshots and removed the disposable Compose project
and AppArmor profile. The nested host is mechanism-level evidence, not the
physical-host proof required for final closure.

T168 owns the observed runtime fail-closed defect. T163 must rerun the full
suite after that repair, cover the supported startup/restart paths, obtain
physical-host evidence, and only then update the threat-model closure claim
and retire the T125 DNS-side-channel acceptance.


## T168 refinement and scoped rerun (2026-09-20)

T168 replaces the installer-only IP boundary with mandatory process confinement;
its authorized refinement of acceptance 4 is recorded above and in the foundation
contract. The scoped nested-host suite now passes rule-loss independence, Compose
restart, re-init and required-restriction failure/recovery with controlled captures.
The initial red result remains historical evidence of the earlier mechanism.
This does not close T163: cumulative/physical-host evidence and retirement of the
older accepted DNS-channel residue still belong to this ticket and T155.
