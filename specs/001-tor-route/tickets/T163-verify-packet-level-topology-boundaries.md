---
id: "T163"
title: "Verify packet-level topology boundaries with capture controls"
status: "pending"
created: "2026-09-13"
last_updated: "2026-09-13"
source: "specs/001-tor-route/analysis/T134-local-topology.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T162"]
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
  - Rule absence is fail-closed: with owner-match rules missing (fresh boot,
    reboot, manual flush) the DP must be observably unable to admit — no SOCKS
    admission succeeds on any supported startup/restart path; a warning, log line
    or unhealthy status with a functioning listener explicitly FAILS the probe
    (Constitution: "The proxy MUST refuse startup when these conditions are not
    met"; round-1 review F3 — warning-only outcomes cannot satisfy closure).
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
   interface, loopback-forwarder mediation closure, and the socket caller matrix
   (DP→SOCKS ✓ / CP→sanitized ✓ / cross-denials, including after socket
   recreation) — each negative paired with a positive control on the same capture.
3. Per-family validation: IPv4 and IPv6 each either pass the same assertions or the
   unsupported family is refused/documented per the deployment contract.
4. Fail-closed rule verification: an execution path (init/health/startup check)
   detects absent owner-match rules and the DP is observably unable to admit —
   no SOCKS admission succeeds. A RuleAbsentStartup probe removes the required
   rules in a disposable deployment, exercises every supported startup/restart
   path, and asserts admission denial; a log line, warning or unhealthy status
   with a functioning listener explicitly FAILS the probe (refusal only — never
   "blocks/flags").
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
