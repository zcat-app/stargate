---
id: "T162"
title: "Implement host-loopback DP with unix-socket sidecar fabric"
status: in-review
created: "2026-09-13"
last_updated: 2026-09-20
source: "specs/001-tor-route/analysis/T134-local-topology.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T134", "T138"]
parallel: false
files_budget: 37
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/spec.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
  - "specs/001-tor-route/contracts/torrc.md"
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

# T162: Implement host-loopback DP with unix-socket sidecar fabric

## Context

T134's investigation (analysis/T134-local-topology.md) recommends candidate A: the DP
binds the host network namespace's loopback directly under the strict bind check, the
DP/CP/Tor sidecar reachability moves to unix-socket fabric on a shared volume (tor's
private 0700 socket directory re-exposed by an image-owned hardlink hook), Tor becomes
the only bridge-attached container, and DP/CP IP egress is denied at packet level by
host owner-match rules provisioned by the installer. This replaces the T125 wildcard
exception (audit B1) and the unproven no-masquerade boundary (audit M1). This ticket
implements the topology; T163 owns the capture-verified evidence suite.

## Analysis

- **Must hold:**
  - `STARGATE_IN_CONTAINER` and the wildcard exception are deleted; every bind goes
    through the strict loopback-only policy (Constitution Deployment Model; FR-010).
  - The DP reaches Tor only via the unix fabric; SOCKS5h hostname pass-through,
    verbatim username forwarding and empty upstream password are unchanged
    (Principle I/III; FR-002/FR-007).
  - DP/CP attach to no docker network; Tor is the sole egress-attached service
    (Principle III actor/traffic matrix; foundation contract §"Deployment and
    authority").
  - The installer installs owner-match egress rules (v4+v6) for the DP uid before
    the stack starts — loopback-scoped ESTABLISHED,RELATED plus **silent** DROP
    only (no blanket loopback, no LOG target, no unrestricted reply acceptance) —
    and the deployment fails closed when they cannot be installed or verified.
    A reverse-initiated off-loopback listener under the DP identity must be
    unusable (SYN-ACK/replies dropped) while loopback admission keeps working
    (T134 A.11 pattern).
  - Sidecar authority is enforced by **mount-separated per-consumer fabrics**: the
    DP fabric volume carries only the SOCKS re-exposure; the CP fabric is reserved
    for T164's sanitized observer endpoint. The raw Tor control socket remains
    tor-private and is not exposed to CP. CP cannot reach SOCKS or raw control,
    and DP cannot reach raw control by construction. T164 implements the T138
    observer after this fabric exists; T165 proves its CP-facing caller matrix.
  - The **abstract-socket channel is closed**: an AppArmor profile for the DP
    mediating AF_UNIX — allowing exactly its pathname fabric sockets, its dp.sock
    server socket AND its control.sock client connection (WatchEvents;
    contracts/control-grpc.md — both IPC directions must keep working) — and
    denying abstract-socket connects, is loaded by the installer. T134 A.12
    demonstrates the channel open without it. A deployment that cannot load
    profiles escalates the topology choice instead of shipping.
  - THREAT-MODEL.md is updated in THIS reviewed change with the implemented
    mechanisms, trusted host state and pending T163 evidence (Constitution V:
    same-change obligation); T163 later updates only measured results.
  - FR-011/FR-012/torrc contract and compose structural tests are amended in the
    same change (no inherited stale pin).
- **Gated:** bind and forwarder unit suites (existing + new red-first regressions);
  torrc byte-match and cold-volume regressions; compose structural M-rules.
- **Residue:** production-namespace capture breadth, per-family validation and
  reboot re-run evidence are extended by T163 — but the *mandatory behavioral
  falsifiers* for the egress enforcement and the socket caller matrix live in THIS
  ticket, atomic with its implementation (Constitution VII; round-1 review F2);
  THREAT-MODEL's mechanism text lands here, its measured-results update with T163.

## Acceptance

1. RED-first regressions preserved: the unix-dial and strict-bind tests fail on the
   pre-change tree (transcripts in the ticket notes), then pass after implementation.
2. Forwarder: `STARGATE_TOR_SOCKS_ADDR=unix://<path>` dials the fabric over
   AF_UNIX; hostname-form targets, opaque username forwarding and zero-length
   upstream password behave exactly as the TCP path (existing forwarder contract
   tests remain green; new unix-path test added).
3. Bind: `bind.CheckListener` loses the container-boundary parameter and the
   wildcard acceptance; `STARGATE_IN_CONTAINER` is removed from the startup wiring
   and compose; a wildcard or specific non-loopback address is refused in every
   mode; the DP in the host namespace binds `127.0.0.1:8881` via the strict path.
4. Tor image + socket authority: rendered torrc switches to `SocksPort unix:`
   inside a tor-private 0700 directory (tor 0.4.9.12 refuses group-accessible
   socket dirs, T134 §3). The Stargate-owned entrypoint re-exposes only SOCKS
   into the DP fabric (0660, DP group; hardlink hook), including after Tor
   recreates its socket. Raw Tor control stays in a tor-private directory,
   reachable inside Tor for its native healthcheck and by the test harness;
   neither CP nor DP mounts it or the cookie. Contracts/torrc.md golden and
   byte-match tests are updated. A **SocketCallerMatrix** regression (real
   sockets, red-first) demonstrates DP→SOCKS succeeding and CP→SOCKS,
   CP→raw-control, DP→raw-control and unprivileged→SOCKS denied, including
   after Tor restart. T164 owns the observer implementation, its positive
   CP→sanitized-health test and its own restart behavior; T165 owns the
   deployed CP-facing caller matrix. This handoff preserves the T138 boundary.
5. Compose: DP `network_mode: host` (loopback bind only, no ports publish); CP
   `network_mode: none` with CP-fabric access only; stargate-host /
   stargate-internal / stargate-cp-tor networks removed; the DP fabric is
   mounted by Tor+DP only, while the CP-only observer fabric is reserved for
   T164 and mounted by CP but not Tor. Neither plane mounts the other's fabric.
   Until T164, Tor health observation is unavailable and advisory; CP holds
   no raw control credential or route. local_compose_test.sh,
   network_hardening_test.go AND `tests/contract/tor/port_exposure_test.go`
   (which fatally resolves the removed stargate-internal network today) are
   rewritten to pin the new shape (no orphaned M13/stargate-host/internal-net
   assertions).
6. Installer + enforcement, atomic with their regressions: `scripts/stargate init`
   (and stack startup where applicable) installs the DP-uid owner-match rules on
   both families — **loopback-scoped ESTABLISHED,RELATED plus silent DROP only; no
   blanket loopback ACCEPT, no IP-initiated exception, no unrestricted reply
   acceptance, and no LOG target** (per-packet kernel records would violate
   Constitution III's aggregate-only rule; T134 A.9 closes the forwarder-mediation
   path and A.11 the reverse-initiated off-loopback reply channel) — and refuses to
   start the DP when they cannot be installed or verified, observably (no admission
   succeeds), on every supported startup/restart path. Four behavioral falsifiers
   ship in this ticket, red-first on real sockets: (a) missing-rule and
   ineffective-rule variants (rules present but not matching, or installer
   reporting success without effect) each fail pre-change and pass post-change;
   (b) **DeniedEgressNoDetailedLogs** — denied TCP/UDP attempts produce zero
   escaped packets (positive capture control) AND no packet-specific metadata
   appears in kernel, journal or container logs; (c) **ReverseChannelClosed** — an
   off-loopback listener under the DP identity cannot complete an externally
   initiated exchange while loopback admission still works, demonstrated against
   the unrestricted-ESTABLISHED shape (falsifier leg) and the shipped shape
   (closure leg); (d) **AbstractSocketForwarderDenied** — with the profile
   loaded, a host abstract-UDS forwarder (T134 A.12 fixture) is unusable by the
   DP identity while ALL authorized AF_UNIX paths keep working, positively
   asserted: authenticated WatchEvents delivery and reconnection over
   control.sock, ReloadTokens over dp.sock, and the Tor fabric dial (falsifier
   leg: mediation succeeds with the profile unloaded). Warning-only outcomes
   explicitly fail; every capture assertion in these regressions fails closed on
   recorder failure (readiness, clean exit, decodable pcap — T134 §4 pattern).
7. Spec/contracts/threat model amended in the same PR: FR-007 (upstream endpoint
   wording — DP-only Unix SOCKS fabric, no `tor:9050` compose path), FR-010/FR-011/FR-012
   wording, architecture spec §4.2 endpoint descriptions, data-model.md §6 volume
   identities, torrc contract, foundation-boundaries pointer, SECURITY-DECISIONS.md
   entry recording the withdrawal of the T125 posture (no constitutional
   amendment — T156 text already forbids the exception), and a THREAT-MODEL.md
   update describing the implemented mechanisms (host-netns placement, silent
   owner-match enforcement and its failure behavior, per-consumer socket
   authority, trusted installer host state) with T163's measurements explicitly
   pending (Constitution V: same-change obligation).
8. `bash scripts/verify.sh` GREEN on the exact candidate.

## Out-of-scope

Production-namespace capture breadth and measured-results updates (T163); the
CP-side observation-authority design (T138 — prerequisite for that surface, not
rewritten here); integrated foundation validation (T155); LAN/VPS profiles;
candidate B relay (documented fallback in the T134 report).

## Notes

Tests-first evidence for Acceptance 1 (2026-09-20; pre-fix HEAD
`5d62aece8bd57e8263cd51425e9fd0da6c2deaea`): after writing the
strict-bind and AF_UNIX forwarder regressions, before changing their production
code, `go test ./internal/bind -run TestCheckListener -count=1 -timeout=15s`
failed because `CheckListener("0.0.0.0", true)` and `CheckListener("::", true)`
returned nil. `go test ./internal/forward -run
TestForwardUnixSocketPreservesSOCKS5hAuth -count=1 -timeout=10s` failed at
`read BND reply: ... i/o timeout` against the real recording AF_UNIX SOCKS
server (the old forwarder attempted the `unix://` endpoint as TCP). After the
production changes, both same named tests passed (`bind` 0.004s, `forward`
0.009s). The first forward test run had an unbounded read and hit the test
timeout; the fixture was corrected with a three-second client read deadline
before implementation, then rerun to produce the intended red result above.

The torrc byte-match and Compose structural assertions also failed before
their source/config rewrites, then passed. The Tor control helper's real-argv
test first observed the old `docker exec ... nc 127.0.0.1 9051` form,
then passed with the Tor-private Unix control socket. The host-boundary
installer test first failed because the profile was absent; it now parses
the profile and pins installer wiring. The real init entrypoint also exits
60, after stopping DP and before Compose up, when a fake loader fails or
when fake host tools acknowledge writes but report a wrong-UID OUTPUT jump.
A disposable `stargate init` on this
unprivileged host exits 60 before creating DP when `sudo -n` cannot load
AppArmor. A privileged disposable container loaded the same profile for
AF_UNIX checks: the first profile denied the authorized SOCKS dial because
AppArmor resolved Tor's original hardlink inode path; after adding that
exact path, the SOCKS handshake and control.sock dial passed. An abstract
socket dial failed under the profile and succeeded without it. These are
initial mechanism checks. The Docker-cadence regression subsequently ran
in a disposable internal bridge: absent and wrong-UID rules admitted the
5102 client (falsifier legs); the scoped IPv4/IPv6 rule set produced zero
decoded TCP/UDP packets on eth0 after a positive same-capture control,
with no matching kernel journal, dmesg or container log records. An
off-loopback 5102 listener accepted a reverse client only under the
unrestricted-ESTABLISHED mutation, not under the shipped lo-scoped rule,
while a loopback listener remained reachable. A uniquely named copy of
the production AppArmor profile then allowed Tor SOCKS, dp.sock bind,
control.sock dial, and the production Go authenticated WatchEvents
reconnect and ReloadTokens-over-mTLS tests; a host abstract socket carried
a byte exchange without the profile but was permission-denied under it.
Recorder readiness, bounded exit and pcap decoding are fail-closed in the
test. The test unloads its unique policy and removes disposable resources.
Production-namespace breadth remains T163; host-root sudo is unavailable
in this execution environment, so actual `stargate init` was separately
observed to stop before DP startup with exit 60, and the real host rule
installation was not exercised here.
The live username-less Tor isolation test first failed in its final
distinct-username calibration after both SOCKS CONNECTs succeeded but both
streams disappeared before a 90-second status poll. An immediate rerun
passed all three subtests, including distinct circuit IDs (19 and 22);
the initial failure is recorded as an external onion-stream timing limit,
not evidence that the first run was green.

Round-1 single-gate review: GLM APPROVE with three Minor test-integrity
observations; Codex Astra REWORK with three Major evidence gaps (the host
firewall socket tests used copied rules, the caller matrix lacked raw-control
connection denials and full post-restart repetition, and log-reader failures
could be treated as empty logs). Round-2 rework touches only the two named
test files and this note. The Docker firewall test now runs the real
`scripts/subcommands/init` inside its disposable privileged network namespace;
only Docker/AppArmor integration is stubbed, and an invalid image pin stops
after successful host-policy installation/verification but before volume or
Compose startup. Its packet and reverse-channel probes run against those
installed IPv4/IPv6 rules. Temporarily removing `-o lo` from BOTH production
install and verification functions made the Docker regression fail at
`reverse off-loopback channel open under scoped rule` (exit 1); both lines
were restored byte-for-byte and the same test passed. The log checks now
fail if dmesg, journalctl or docker logs fails; an explicit failed-reader
falsifier covers each invocation type, and available persistent/runtime
journal layouts are queried independently, with zero layouts a failure.
The real-socket Tor caller matrix now tests all five caller outcomes before
and after restart, positively connects to Tor's raw control endpoint in its
own namespace, then attempts real connections from the deployed consumer
view and from adversarially state-volume-attached CP/DP identities. A first
strengthened run correctly showed the consumer's 0700 ancestor returns
`Permission denied` rather than `ENOENT`; the assertion accepts either
denial, while the mounted-state leg requires `Permission denied`. The
corrected matrix passed (14.36s). These rework checks do not claim T163's
production-namespace capture coverage.

File budget grounding (37), enumerated path-by-path:
(1) data-plane/internal/forward/tor.go; (2) forward/tor.go's unix-dial test;
(3) data-plane/internal/bind/check.go; (4) bind/check_test.go;
(5) data-plane/cmd/stargate-proxy/main.go; (6) sidecars/tor/Dockerfile;
(7) sidecars/tor/torrc; (8) sidecars/tor entrypoint re-exposure hook (new);
(9) compose/docker-compose.local.yml; (10) scripts/subcommands/init;
(11) init's test; (12) the DP AppArmor profile (new, installer-loaded);
(13) specs/001-tor-route/spec.md (FR-007/010/011/012); (14) architecture spec
§4.2; (15) data-model.md §6; (16) contracts/torrc.md;
(17) contracts/foundation-boundaries.md; (18) THREAT-MODEL.md;
(19) SECURITY-DECISIONS.md; (20) quickstart;
(21) tests/contract/compose/local_compose_test.sh;
(22) tests/contract/compose/network_hardening_test.go;
(23) tests/contract/tor/port_exposure_test.go;
(24) tests/contract/torrc/render_byte_match_test.go;
(25) tests/contract/torrc/invariants_test.go (per contracts/torrc.md);
(26) tests/contract/tor/control_port.go;
(27) tests/contract/tor/control_port_live_test.go;
(28) tests/contract/tor/username_less_isolation_test.go;
(29) tests/contract/torrc/isolate_socks_auth_effect_test.go;
(30) tests/contract/torrc/live_sidecar_test.go;
(31) tests/contract/tor/control_port_test.go;
(32) this ticket; (33) STATUS.md. The Docker-backed init test at (11)
needed no edit (it passes unchanged). Its freed slot and the four reserved
paths are used by the explicit T163/T164 handoff corrections, the T106
count-probe fixture-path correction, the AF_UNIX probe fixture, and the
combined host-enforcement regression. Total touched paths: 37/37.

Prototype evidence for every mechanism named above is in
`specs/001-tor-route/analysis/T134-local-topology.md` (§4 results incl. the round-2
A.9 loopback-forwarder closure, §7 verbatim scripts): strict-path host-loopback
bind, hardlink re-exposure, SOCKS5-over-UDS, scoped ESTABLISHED-only owner-match
DROP with positive capture controls, cold-start restore. T163 extends the evidence
to production namespaces; it does not own the mandatory falsifier (round-1 review
F2 — the regression is atomic here).
