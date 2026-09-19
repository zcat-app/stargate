---
id: "T162"
title: "Implement host-loopback DP with unix-socket sidecar fabric"
status: "pending"
created: "2026-09-13"
last_updated: "2026-09-13"
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
    DP fabric volume carries only the SOCKS re-exposure, the CP fabric volume only
    the control re-exposure (0660 group-gated); CP cannot reach the SOCKS socket
    and DP cannot reach the control socket by construction. The CP-side sanitized
    observation surface itself follows T138's resolved design (prerequisite).
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
4. Tor image + socket authority: rendered torrc switches to `SocksPort unix:` +
   the T138-resolved CP observation endpoint (each inside a tor-private 0700
   directory on its own per-consumer fabric volume — tor 0.4.9.12 refuses
   group-accessible socket dirs, T134 §3); the Stargate-owned entrypoint re-exposes
   each endpoint only into its consumer's fabric (0660, consumer group; hardlink
   hook). Raw ControlSocket re-exposure to the CP is NOT prescribed — the CP fabric
   carries whatever enforced observer boundary T138 lands. Contracts/torrc.md
   golden and byte-match tests updated; cookie facts recorded for T138. A
   **SocketCallerMatrix** regression (real sockets, red-first) demonstrates
   DP→SOCKS succeeding and the cross-direction denials that the landed T138
   endpoint defines — including after socket recreation (tor restart).
5. Compose: DP `network_mode: host` (loopback bind only, no ports publish); CP
   `network_mode: none` with CP-fabric access only; stargate-host /
   stargate-internal / stargate-cp-tor networks removed; the two per-consumer
   fabric volumes carry the sidecar sockets (DP fabric mounted by tor+DP, CP
   fabric by tor+CP — never both); local_compose_test.sh,
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
   wording — still `tor:9050` on the compose network), FR-010/FR-011/FR-012
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
(32) this ticket; (33) STATUS.md — 33 enumerated, leaving four paths within
the 37-file budget for the SocketCallerMatrix / ReverseChannelClosed /
DeniedEgressNoDetailedLogs / AbstractSocketForwarderDenied regression files
the acceptance adds.

Prototype evidence for every mechanism named above is in
`specs/001-tor-route/analysis/T134-local-topology.md` (§4 results incl. the round-2
A.9 loopback-forwarder closure, §7 verbatim scripts): strict-path host-loopback
bind, hardlink re-exposure, SOCKS5-over-UDS, scoped ESTABLISHED-only owner-match
DROP with positive capture controls, cold-start restore. T163 extends the evidence
to production namespaces; it does not own the mandatory falsifier (round-1 review
F2 — the regression is atomic here).
