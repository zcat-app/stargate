---
id: "T134"
title: "Investigate a constitution-compliant local topology"
status: done
created: "2026-09-12"
last_updated: 2026-09-19
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T125", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T125"
tests_first: []
reviews: { round: 1, date: 2026-09-19, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T134: Investigate a constitution-compliant local topology

## Context

B1/M1: T125 wildcard binding and no-masquerade reasoning do not establish the constitutional deployment boundary. Investigate alternatives before choosing implementation.

## Analysis

Property map (analysis gate, 2026-09-13; full evidence in
`specs/001-tor-route/analysis/T134-local-topology.md`):

- **Must hold:**
  - No production behavior change under this ticket: prototypes use disposable
    state and throwaway docker resources only (§Out-of-scope; no amendment).
  - B1 reproduced with disposable state: strict native wildcard refusal
    (BIND_REFUSED, exit 1) vs the `STARGATE_IN_CONTAINER=1` boolean opening a live
    SOCKS5 listener with no container/tunnel premise.
  - At least two concrete alternatives compared under the T156 constitution across
    loopback ingress, DP/CP/Tor authority, destination DNS and cold-start.
  - Candidate prototypes assert loopback reachability, non-loopback refusal and
    packet-level DNS/TCP/UDP isolation with positive capture controls; environment
    assumptions and failed alternatives reported.
  - The recommendation names remaining authoritative conflicts explicitly; no
    disputed design implemented.
  - Follow-up implementation tickets (T162 topology, T163 verification) filed with
    remediates/spec refs/red-first regression and measurable closure, wired into
    T155 blocked_by and affected consumers T123/T124; graph acyclic; STATUS
    regenerated.
- **Gated:** post-T139 fail-closed `verify.sh` (bind unit contract, compose
  structural M-rules, network-hardening probes) stays green and unchanged on this
  ticket's own commit.
- **Residue (this ticket's targets — none previously gated):**
  - Startup safety never reproduced natively → R1 probe (done).
  - No gate observes packets; TCP connect-timeout is non-discriminating → P-A
    capture probes with positive controls (done at prototype level).
  - Tor unix-socket feasibility unproven → report §3: 0700 dir required, native
    0600 sockets, hardlink re-exposure works; group-access and root-write
    alternatives failed (recorded).
  - Constitutional fit undocumented → comparison matrix + recommendation (done).
  - Follow-up wiring absent → T162/T163 + T155/T123/T124 edits (done).
  - **Left over for T163:** production-namespace captures, per-family validation,
    fail-closed rule-absence behavior; for T155: integrated evidence. The
    privileged-container host-sim stands in for the physical host — mechanism-level
    evidence only (stated limitation, not a compliance claim).

## Acceptance

1. Reproduce strict native wildcard refusal versus the STARGATE_IN_CONTAINER exception using disposable state; preserve the audit evidence.
2. Compare at least two concrete alternatives under the T156 constitution, including loopback ingress, DP/CP/Tor authority, destination DNS and cold-start operation.
3. For candidate prototypes outside production, assert loopback reachability, non-loopback refusal and packet-level DNS/TCP/UDP isolation with positive capture controls; report environment assumptions and failed alternatives.
4. Deliver a reviewable design recommendation and explicitly list any remaining authoritative conflict. Do not implement a disputed design or amend the constitution under this ticket.

### Required planning refinement


Completion requires a reviewed recommendation and concrete implementation follow-up tickets with
`remediates`, spec/contract references, a tests-first regression, and measurable closure criteria.
Before marking this investigation done, add every required follow-up to T155 `blocked_by`
and to affected consumers (including deployment, CONNECT tests, or event consumers as applicable).
A recommendation alone does not close the finding. Unresolved authoritative conflicts remain
blocking; this ticket cannot authorize a constitution amendment or accept the risk.

## Out-of-scope

Production behavior changes, constitution amendments, or accepting T125 residual risk.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

**Investigation outcome (2026-09-13):** candidate A recommended (host-loopback DP,
strict exception-free bind check, unix-socket sidecar fabric with image-owned
re-exposure, packet-level owner-match egress denial provisioned by the installer);
candidate B documented as the viable fallback, candidate C rejected on evidence.
Full report with preserved probe scripts and transcripts:
`specs/001-tor-route/analysis/T134-local-topology.md`. Implementation follow-ups
T162 (topology) and T163 (packet-level verification) are filed and wired into
T155/T123/T124; remaining authoritative conflicts are listed in the report §8 —
all spec/contract/test surfaces to amend in follow-ups, none constitutional.

**Round-2/3 revisions (review F1–F4 twice renewed + minors):** the round-1 rule
set carried a blanket loopback ACCEPT (egress laundering via host-loopback
forwarders) and a LOG target (per-packet kernel records vs Constitution III) —
the hardened set (scoped shim port + ESTABLISHED,RELATED + **silent** DROP) is
re-probed with the A.9 forwarder-mediation test; sidecar authority became
mount-separated per-consumer fabrics with the A.10 caller matrix; candidate B's
relay identity received its own capture-verified isolation probes (B.2) and
equivalence claims are restricted to measured properties; the enforcement and
caller-matrix falsifiers moved into T162 (atomic with implementation, plus a
DeniedEgressNoDetailedLogs regression and T138 as prerequisite for the CP-side
surface), the THREAT-MODEL mechanism update moved into T162 (same reviewed
change), T163's closure wording is refusal-only and measured-results-only, and
the probe host's public IP is redacted. Round 4 scoped the reply acceptance to
loopback (A.11 demonstrates the reverse-initiated off-loopback channel open under
the prior shape, dead under the shipped one), relabeled the CP control PASS as
transport/mount evidence only (sanitization is T138's design), made every capture
phase fail closed, embedded the fixture generation in the driver, and preserved
the dir-mode sweep in-driver. Round 5 made the fabric assertion require the
complete upstream-derived reply (with a dead-shim discrimination phase), gave the
relay identity the same loopback-scoped rules with its own reverse-channel
falsifier, and re-grounded T162's file budget. Round 6 made the capture controls
per-protocol (TCP/UDP/UDP-53 asserted individually in both directions) and
completed T162's affected-surface inventory (FR-007, architecture §4.2,
data-model §6, port_exposure_test.go). Round 7 demonstrated the abstract-socket
forwarder channel open for a host-netns DP (A.12, with positive control),
qualified the compliance claim accordingly, and gated T162 on installer-loaded
AppArmor unix mediation with a discriminating regression (budget re-grounded to
32, enumerated path-by-path). Round 8 corrected the formal review's six omitted
Docker-cadence Tor transport surfaces, re-grounded T162's budget to 37, corrected
the preserved A.7 and SOCKS byte-count descriptions, and clarified that candidate
B still requires host firewall and AppArmor enforcement. See the report's revision
records.
