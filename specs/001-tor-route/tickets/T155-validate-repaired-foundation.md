---
id: "T155"
title: "Validate repaired foundation before feature work"
status: "pending"
created: "2026-09-12"
last_updated: 2026-10-01
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T134", "T135", "T136", "T137", "T138", "T139", "T160", "T141", "T142", "T143", "T144", "T145", "T146", "T147", "T148", "T149", "T150", "T151", "T152", "T153", "T156", "T120", "T114", "T121", "T123", "T124", "T126", "T132", "T157", "T158", "T159", "T161", "T162", "T163", "T164", "T165", "T167", "T168", "T172", "T173", "T174", "T176", "T183", "T184", "T185", "T186", "T187", "T188", "T193", "T194", "T195"]
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
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T155: Validate the repaired foundation before feature work

## Context

The September foundation audit failed despite a green baseline. This checkpoint prevents
investigation-only completion from unblocking feature work while defects remain unfixed.

## Analysis

- Must hold: T156 constitutional deployment, isolation, authority and routing guarantees.
  Concretely, on one recorded candidate: (a) every September/July finding maps to a done,
  reviewed implementation owner in `blocked_by` with a discriminating test, or stays open;
  (b) DP binds only host loopback in Local and refuses non-loopback/`::1`; DP-UID TCP/UDP/DNS
  egress is denied with positive controls captured; (c) CP holds no raw Tor control authority
  and prohibited commands never reach Tor; (d) clean-volume `scripts/stargate init` reaches
  authenticated Tor-routed destination bytes without harness provisioning; (e) authenticated,
  idle and post-rotation reloads accept only the current pin, resumption included; (f) DP
  restart restores the last acknowledged generation and CP-down routing survives; (g) distinct
  client/profile/site partitions never share a circuit while same-partition traffic may;
  (h) HTTP CONNECT is refused and a protected request never falls back to Direct; (i) persisted
  counters contain only completed hour buckets, retention cleanup runs, revocation survives
  restart/rollback of supported state.
- Gated: per-ticket regressions and independent reviews, followed by current integrated evidence.
  Live checks run on the saved QEMU guest (own kernel/namespaces) and host Mullvad Browser;
  each result binds the candidate snapshot hash and is invalidated by later executable changes.
- Residue: synthetic and skipped tests do not establish clean-host or browser-network behavior.
  VM runs do not establish physical-NIC, routed-IPv6, LAN/VPS or hypervisor behavior; those and
  release-cadence checks (browser launch/session restore, T034a/T034f/T070a) stay tracked in the
  live-e2e README, never recorded as PASS.

## T165 Local observer input (2026-09-21)

- The [T165 observer evidence](../analysis/T165-observer-evidence.md) records
  the clean-volume Local deployment, CP/observer production identities and
  mounts, positive CP-namespace packet capture, forbidden-command non-arrival,
  finite token/failure matrix, deployed CP→DP STARTED/HEALTHY/UNHEALTHY
  event sequence with no false lifecycle event, socket recreation, and CP-down
  authenticated destination bytes through real Tor. The complete T163/T165
  guest run is `target/runs/T165-r2-vm-final3.log`; copied raw artifacts are
  under `target/live-e2e/T165-vm-20260921-190436/` (gitignored).
- This input covers the QEMU guest's Local namespace and kernel. It does not
  substitute for T155's remaining foundation, routed-IPv6, LAN/VPS, physical
  NIC, browser, release-cadence or independent cumulative-review checks.

## T152 operational-boundary follow-up

T174 must migrate the live harness's Docker-health and DP receipt-journal consumers before
this checkpoint uses fresh integrated results. The T165 artifacts above remain historical;
they do not establish the post-T152 observation mechanism.

## Attempt 1 outcome (2026-09-29)

Grounding on snapshot `694dbd8` reconciled the September/July audit and ran a
fresh cumulative redteam (three Opus `stargate-redteam` passes: transport,
control-plane/browser, deployment). At the maintainer's direction every finding
then went through a falsification pass before ticketing. Report:
[redteam-20260929-694dbd8](../../../reviews/redteam-20260929-694dbd8.md).

- Surviving Majors, now blockers here: T183 (T034 DNS-leak gate cannot run),
  T184 (Tor package-closure rollback), T185 (unlocked Maven dependencies),
  T186 (blocked protected request returns Firefox DIRECT), T187 (pending/stale
  revocation invisible; counted before acknowledgement), T188 (no private-window
  access check; ordinary-proxy fallback observed).
- Surviving Minors: T189/T190/T191, blocking T078 rather than this checkpoint.
- The reconciliation's clean-install gap narrowed: `tests/live-e2e/local-topology/run.py`
  already exercises real `scripts/stargate init`; Acceptance 2 still needs a
  current-candidate run. Moving done findings out of `redteam/findings/open/`
  stays Acceptance 1 work at closure.
- No live VM run was recorded: the blockers above change init, compose, the
  extension and tests, so evidence taken now would be invalidated. The maintainer
  chose to return this checkpoint to pending (2026-09-29). This redteam pass is
  interim; Acceptance 5 requires a fresh pass on the final candidate.

## Acceptance

1. Reconcile every September audit finding and the July finding ownership table against
   current code and durable review evidence. All required implementation follow-ups must
   exist in this ticket's `blocked_by` and be done; recommendations alone cannot pass.
2. Run `scripts/verify.sh` on the exact candidate and preserve its gate summary. Exercise
   the documented clean-volume operator startup without harness-only provisioning fixes,
   then real CP/DP authenticated reload, idle reload, peer-pin rotation/resumption, DP restart,
   CP-down routing survival and same-target/distinct-first-party isolation.
3. Prove the selected topology and observer boundary using positive controls and negative
   probes from production namespaces: bind refusal, DNS/TCP/UDP egress and prohibited Tor
   commands. Test the selected CONNECT contract and operational journal policy.
4. Create/update `specs/001-tor-route/live-e2e/README.md` with prerequisites, commands, snapshot and evidence
   for foundation checks and remaining release-cadence checks, including D-live-N decisions,
   preserve/reset semantics and transport-relevant/invisible classification. Track a real-browser
   hardening/token-failure probe for unintended Direct fallback, with packet attribution.
   Required foundation checks that cannot run keep this ticket pending; do not convert SKIP
   into PASS. Milestone-wide T034a/T034f/T070a evidence remains required later.
5. Obtain a fresh independent cumulative foundation redteam pass under the canonical
   workflow. No unresolved Blocker/Major may pass without explicit maintainer disposition;
   constitutional conflicts require the governance path and cannot be accepted by this plan.
   Record the reviewed snapshot and invalidate affected evidence after further changes.
6. Leave T078/T079 pending for the completed milestone. File new findings as focused
   remediation tickets, add blockers here and to affected consumers, and reverify closure.

7. Verify T156 policy end-to-end: device/profile/site partitioning, no Direct fallback,
   complete-hour-only metric publication, operational-writer/retention cleanup, and acknowledged
   revocation surviving supported rollback/restart. No active inherited contract exception may
   substitute for these checks. Add required implementation children before closure.

## Out-of-scope

Feature expansion, constitution amendments, fabricated historical tests-first evidence,
release publication, and substituting this checkpoint for final milestone reviews.

T147 migration dependency: T172 reconciles HTTP CONNECT contracts and consumer acceptance;
T173 implements refusal with preserved authenticated SOCKS coverage and deployed evidence.
Both must complete before this consumer runs; T147 planning completion alone is insufficient.
