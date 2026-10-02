---
id: "T155"
title: "Validate repaired foundation before feature work"
status: "pending"
created: "2026-09-12"
last_updated: 2026-10-02
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T134", "T135", "T136", "T137", "T138", "T139", "T160", "T141", "T142", "T143", "T144", "T145", "T146", "T147", "T148", "T149", "T150", "T151", "T152", "T153", "T156", "T120", "T114", "T121", "T123", "T124", "T126", "T132", "T157", "T158", "T159", "T161", "T162", "T163", "T164", "T165", "T167", "T168", "T172", "T173", "T174", "T176", "T183", "T184", "T185", "T186", "T187", "T188", "T193", "T194", "T195", "T196", "T198"]
parallel: false
files_budget: 14   # raised 8 -> 14, pre-granted (rule 2026-10-01), each added path named in Acceptance or directly implementing/testing an acceptance item:
                   # ticket, STATUS.md, evidence/T155-tests-first.json (fixed overhead); live-e2e/README.md (A4);
                   # tests/contract/workflow/live_e2e_tracker_test.sh (tests-first for A4);
                   # tests/live-e2e/local-topology/t155_stack.py + evidence/T155-live-results.json (A2/A3/A7 harness and sanitized results, preserved after round-1 review);
                   # tests/integration/partition_axes_test.go + stream_isolation_dp_uname_test.go (A2/A7 device/site isolation axes, round-1 review finding);
                   # tickets T196, T197, T198 and T078 blocked_by (A6: new findings filed as focused tickets and blocking the milestone redteam)
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
aborted_attempts: [{ date: 2026-10-02, round: 3, reason: "run-task --reset", history: target/runs/T155.review-history }]
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

## Attempt 2 outcome (2026-10-01)

Attempt 2 (`ccd622d`) stopped on A2-M2 (WebRTC default on Mullvad Browser 153; unreachable
failure notification; untruthful onboarding), fixed by T195. Summary and the Acceptance 1
reconciliation table: [redteam-20261001-79d49e9](../../../reviews/redteam-20261001-79d49e9.md).

## Attempt 3 outcome (2026-10-01)

Candidate source snapshot `989b8f97365280753395c9cc902565b9e24627b8` (after T195). The T155
candidate adds documentation, evidence and tests only (this ticket, `STATUS.md`, the
[live-e2e README](../live-e2e/README.md), its structure check, the stack harness and sanitized
results, the device/site isolation axes in `tests/integration`, three new tickets and a
`blocked_by` edit); none changes product code, Compose, the extension or image inputs. Live
results bind the source snapshot; the integration binary was rebuilt for the new axes (see
"Device and site axes").

- **Short TMPDIR (maintainer-approved 2026-10-01: short TMPDIR for socket path limit):** the
  driver's `verify.sh`, review and Go/contract runs use `TMPDIR=/tmp/T155` because
  `.scratch/tmp/T155` paths exceed the 108-byte Unix socket limit. Scratch reports stay under
  `.scratch/tmp/T155`.
- **Tests first:** the driver requires a red/green record for a privacy-critical ticket. The
  README structure check (`live_e2e_tracker_test.sh`: required sections, existing command paths,
  T186/T188 probe tracking, T034a/T034f/T070a and launch/session-restore listed, D-live-N log, no
  unrun check recorded as PASS) has red (README absent) and green records. The device/site axes
  (below) have a red against a mutated data plane and a green against the candidate. Record:
  `specs/001-tor-route/evidence/T155-tests-first.json` (earlier pairs kept under `superseded`).
- **Host browser probes (F5), pinned Mullvad Browser 153.3.0esr** (the host `/usr/bin/mullvad-browser`
  is 140.16.0esr and the extension refuses it, minVersion 153.0; disposable profiles):
  `descriptor-matrix`, `blocked-proxy`, `private-access` and `full` all `GREEN`.
- **Live Local stack on the QEMU guest** (per-ticket copy of the saved guest; kernel 6.8.0-142,
  Docker 29.1.3; guest IPv6 disabled on non-loopback interfaces to avoid the `fec0::` route that
  `run.py` refuses, disclosed as D-live-2). The stack harness and sanitized per-check results are
  committed (`tests/live-e2e/local-topology/t155_stack.py`, `specs/001-tor-route/evidence/T155-live-results.json`
  with both SHA-256 values; the committed script differs from the executed scratch copy only by
  the SPDX header and an attempts label):
  - `run.py` (clean-volume real init, topology, observer, CP-down Tor-routed bytes): **PASS on the
    fourth attempt**; attempts 1-3 on identical sources failed inside `observer.py`'s fixed 35 s
    CP-event windows (known timing sensitivity, T174 record). Not erased; owner T196.
  - Stack script (real init, quickstart reloads, status `token delivery: ACKNOWLEDGED(n)`,
    post-rotation and 180 s idle reload, DP restart with CP down, CP-down Tor bytes, revocation,
    `STALE_CONFLICT` rollback and recovery, old-pin refusal, completed-hour-only aggregates, retention,
    logging `none`, state-file allowlist, `connect_refusal.py`): 50 PASS, **1 FAIL**. The FAIL is
    `tests/contract/compose/inter_plane_wire_test.sh`: its runtime rows R2 and R3 (bash
    `exec 3<>unix-socket` always fails with ENXIO, so R3 cannot fail and R2 cannot pass), R5 (wireprobe
    exit 0, meaning the bad major was rejected, read as "accepted") and R7 (host-netns `/proc` read) are
    defective, and every row prints PASS regardless; the results JSON marks R2/R3/R5/R7 unreliable.
    Independent `wireprobe` verdicts and an `ss`-by-pid DP listener check passed as supplements; none of
    that turns the script's exit 1 into a PASS. Owner T196. Two stale checks in the scratch harness were
    fixed before use (the `ACKNOWLEDGED(` line-start match, which the command's `token delivery: ` prefix
    defeats, and a last-line-only `STALE_CONFLICT` match); the first stack run (47 PASS, 2 FAIL) had the
    second defect; it is superseded by the rerun, not hidden.
  - T126 suite (`TestStreamIsolationDPUNAMEForwarding`, `TestT126*`): PASS. T182 suite:
    `TestOnionLoad` PASS (first run), one real-Tor failure (`TTL expired`), PASS on rerun;
    `TestStreamIsolationPerFirstPartyDomain` one failure (reference onion refused by Tor), PASS on rerun.
- **Device and site axes (round-1 review finding).** T126 varies only the browser-profile axis.
  `tests/integration/partition_axes_test.go` adds, as further subtests of the T126 stack, a device pair
  (second bearer token) and a first-party-site pair against the same target, each required to land on
  distinct non-zero BUILT circuits and protected by T126's same-partition calibration, plus a hermetic
  derivation test pinned to independently computed vectors. Results: see the README Evidence index.
- **Fresh cumulative redteam, durable record.** Snapshot `989b8f97365280753395c9cc902565b9e24627b8`,
  blind `git archive` export with the project's review history, findings, SECURITY-DECISIONS, tickets,
  analysis, evidence and journal removed. Three `stargate-redteam` reviewers (transport; control
  plane and browser; deployment and supply chain), each self-reported Claude Opus 5.5
  (`claude-opus-5-5`), then three `general-purpose` falsifiers, each self-reported Claude Sonnet 5.5
  (`claude-sonnet-5-5`). All Claude, model not independently verified, independence limited to fresh
  context (the implementer is also Claude). Reviewers ran Go/Node/Maven tests offline and probes in
  scratch copies and were forbidden host ports, browsers, containers and the network; the area-2
  falsifier alone used the pinned Mullvad Browser with disposable profiles, after all live probes
  had finished. No interference. Verbatim reports: `.scratch/tmp/T155/redteam/` (gitignored);
  this section is the durable record.
  - **Result: no Blocker and no Major survived.** 12 claimed Majors (area 1: 2, area 2: 5, area 3: 5)
    were falsified, narrowed to Minor, or duplicates of T189/T190/T191/T081/T075.
  - Falsified or duplicate (not ticketed): area 1 M1 (DP forwards any username; FR-002/FR-007 and
    foundation-boundaries require intact forwarding, the extension HMAC key is the device token; repeat
    of the 79d49e9 A1-M1 verdict; stale text T189 item 4), m1/m3 (T189 items 1/2), m2 (accepted `loadedAt`),
    m4 (socks5-auth "until either end closes"); area 2 M1 WebRTC gate startup-only (T190 item 1; RAN
    live: pref unlocked, API reads true after an about:config flip, a new `.onion` request still reaches
    8881 with the token until the extension reloads, but 0 ICE candidates and 0 UDP to a STUN listener
    because Mullvad's ICE prefs plus the baseline proxy; behaviour claim true, severity rests on
    architecture §14.5 Part 2 and the spec decision T190 item 1 carries), M2 onion-page clearnet
    subresources go Direct (T190 item 7; FR-001 scope; reproduced; Referer/Origin not sent), M4 CP wildcard
    HTTP bind (accepted 694dbd8 verdict, `network_mode: none`), m2/m4/m5 (T190 items 2/6/5, T191 item 7),
    m7 (foundation-boundaries pins the id; no New Identity in this build), i2/i5; area 3 M1-M5 (T191 items
    12, 11, 4, 3, 4/6; M3 narrowed: live suites are release-cadence by design), m3 (T191 item 2), m4
    (SECURITY-DECISIONS 2026-09-20), m6, m2/m7 Info.
  - **New surviving Minors (block T078), now filed:** T197 (A2-M3 popup indicator stale after a bfcache
    restore, reproduced live; A2-M5 prose for the inventory and DoH blocklist that do not exist; A2-m8
    stale §5.3 Reference), T198 (A1-M2 abstract Unix-socket confinement is AppArmor-only and `init`
    does not gate on af_unix mediation, with the correction that "require Landlock ABI 6" would refuse
    the measured host; A3-m1 `init` prints unchecked HEALTHY/bind facts; A3-m5 quickstart Engine/volume
    count/key-mode errors), T196 (the harness defects above). T078 `blocked_by` gains T196, T197, T198; T155 gains T196 and T198 (see below).
- **Review rounds and the maintainer's decision (2026-10-02).** Round 1: GLM and Astra REWORK (durable
  redteam record, preserved F2 harness, device/site isolation axes, remediation owners; all addressed).
  Round 2: GLM APPROVE; Astra APPROVE-WITH-FIXES (README snapshot paragraph, applied); fresh re-review: GLM
  APPROVE, Astra REWORK with two Majors: **A-1** the live evidence has no TLS-resumption assertion (Acceptance 2
  names "peer-pin rotation/resumption"; `wireprobe` offers no session ticket) and no exported-counter assertion;
  **A-2** T196/T197/T198 must block T155, not only T078 (Acceptance 6: "add blockers here and to affected
  consumers"). Maintainer decisions: A-2 is upheld for T196 and T198 (they now block T155; Acceptance 6 is not
  amended and no override is given; T197 blocks T078 only); T196, T197 and T198 are approved as filed with the
  T078 `blocked_by` edit (their THREAT-MODEL, SECURITY-DECISIONS and constitution wording needs separate approval
  when they run); round 3 is not spent on the resumption probe now. Attempt 4 re-runs the live evidence after
  T196 and T198 land and includes the live TLS-resumption probe for A-1.
- **Parked work:** the attempt-3 README, evidence and tests are parked UNREVIEWED on the local branch `wip/T155-attempt3` for attempt 4 to pick up through a reviewed commit.
- **Acceptance 1 closure** is the done follow-up: the reconciliation table is in
  [redteam-20261001-79d49e9](../../../reviews/redteam-20261001-79d49e9.md) and was re-checked at this
  snapshot (16 open records, all owners done with fixes at HEAD; 11 CLOSE, 5 CLOSE-WITH-RESIDUE);
  the moves from `redteam/findings/open/` to `closed/` follow in the `docs: mark T155 done` commit so
  the closure cites this ticket's commit.
- **Not established, tracked in the README, never PASS:** T034a, T034f, T070a, real-browser
  launch/session-restore (including cache-served protected subresources) and host-NIC packet
  attribution, routed IPv6, LAN/VPS, physical NIC, stable-channel browser.

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
