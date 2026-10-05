---
id: "T155"
title: "Validate repaired foundation before feature work"
status: in-progress
created: "2026-09-12"
last_updated: 2026-10-05
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T208", "T203", "T134", "T135", "T136", "T137", "T138", "T139", "T160", "T141", "T142", "T143", "T144", "T145", "T146", "T147", "T148", "T149", "T150", "T151", "T152", "T153", "T156", "T120", "T114", "T121", "T123", "T124", "T126", "T132", "T157", "T158", "T159", "T161", "T162", "T163", "T164", "T165", "T167", "T168", "T172", "T173", "T174", "T176", "T183", "T184", "T185", "T186", "T187", "T188", "T193", "T194", "T195", "T196", "T198", "T204", "T205"]
parallel: false
files_budget: 21   # raised 8 -> 14 in attempt 3 and 14 -> 17 in attempt 4, both pre-granted (rule 2026-10-01); attempt 4's raise adds the
                   # Acceptance 6 filings the maintainer directed into this candidate on 2026-10-03 (new T200, T201; additions to T189, T197, T199; T078 blocked_by).
                   # Attempt 4 touches 17 paths, each named in Acceptance or directly implementing/testing an acceptance item:
                   # ticket, STATUS.md, evidence/T155-tests-first.json (fixed overhead); live-e2e/README.md (A4);
                   # tests/contract/workflow/live_e2e_tracker_test.sh (tests-first for A4);
                   # tests/live-e2e/local-topology/t155_stack.py + evidence/T155-live-results.json (A2/A3/A7 harness and sanitized results);
                   # tests/integration/partition_axes_test.go + stream_isolation_dp_uname_test.go (A2/A7 device/site isolation axes);
                   # tests/contract/compose/wireprobe/wireprobe.go + wireprobe_test.go (A2 "peer-pin rotation/resumption": live resumption probe and its hermetic discrimination test)
                   # tickets T200 and T201 (new), T189, T197, T199 (items added) and T078 (blocked_by + one decision line) (A6)
                   # (attempt 3's ticket filings and its T078 blocked_by edit landed separately and are not in this candidate)
                   # Resume after T208 (2026-10-05) touches 20 paths: the 13 reconciled candidate paths (ticket, STATUS.md, both evidence
                   # JSONs, live-e2e README, wireprobe.go/_test.go, the tracker test, t155_stack.py, partition_axes, route_diagnostic,
                   # stream_isolation_dp_uname and stream_isolation tests) plus the Acceptance 6 filings below.
                   # raised 17 -> 20 on 2026-10-05, not pre-granted: 19 paths were shown to and approved by the maintainer with the filing shape
                   # "Fold in, one new ticket" (new T209; additions to T189, T190, T197, T199; T078 blocked_by); the twentieth, T077 blocked_by,
                   # was decided by the orchestrator under the maintainer's delegation of the same day. 20 exceeds twice the pre-attempt-3
                   # budget of 8; the maintainer's choice, not the pre-grant rule, authorizes that.
                   # raised 20 -> 21 on 2026-10-05, maintainer-approved ("Completion guard, carry evidence (Recommended)"):
                   # tests/live-e2e/local-topology/test_t155_stack.py, the regression for the round-1 review Major.
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: ["2026-10-03 maintainer: approve full next scope after T203; T204 and T205 repairs, T117 absorption, T206 release-only filing, then T155 TLS-probe repair and full validation", "Maintainer 2026-10-03: refine A6 verbatim; require authenticated live GetStatus red/green publication probe (Attempt 4 resumed below)", "2026-10-04 maintainer: \"ok do that in the 155\"; D1-only current-ticket diagnostic correction and explicit exception to A6/workflow new-remediation filing, genuine RED/GREEN and affected evidence; no new owner/edges or privacy waiver", "2026-10-05 maintainer: \"ok 250s, wording approved\"; park T155, file T208, reopen T155 after it for one final live pass", "2026-10-05 maintainer (relayed by the orchestrator): \"Fold in, one new ticket\" and \"Evaluator checks, then file\"; r5 survivors filed as additions to T189/T190/T197/T199 and new T209, T078 blocked_by T209; the 19-path budget raise approved by that choice", "2026-10-05 maintainer: \"A: No, scoped + release decision\" (onion-to-clearnet redirect: not an automatic route downgrade under 001's destination-only routing; 001-specific, not extended to user-selected routes; disclosure wording and a redirect test under T190 item 7; maintainer decides block-or-disclose before T078)", "2026-10-05 maintainer: \"Accept Claude-only now\" (the all-Claude r5 pass is accepted as the Acceptance 5 pass; the Astra and GLM cumulative passes remain T078's under the 2026-09-29 decision recorded there)", "2026-10-05 maintainer: \"Split to T209 (Recommended)\" (the three T203 orphans, including the quickstart floor reason, and the Dockerfile/Makefile comments to T209; THREAT-MODEL banner/§5.9 and CLAUDE.md stay in T197); \"Owners for two, rest no ticket (Recommended)\" (A2 m7 to T197, A3 m2 increment to T199, others no ticket); \"evaluate and ultrathing best solution\" (the unhomed notes and the T077 edge delegated to the orchestrator; orchestrator decided 2026-10-05); maintainer acknowledged the resulting set: \"ok looks good\"", "2026-10-05 maintainer, on the round-1 review Major: \"Completion guard, carry evidence (Recommended)\" (t155_stack.py exits 0 only when every mandatory check of the mode is recorded PASS; interrupts recorded as incomplete; regression tests first; F2 carried forward by a mechanical comparison, no rerun; budget 21); \"Stale SD entry to T209 (Recommended)\"; \"R-7 to T078 (Recommended)\"; \"Keep fixing to the cap\" (a further harness-only Major that does not touch recorded live evidence may be fixed inside T155 up to round 3)"]
remediates: "T125"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: [{ date: 2026-10-02, round: 3, reason: "run-task --reset", history: target/runs/T155.review-history }, { date: 2026-10-03, round: 1, reason: "run-task --reset", history: target/runs/T155.review-history }, { date: 2026-10-04, round: 1, reason: "run-task --reset", history: target/runs/T155.review-history }]
reopens: []
redteam_findings: []
clarity_check: {}
---

# T155: Validate the repaired foundation before feature work

## Deferred on T208 — 2026-10-05

T155's resumed validation on baseline `403d424` stopped at the mandatory HTTPS onion
load: `TestOnionLoad` failed in both T182-suite selections on 2026-10-04. A diagnosis on
2026-10-04 (one instrumented selection in the disposable guest and a native-speed Tor
control) found that the data plane's 30 s upstream deadline ends first connects to an
onion service that Tor completes later. Token-delivery lag was also present in the
2026-10-03 passing run and does not separate pass from fail. The measurements and their
limits are recorded in T208.

The maintainer chose to repair the contract deadline and align the onion-load test in a
new ticket (2026-10-04, "ok go with A") and approved its value and wording (2026-10-05,
"ok 250s, wording approved"). T155 is deferred on T208. This is not a waiver: mandatory
HTTPS onion load remains unproved and T155 remains incomplete.

The stopped candidate is preserved, uncommitted: 13 staged paths and no unstaged change
at HEAD `403d42405357bc7b1e36f50abae57432474eb53f`, in the detached checkout
`/home/claudia/stargate-observer-repair`. Index SHA-256
`bfee08a8438f866995930314550760ad2e5c81ac3c00c4f5a6262ab665cd7ed8`; staged diff SHA-256
`184e3345b2825394d728a385577524e1859e4ec51d0d5744f047e8a41de8d9dd`. Verified archive:
`/home/claudia/stargate/.scratch/tmp/T155/park/20261005-t208/`. The D1 correction and its
independent closure are part of that candidate and are not committed by this filing. The
earlier 17-path candidate at `10a9323` stays preserved as recorded below.

Live results taken on 2026-10-04 bind the data-plane binary of baseline `403d424`. T208
changes that binary. On resume, evidence renewal follows affected inputs under this
ticket's existing rule, and no 2026-10-04 live result is presented as evidence for the
changed binary. No ordinary review, full verify, commit or merge of the T155 candidate
was run.

On resume: reopen through the prescribed lifecycle on the new HEAD, establish the new
start-sha, reconcile the preserved candidate (including the one comment line T208
changes in `tests/integration/stream_isolation_test.go`), recapture RED/GREEN, then run
one final live pass, verify and the ordinary review. Earlier records stay superseded and
are never relabelled. After T155 completes, the reserved T202 decision and the approved
T202, T200, T201 sequence follow unchanged.

## Current approved continuation — 2026-10-03

T203 is done. The maintainer approved T204 (CP listener boundary), then T205
(persistent hardening-record/schema repair, absorbing T117), followed by resuming T155.
Both new Major owners are prerequisites; T155 remains deferred until both are done.
T206 files the DNS capture-integrity Minor as a T078/T081 release/consumer blocker;
it does not block T155 under acceptance 6, and its execution is not pulled into this sequence.

On resume, reconcile the preserved candidate against the actual new baseline without
reapplying already-filed metadata or relabelling old evidence. Repair T155's owned TLS
negative-resumption probe using the retained early-abort falsifier and independently
establish the attempted resumed path. Keep safe/unsafe/no-ticket/declined-ticket controls,
recapture RED/GREEN, and complete the approved authenticated real-hour GetStatus and
integrated live validation. The production TLS implementation is not shown bypassed by
this evidence defect. Prior reports remain historical; required skipped evidence cannot
close acceptance. Exact reserved wording and genuinely new Majors retain their stop rules.

After T155 completes, return to T202's reserved exact-ticket/cadence decision, then the
approved T202, T200, T201 sequence. This does not authorize running unrelated plan steps.

## Historical observer-only deferral — 2026-10-03

T203 is the only newly authorized repair from the resumed cumulative findings. The user
authorized independent observer design verification and proceeding if it passed; verification
returned PASS WITH REQUIRED DESIGN CORRECTIONS, accepted by the orchestrator. T155 execution
is parked before T203 starts. This deferral does not authorize the separate hardening-record,
CP-listener or DNS-capture findings; surviving Majors still prevent T155 completion even after
T203. The resumption-probe early-abort false pass remains T155-owned work on future resume.

The original 17-path candidate and README unstaged correction are preserved, uncommitted,
at HEAD `10a9323bd3bfcedcbb3394ee994a276f75bacf9a` in the detached original checkout.
Verified archive: `/home/claudia/stargate/.scratch/tmp/T155/park/20261003-observer-handoff/`.
Its index SHA256 is `165ef229fdb84d6f126cf0417c5077a14cfa09dada628017cb023e69a63ea21b`;
staged diff SHA256 `b04b917d77cfcfa2499aef17220537b06cd2f58e1e87e1b6d999afd30807b123`;
unstaged diff SHA256 `8bea5fd628c39078a5dfcd330405e521085637f3c529177b1e9272a8867d8466`.
The archive contains index/working snapshots, separate patches, tests-first records and
superseded history, review history, reports, raw outputs and handoffs; reconstruction checks
passed. The original start-sha and wip/T155-attempt3 branch are retained.

All attempt narratives below are historical. This bookkeeping checkout imports no T155
executable changes or evidence JSON/README as current evidence. The new active-hour-export
mutant RED is valid only against its original baseline; GREEN was not run. Full fresh guest
O1 and browser private-access were interrupted after the new Major stop; S/I/T and browser
full were not run. Descriptor-matrix and blocked-proxy finished GREEN with zero failures.
No resumed ordinary review or verify completed. Every owned live process was stopped.

Previously approved candidate-only metadata is materialized explicitly with this filing:
T200/T201, the approved additions to T189/T197/T199 and their T078 blockers. These are earlier
approvals, not authorization for any of the newly discovered non-observer repairs. Their
exact archived metadata must not be reapplied blindly when the remaining T155 patch resumes.
After prerequisite commits, reopen via the prescribed lifecycle, establish the actual new
HEAD/start-sha and recapture RED/GREEN; keep old records superseded, never relabel hashes.
Current other findings/reports: original `.scratch/tmp/T155/redteam-a4r/`; observer design
report: `.scratch/tmp/T155/glm-repair-advice/design-verification.md`.

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

## Attempt 4 (2026-10-03)

Baseline `10a9323` (after T196 `6228d4a`, T191 `a046386`, T198 `75fa66b`; T199 blocks T078 only).

### Grounding

- The attempt-3 README, tracker test, `t155_stack.py`, `partition_axes_test.go` and the
  `stream_isolation_dp_uname_test.go` edit were brought back from `wip/T155-attempt3`
  (`5368691`) as file contents, not by merging; the branch stays for the maintainer. Attempt 3's
  evidence JSONs bind `989b8f9` and were not reused.
- Superseded by T196: `t155_stack.py`'s supplementary wireprobe-sequence and `ss`-by-pid checks
  (R2/R3/R5/R7 are repaired and a row prints PASS only without a finding, so the gate's own rows
  and exit code decide); the README's D-live-2 (guest IPv6 now stays enabled, `run.py` probes the
  `fec0::` address) and the harness-defect notes in the Evidence index.
- A-1 design: the Go DP keeps TLS 1.3 resumption and re-checks the current `cp.pub` in
  `VerifyConnection` (T135; wire-auth.md §2.4 "Revocation/rotation", §4). `wireprobe resume`
  (CP identity, CP stopped per §6.2) takes a ticket, resumes it (positive control: the live DP
  issues and accepts tickets), rotates `cp.*`, offers the old ticket (must get no RPC answered),
  repeats the old identity in a full handshake (refused) and presents the rotated identity
  (answered, so the refusals are not an outage). The negative control is a DP that pins only full
  handshakes (`VerifyPeerCertificate`, the T135 defect): the hermetic stand-in in
  `wireprobe_test.go` and the live mutant DP used for the red record must both make step 4 fail.
  The Java CP disables session reuse in both roles (wire-auth.md §2.4), so the DP's `dp.sock` is
  the resumption surface.
- Initial exported-counter disposition treated CP persistence as coverage; round-1 review
  falsified that equivalence. The resumed attempt below replaces it with authenticated DP RPC evidence.

### Property map (attempt 4)

| Must hold (Acceptance) | Gated by | Residue (live, this ticket) |
|---|---|---|
| Resumption cannot bypass the current pin; old identity refused after rotation (A2) | `controlclient` T135 unit tests; `wireprobe_test.go` stand-ins | `t155_stack.py` resumption phase on a real `init` stack; mutant-DP red |
| Clean-volume real init, topology, observer, egress, prohibited commands, CP-down bytes (A2, A3) | contract suites (assumed sidecar behaviour) | `run.py` on a fresh guest |
| Reloads, idle reload, DP restart, rollback, revocation, retention, completed hours, journal policy, CONNECT (A2, A3, A7) | unit/contract tests | `t155_stack.py` full run incl. `connect_refusal.py` and the repaired wire gate R1-R9 |
| Authenticated GetStatus excludes the active hour and publishes immutable nonzero completed traffic (A7) | T158 counter and RPC tests | real UTC rollover on unchanged deployed DP; active-hour-export mutant red |
| Profile/device/site partitions never share a circuit (A2, A7) | hermetic derivation vectors | T126 stack with the device/site axes; T182 suite |
| No Direct fallback in the real browser (A7) | extension unit tests | four host probes, pinned Mullvad Browser 153.3.0esr |
| Installer confinement after T198's init gate (A3) | `init_t198_test.sh` | `t162_enforcement_test.sh` docker tier on the guest |

### Progress (2026-10-03, stopped for the maintainer before driver review)

- **Tests first** (`specs/001-tor-route/evidence/T155-tests-first.json`, one probe command
  `bash target/runs/T155a4/tf.sh`: tracker check, hermetic `wireprobe resume` discrimination,
  live `t155_stack.py --only resumption`, live T126 stack with the device/site axes). Red against
  a staged mutant (README absent; DP `ClientTLSConfig` pinning via `VerifyPeerCertificate` only;
  constant upstream username): README missing; step 4 "the DP answered the OLD CP identity on a
  resumed session after rotation" with the step-2 positive control passing; profile, device and
  site pairs on one circuit while calibration passed. The current red was captured after the
  final test files (post-redteam tightening and the tracker residue fold-in); the two earlier
  reds are kept under `superseded`. A dry run of the same command on the unmutated candidate
  passed (all parts). **Green** on the final candidate (fresh guest): tracker OK, hermetic resume
  test 4/4, `--only resumption` 10 PASS 0 FAIL, T126 stack with the device/site axes PASS. The
  first green attempt failed only in the T126 calibration pair (both parallel CONNECTs to the
  reference onion timed out after 3 minutes through real Tor; the profile, device and site pairs
  passed in that run); the tool records no failed green, so this is disclosed here: 1 rerun,
  identical command, raw output `target/runs/T155a4/green-attempt1-fail.out`.
- **Host browser probes** (pinned Mullvad Browser 153.3.0esr from `target/t157-tools`, geckodriver
  0.37.0, disposable profiles; extension package SHA-256 `9813e2e8…`): `descriptor-matrix`,
  `blocked-proxy`, `private-access`, `full` all exit 0 (`target/runs/T155a4/browser/`). Not yet
  bound into the evidence JSON; the final candidate decides whether they are reused.
- **Cumulative redteam** on index tree `6e70e622` (= `10a9323` + this diff), blind export: three
  `stargate-redteam` reviewers and three `general-purpose` falsifiers, all Claude (self-reported
  Opus 5.5), model not independently verified, independence limited to fresh context. Reports
  under `.scratch/tmp/T155/redteam-a4/`. No Blocker or Major survived falsification. Area 2 M1's
  leak sub-claim was falsified by a live run (X1, pinned browser after the host probes finished:
  no onion name reached the resolver, DoH or HTTP/3; M1 stays Minor). Post-redteam delta
  (T155's own files only): `wireprobe resume` step 4 now rejects a declined ticket as vacuous
  (new `declined` stand-in), `t155_stack.py` checks the DP process is unchanged across the probe,
  requires a GetStatus refusal (not any non-zero exit) for the old identity, computes details
  once and requires non-empty aggregate rows; the tracker rejects any upper-case PASS/GREEN in a
  check row except "never recorded as PASS"; the README states what F1 versus F2/F4 leave on the
  host and no longer describes a foreign-extension inventory in R-6.
- **Stop and resume.** Surviving Minor/Info findings were returned to the maintainer as drafts
  (nothing filed). The maintainer's decisions (below) resumed the attempt.

### Final live pass (2026-10-03, final candidate)

Shipped candidate: the staged tree of this ticket's final executable content (tar SHA-256
`f57ff765…`, staged diff `b3046713…`, per-file hashes in
`specs/001-tor-route/evidence/T155-live-results.json`), on a fresh copy of the saved QEMU TCG
guest (Ubuntu 24.04.5, kernel 6.8.0-142, Docker 29.1.3, Compose 2.40.3), guest IPv6 left enabled.
Only non-executable files (this ticket, STATUS.md, the README evidence index and the evidence
JSONs) changed afterwards.

- `run.py` (A2/A3: clean-volume real init, topology, IPv4/IPv6 egress matrix with positive
  controls, bind refusal, observer boundary, prohibited Tor commands, CP-down Tor bytes): **PASS on
  attempt 3** (52 PASS lines). Attempt 1: observer-probe `go build` exceeded the 120 s bound on the
  fresh guest's cold Go cache (the root cache was then warmed by building the same packages; bound
  unchanged). Attempt 2: `scripts/stargate init` exit 40, observer READY not confirmed within
  300 s. Both are loud failures before the CP-event windows; T196's CP-restart and
  first-subscription failure classes did not recur (0 of 3). Attempt 2's raw run.py log was
  overwritten by attempt 3's (same log name); its evidence directory is kept.
- `t155_stack.py` full (A2/A3/A7): **56 PASS, 0 FAIL**: authenticated, post-rotation and 180 s
  idle reloads (`ACKNOWLEDGED(n)`), unknown token denied, Tor bytes with CP up, completed-hour-only
  aggregates and retention (non-empty rows), label-only predecessor DP with `connect_refusal.py`
  PASS (A3 CONNECT contract), the repaired wire gate R1-R9 PASS with exit 0, old CP identity
  refused with a GetStatus refusal, the **TLS resumption phase** (resumed before rotation; old
  ticket refused with the handshake aborted; old identity refused; rotated identity answered; DP
  process unchanged), revocation, DP restart with CP down (snapshot restored and unchanged,
  CP-down Tor bytes), `STALE_CONFLICT` rollback refusal with revocation surviving and recovery,
  logging driver `none`, allowlisted state files only.
- T126 suite with the T155 device and site axes and calibration, `TestT126*`, `TestT155*`: PASS.
  T182 suite (`TestOnionLoad`, `TestT126PartitionUsernameReferenceVector`,
  `TestStreamIsolationPerFirstPartyDomain`): PASS. No reruns.
- `STARGATE_TEST_TAGS=docker tests/contract/stargate-cli/t162_enforcement_test.sh`: exit 0 (after
  T198's round-2 init change).
- Host browser probes on this candidate (pinned Mullvad Browser 153.3.0esr from `target/t157-tools`,
  geckodriver 0.37.0, disposable profiles; the host's 140.16.0esr is refused by the extension):
  `descriptor-matrix`, `blocked-proxy`, `private-access`, `full` all GREEN.
- This pass had no separate live `GetStatus` assertion. Its operational persistence checks
  do not establish DP traffic publication; round-1 review invalidated that earlier coverage claim.
- One tool-limit event: a host-side wait loop polling the guest was moved to the background by
  the tool limit once; no test or live command was cut short.

### Redteam survivors and dispositions (maintainer decisions, 2026-10-03)

Filing plan R was approved, written inside this candidate because Acceptance 6 requires the
filing before closure and a HEAD move would invalidate the tests-first baseline:

| Survivor (falsified claim) | Severity | Disposition |
|---|---|---|
| A2 M1: `browser-profile/user.js` lacks DoH-off/HTTP-3-off; `run.sh` Part 1 RED on a template-only profile; probes inject `trr.mode=5`; docs call it release-verified; no onion leak (X1 RAN) | Minor | new **T200** (blocks T078) |
| A2 m3: changed `tokens.yaml` loads after `STALE_CONFLICT` overtake the DP generation and re-authorize a revoked token (E4 RAN) | Minor | new **T201**, durable marker chosen over disclosure (blocks T078) |
| A3 m1: `connect_refusal.py` verdicts are bare `assert`s, removed by `-O` (RAN) | Minor | **T189** item 6 |
| A3 m7: CI toolchains pinned by version string only (Constitution IV) | Minor | **T199** item 3 |
| A3 m8 + A2 M4 residue: THREAT-MODEL presents unimplemented supply-chain mechanisms and §7.3 "encodes mitigations in code" | Minor | **T197** item 3 extension |
| A1 note: `unknown ca` vs `bad_certificate` (RAN) | Info | **T189** item 4 |
| A1 m4 evidence: `data-model.md:167` / `token.go` describe `loadedAt` inaccurately (RAN) | Info | **T189** item 7 |
| A2 i1(b): THREAT-MODEL `:1291` "never displayed" (fixed by T195) | Info | **T197** item 4 |
| A3 M1 (narrowed): Tor sidecar LAN/host reach, 989b8f9 residue | Info | **T197** item 5 disclosure; **T078** decides whether Tor counts as a "compromised application process" |
| A2 m4 New Identity, A2 m5 `readError` enum, A3 m11 quickstart teardown note, A3 i2-i6, A1 survivors-as-Info | Info | no ticket (recorded in the redteam summary) |
| T155's own files: A1 i1 (declined ticket), A2 M4 R-6 row, A3 m2/m3/m4 and the falsifier-3 F7 nit, tracker residue (lower-case "passed", nonexistent `tests/contract` paths, any 40-hex snapshot) | – | fixed in this candidate |

T078's `blocked_by` gains T200 and T201 (T189, T197, T199 already block it). The budget raise to
17 paths is labelled pre-granted (rule 2026-10-01) because Acceptance 6 names the filing; the
maintainer directed these six ticket paths into the candidate. Note: 17 exceeds twice the
pre-attempt-3 budget of 8; the maintainer's direction, not the rule, authorizes that part.
Draft redteam summary for `reviews/` (uncommitted): `.scratch/tmp/T155/redteam-a4/summary-draft.md`.

### Attempt 4 resumed after round-1 escalation (2026-10-03)

The maintainer selected **refine**, approving the exact Acceptance 6 replacement below and
requiring the F1 authenticated live `GetStatus` probe: generated traffic; repeated absence of
an active-hour row; a real UTC hour boundary on one running DP; a nonzero completed traffic
row; further traffic with the published row unchanged. The earlier claim that CP operational
persistence covered DP traffic publication is withdrawn. No override or Acceptance 7 narrowing
is authorized. `run-task.sh T155 --reset` archived the round-1 verdicts and recorded the abort.
GLM's Minor requires independently reproducible provenance for the three partition vectors.
The original baseline and staged candidate are retained; previous red/greens stay superseded.
The developer is a fresh Codex subagent inheriting its orchestrator's configuration, not Claude.
The installed Codex CLI is used for the ordinary review gate, with actual version recorded
before each round (0.160.0 observed at resume; no version pin).

The fresh independent plan outline was read before implementation. On 2026-10-03 the
maintainer approved one-time status recovery from `pending` to `in-progress`: START's
unconditional dirty-tree guard conflicts with retaining this already-started candidate.
HEAD, `start-sha`, staged contents and history remain intact. This resumes IMPLEMENT and
all normal downstream verification/review/commit gates; it authorizes no general bypass.

The existing maintainer-approved `Info — no ticket (recorded in redteam summary)` dispositions
remain informational observations already dispositioned, not open corrective-action findings
or claims that mechanisms were implemented. New/open actionable survivors follow Acceptance 6.
The new Python HMAC transcript in `evidence/T155-live-results.json` independently reproduces
all four partition vectors from the contract, addressing GLM's provenance Minor.

The added traffic probe's first live red passed clean init, authenticated reload and Tor-byte
positive controls, then failed on the first authenticated `GetStatus`: active Unix hour
497511 was exported. The only production mutation was Snapshot's `<` changed to `<=`.
It was restored exactly from HEAD after capture; earlier red/green pairs remain under
`superseded`. Command: `bash target/runs/T155a4r/traffic-tf.sh`. No red rerun was needed.


## Resume after T208 — 2026-10-05

Baseline and start-sha `f5558925547e81737987ea8ea34f6c09495e051d` (T208 done at `334835d`,
`496f89e`). The developer is a fresh Claude subagent on the orchestrator's configuration
(self-reported Fable 5.1 at the start of this resume and Opus 5.5 later in the same session;
not independently verified).

### Reconciliation of the preserved 13-path candidate

Source: the verified archive `park/20261005-t208/` (its `restore/` tree was compared
byte-for-byte with the preserved checkout before use). No path was dropped; the union is
13 paths within `files_budget` 17, so no budget raise was needed.

| Path | How |
|---|---|
| `tests/contract/compose/wireprobe/wireprobe.go`, `wireprobe_test.go`, `tests/contract/workflow/live_e2e_tracker_test.sh`, `tests/integration/partition_axes_test.go`, `route_diagnostic_test.go`, `stream_isolation_dp_uname_test.go`, `tests/live-e2e/local-topology/t155_stack.py` | taken as-is (none changed between `403d424` and `f555892`) |
| `tests/integration/stream_isolation_test.go` | merged: T208's comment line stays; the two D1 hunks applied on top without conflict |
| this ticket | merged: committed frontmatter, park note and history kept; the candidate's D1 direction and closure block inserted at its original place after Acceptance 6, and its 2026-10-04 `decision_refs` entry added |
| `specs/001-tor-route/live-e2e/README.md` | taken, then its Evidence index rewritten for this pass |
| `specs/001-tor-route/evidence/T155-tests-first.json` | taken as the starting record; the new red moved all six earlier records under `superseded` |
| `specs/001-tor-route/evidence/T155-live-results.json` | rewritten for this pass; the candidate's whole 2026-10-04 record is kept unchanged under `superseded`; the `partition_vector_provenance` transcript cited by `partition_axes_test.go` and the attempt-4 section above was re-executed on 2026-10-05 (output identical to 2026-10-03) and restored after round-1 review |
| `specs/001-tor-route/STATUS.md` | regenerated, not merged |

The earlier review history (`target/runs/T155.review-history`) was copied into this
worktree unchanged (SHA-256 `3c9f4174…6046d`) so later gate records append to it.

### Tests first on the new baseline

One command for red and green (hermetic `wireprobe` resume/early-abort tests, then
`TestT059RouteDiagnosticDoesNotInventTorRefusal`). Red was captured with every candidate
file staged except the D1 helper correction: the TLS controls pass and the three reply
classes 0x03/0x04/0x06 fail on the unrepaired helper while its six preservation controls
pass (red snapshot `857323da…`). The live mutant reds of earlier attempts bind their own
baselines and were not repeated; the test sources they exercised are unchanged.

### Final live pass (one pass, no rerun)

Evidence renewal: T208 changed the data-plane binary, so every check that deploys it or
runs the integration binary was executed again; F5's inputs are unchanged and it was
executed again anyway. Candidate identity, per-check results, timings, raw-log hashes and
limits: `specs/001-tor-route/evidence/T155-live-results.json`; raw artefacts under
`target/runs/T155r/`. Fresh copy of the saved QEMU TCG guest (`guest-T155r.qcow2`), one boot.

| Check | Result (attempts) |
|---|---|
| F1 `run.py` | exit 0, 52 pass lines, no fail or skip (1) |
| F2 `t155_stack.py` full, F3 inside | exit 0, 104 pass, 0 fail (1): wire rows R1-R9 each PASS with script exit 0; old identity refused after rotation; TLS resumption phase (resumed before rotation; old ticket on the pin-verified resumed path gets no RPC; old identity refused; rotated identity answered); real UTC rollover at 09:00 on one running DP with 7 empty pre-rollover reads, then an unchanged completed row (5 requests, 1113 bytes) through three further traffic rounds; `connect_refusal.py` exit 0 |
| F4 T126 suite with device and site axes | exit 0, 14 pass records (1) |
| F4 T182 suite | exit 0 (1): `TestOnionLoad` PASS, one attempt, `ok` after 91.86 s, 225341 bytes; `TestStreamIsolationPerFirstPartyDomain` PASS |
| F5 four browser modes, pinned Mullvad Browser 153.3.0esr | all four GREEN, 35 scenarios (1) |
| F7 T162 docker tier | exit 0, both groups OK (1) |

The mandatory HTTPS onion load is proved on the 250 s data plane by this one selection.
The 2026-10-04 control-plane exit during the wire gate did not recur; its cause is still
unknown. `TestOnionLoad`'s control onion (not part of its verdict) returned a failure reply
after about 120 s. No tool time limit ended a test command.

### Cumulative redteam on this candidate (Acceptance 5)

Blind export of index tree `d6f46b9b8eb269814b316a40e86a3826b728226e` (432 files; review
history, findings, SECURITY-DECISIONS, tickets, STATUS, evidence, analysis, journal and
scorecard removed). Three `stargate-redteam` reviewers (transport; control plane and
browser; deployment), each self-reported Claude Opus 5.5, then three `general-purpose`
falsifiers with the project history, each self-reported Claude Fable 5.1. All Claude, models
not independently verified, independence limited to fresh context (the developer is also
Claude). Everything was read-only source inspection: no build, test, container, browser or
probe was run by reviewers or falsifiers, because the live pass was in progress. Reports:
`.scratch/tmp/T155/redteam-r5/` (gitignored); this section is the durable record.

- Claimed: 1 Blocker and 4 Majors (area 2: B1 onion-page clearnet requests go Direct, M1
  shipped profile lacks DoH/HTTP-3 off, M2 threat-model prose for mechanisms that do not
  exist, M3 stale popup route label; area 3: M1 AppArmor confinement not checked on the
  running DP), 22 Minors, 18 Info.
- **After falsification no Blocker and no Major survived.** B1, M1, M2 and M3 are the
  claims already owned at Minor by T190 item 7, T200, T197 item 3 with T190 item 3, and
  T197 item 1. Area 3 M1's core repeats a claim falsified in the 694dbd8, 79d49e9 and
  989b8f9 passes (on the measured rootful local daemon a host without AppArmor exits 60
  and a missing profile makes Docker refuse the start). The eight area 1 Minors are
  owned by T189 items 1-5 or T067a/T067b, already accepted and disclosed, or falsified
  against the contracts.
- The new increments that survived, all Minor or Info, and their dispositions are in the next
  section.

### Survivor dispositions and filings (maintainer decisions, 2026-10-05)

The maintainer chose the filing shape "Fold in, one new ticket" and the process "Evaluator
checks, then file" (2026-10-05, relayed by the orchestrator). An independent evaluator checked the drafts before anything was written, and its required
corrections were applied. The same evaluator session then re-checked the second revision,
read-only, and returned APPROVE WITH REQUIRED CORRECTIONS; its further corrections were
applied before filing. The evaluator is Claude: the first pass self-reported Fable 5.1 and
the re-check runtime reported Opus 5.5, neither independently verified, so independence is
limited to fresh context from the developer. In the first pass the evaluator ran
`git write-tree` once by mistake, outside its read-only brief; the index file hash was
unchanged between the end of the first pass and the re-check, and the re-check ran no git
command that writes.
The filings are inside this candidate because Acceptance 6 requires them before closure and
a HEAD move would invalidate the tests-first baseline. The budget raise to 19 paths is
maintainer-approved by the filing choice; the twentieth path (T077's `blocked_by`) was
decided by the orchestrator under the maintainer's delegation of 2026-10-05 ("evaluate and
ultrathing best solution"). Neither is pre-granted.

| Survivor (after falsification) | Severity | Disposition |
|---|---|---|
| A2 B1 redirect sub-case: an onion-to-clearnet HTTP redirect is not named or tested (READ, not run) | Minor | **T190** item 7 addition: the maintainer's 001-specific reading, then a block-or-disclose decision before T078, then disclosure and a test written to that decision |
| A2 M3 new part: a main-frame navigation that never commits leaves the Tor label over a clearnet page (READ, not run) | Minor | **T197** item 1 addition |
| A3 M1 increment: `init` verifies the invoking kernel, not the running DP's label; supported daemon scope unstated; the harness reads `docker inspect` | Minor | new **T209** (blocks T078 and T077) |
| A3 m3: observer `read_only`, `cap_drop` and `no-new-privileges` unasserted | Minor | new **T209** |
| A3 m5 comment half and m6 T203 orphans: Dockerfile/Makefile "verified"/"digest pinned" comments; env example and local-topology README describing the pre-T203 observer; quickstart Engine-floor reason citing a removed `subpath` | Minor | **T209** Acceptance 8 (maintainer: "Split to T209 (Recommended)") |
| A3 m6 remainder: THREAT-MODEL banner/§5.9, `CLAUDE.md` deployment sentence | Minor | **T197** item 6 |
| A3 m1 gitleaks half: CI gitleaks binary not digest-checked | Minor | **T199** item 4 |
| A2 m2: `<local>` bypass leaves single-label hosts unrouted | Minor | **T190** item 10 (filed under Acceptance 6; maintainer delegated the choice 2026-10-05, orchestrator decided) |
| A2 m3: two labels sharing one token value | Info | **T190** item 8 addition |
| A2 m4: 8881 squatting while the DP is down | Info | **T197** item 7 |
| A2 M2 residue: `run.sh` still names the foreign-extension inventory | Info | **T197** item 3 addition |
| A2 m7: THREAT-MODEL §4.1 and §4.3-§4.5 describe routes 001 does not ship in the present tense, with no per-route implemented/target label (Principle V) | Info | **T197** item 8 (maintainer: "Owners for two, rest no ticket (Recommended)") |
| A3 m2 increment: the `docker-cadence` path filter omits `data-plane/cmd/tor-health-publisher/**` (in the Tor image since T203) and `data-plane/cmd/tor-observer/**` (in the observer image) | Info | **T199** item 5 (same decision) |
| A1 i5: `tor:9050` wording in `socks5-auth.md` and `dpharness.go` | Info | **T189** item 4 addition |
| A1 i3: verifier-count timing (read from the code; unmeasured) | Info | **T189** item 8 |
| A3 i3: a compromised DP can read the host name (interface identifiers via socket ioctl unverified); A2 i6: the CP image copies its jars owned by the runtime user (read-only rootfs mitigates); A3 i6: `init` admits one fixture Compose path under the repository root, by design (T162); A1 m7 refinement: on a quiet host the hourly rows also let the CP infer one tunnel's lifetime (same class as the THREAT-MODEL quiet-host disclosure) | Info | no ticket (maintainer, 2026-10-05); this row is the durable record, the scratch reports are not |
| A3 i4: the Tor entrypoint's 0.2 s poll spawns about five short processes per iteration | Info (performance) | no ticket; for the `stargate-perf` pass at T079 |

Notes, not findings (maintainer delegated the choice 2026-10-05; orchestrator decided not to
ticket them): `proto/stargate/v1/control.proto` names T067b's contract-test harness as a
`GetStatus` caller (its test file is named in `contracts/control-grpc.md`); whoever runs
T067b checks that the comment still holds (the falsifier did not establish it is wrong). A
DP-side `sg1:` username-shape gate (F1 m1) is an optional design change for the maintainer;
a quickstart line "restart the DP after repairing keys" (F1 i4) is optional. Two leftovers
were homed under the same delegation: the `init` comment on `stargate-keys` ownership,
noted by the area 2 falsifier (T190 item 5), and the `torrc.md` "Parses the golden"
sentence that T208 recorded as incomplete (T189 item 4).

T078's `blocked_by` gains T209; T189, T190, T197 and T199 already block it. T077's
`blocked_by` gains T209 (T209 changes `init` and the quickstart prerequisites T077 walks
through; T088 hands daemon variance to T077). None of these blocks T155: no Blocker or Major
survived.

Redirect reading (maintainer, 2026-10-05, "A: No, scoped + release decision"): under 001's
destination-only routing, an onion page's redirect to a clearnet URL is not an "automatic
route downgrade" (Constitution III network-origins matrix). The reading is specific to 001
and does not extend to user-selected routes. Disclosure wording and a redirect test are
filed under T190 item 7. Before T078 the maintainer decides whether clearnet requests
initiated from an onion page are blocked instead of only disclosed; T190 item 7 records
that decision before its test is written. Because the reading is "no", the falsifier's
condition for this item to block T155 is not met. No onion-to-clearnet redirect has been
run; the behaviour is read from `router.js`.

Acceptance 5 (maintainer, 2026-10-05, "Accept Claude-only now"): the r5 pass recorded above
is this ticket's cumulative pass. Its form: three `stargate-redteam` reviewers and three
falsifiers, all Claude (reviewers self-reported Opus 5.5, falsifiers self-reported Fable 5.1;
not independently verified), read-only source inspection (nothing was built or run; the
developer is also Claude), on the blind export of index tree
`d6f46b9b8eb269814b316a40e86a3826b728226e`. One falsifier ran `git write-tree` in the
worktree, outside its allowed read-only commands; it printed the already-recorded tree id
and reported no other write. Against that snapshot the candidate adds the two evidence JSONs and the new T209 ticket,
and changes this ticket, STATUS.md, the live-e2e README (its Evidence index) and tickets
T077, T078, T189, T190, T197 and T199; none of those is executable. After review round 1 the
candidate also changes `tests/live-e2e/local-topology/t155_stack.py` (entrypoint only) and
adds `tests/live-e2e/local-topology/test_t155_stack.py`; that change was not seen by the r5
pass and is covered by the ordinary review of round 2 (next section). The Astra and GLM cumulative passes remain T078's under the
2026-09-29 decision recorded there.

### Review round 1 and the harness completion guard (2026-10-05)

Driver verify before review: GREEN, 38 gates passed, 4 skipped (the wire runtime rows and the
T162 docker tier, both run live in F2 and F7; the docker operational capture; release-cadence
reproducibility), none failed.

- Round 1 (snapshot `c879c531…`): both reviewers APPROVE-WITH-FIXES, one Minor each, both
  documentation. Astra: the evidence did not state the two isolation limits the contract
  requires of T155 evidence; the sentence was added to the README Evidence index. GLM: the
  `partition_vector_provenance` transcript cited by `partition_axes_test.go` was missing from
  the results record; the command was re-executed (output identical to 2026-10-03) and the
  section restored.
- Round 1 refresh after those fixes (snapshot `fb1ade0e…`): GLM APPROVE; Astra REWORK with one
  Major. `t155_stack.py`'s entrypoint caught only `Exception`, so an interrupt inside a
  phase skipped the failure record and the `finally` block exited 0 from a partial result
  list; nothing checked that the run was complete. Astra did not claim the recorded run
  was interrupted.

Maintainer decision (2026-10-05, "Completion guard, carry evidence (Recommended)"), tests first:

- Red: `test_t155_stack.py` executes the real entrypoint block with stand-in phases. Against
  the unrepaired harness, an interrupt after one passing check, `SystemExit(0)` inside a
  phase and an early return each ended with exit 0 in all three modes (9 failures); the
  cases that need the mandatory list failed or errored because none existed; the
  ordinary-exception control passed.
- Fix: the harness declares the mandatory check names per mode (`MANDATORY`: 65 names for
  the full run, 10 for `--only resumption`, 11 for `--only traffic`, with minimum counts
  for the repeated traffic checks). The entrypoint records an interrupt or any other
  `BaseException` as an explicit incomplete failure, records a failed cleanup, and exits 0
  only when every mandatory check of the mode was recorded PASS and nothing failed.
  Cleanup still runs.
- Drift guard, as chosen: the test reads the `check()`/`require()` names from the harness
  source (per function, with the wire-row names expanded) and requires the declared list of
  each mode to equal them, so a new or renamed check cannot be left out. The comparison with
  a completed run's `results.json` is done once, below, as the carry-forward check; it is
  not a permanent test, because raw results are not in the repository.
- Green: the identical command passes (11 tests at that point; 13 after the round-2 additions below). The D1/TLS red/green pair moved under
  `superseded` in the tests-first record with the six earlier records.

F2 is carried forward without a rerun (README D-live-6). The recorded run used the pre-fix
harness. Only the success decision and the abnormal-termination paths changed: the first
558 lines of `t155_stack.py`, which hold every function and check body, are byte-identical
before and after, and no file under `data-plane/`, `control-plane/`, `compose/`, `sidecars/`
or `scripts/` changed. The recorded `results.json` (SHA-256 `cd839c3d…`) was checked with the
repaired harness's own `missing_mandatory`: all 65 mandatory names are present with at least
the required counts, no recorded name is outside the list, and none of the 104 results is a
failure. Its raw log ends with the last check of the full run. The comparison is recorded
in `evidence/T155-live-results.json` (`f2_carry_forward`). The repaired entrypoint and the
two focused modes have hermetic coverage only.

Round 2 (snapshot `13df1e5d…`; a first launch failed closed on a rejected Codex login and
imported nothing): both reviewers APPROVE, each with one Minor in this ticket's own harness.
Both were fixed here before commit instead of being left for a follow-up, tests first, and
the changed candidate was re-reviewed in the same round. Astra: a non-zero exit of
`docker compose down` was ignored, so a failed teardown could still end with exit 0; red
(3 failures, one per mode) then green, and the entrypoint now records it as a failed cleanup.
GLM: the drift guard read check names only from functions, so a check added at module
level would escape it; the test now requires that no `check()`/`require()` call exists
outside a function (with positive controls for its detector). Neither change touches a
check body or the recorded results, so the F2 carry-forward above is unchanged; whether the
recorded run's teardown returned zero was not captured by the earlier entrypoint.

Two items from the Acceptance 1 closure re-check were given owners inside tickets already
in this candidate (maintainer, 2026-10-05): the stale present-tense ControlPort description
in the 2026-07-16 T094a SECURITY-DECISIONS entry is T209 Acceptance 9 ("Stale SD entry to
T209 (Recommended)"; the wording stays reserved for the maintainer and nothing was written
to that file), and release-cadence item R-7 is owned by T078 ("R-7 to T078 (Recommended)").

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
6. Leave T078/T079 pending for the completed milestone. File new findings as focused remediation tickets. Surviving Blocker/Major findings block this ticket; surviving Minor/Info findings block T078 and their affected consumers, and T078 cannot complete while any remains open. Reverify closure.


**D1-only governing maintainer direction — 2026-10-04.** The user explicitly
approved "ok do that in the 155" after the orchestrator described correcting D1
within T155 with a specific exception to follow-up filing. For this source-backed
Info only, current T155 owns the static `t059ClassifyDialErr` `unknown error `
result/comment correction and `TestT059RouteDiagnosticDoesNotInventTorRefusal`.
This governing direction supersedes A6's new-ticket filing sentence and the
workflow's done-ticket-to-new-remediation rule for D1 only; exact A6 remains above.
No T207/T189 filing, new consumer edge, completed T059/T126 ticket/history amendment,
constitutional exception, privacy waiver or unresolved-finding acceptance is authorized.

Author the real-helper regression before the fix and preserve behavioral RED then
identical-command GREEN, including nil, AUTH, listener/deadline branch controls and
nonempty ROUTE for fixed 0x03/0x04/0x06 without arbitrary details or invented native
Tor refusal. Preserve branch order and every caller's failed-CONNECT Fatal guard.
Record D1 and its independent closure check; all other A6 finding rules remain binding.
The current combined capture naturally preserves the original TLS RED under
`superseded`: its new RED proves D1 while the repaired TLS controls pass. The original
TLS command is also executed unchanged as a separate passing observation; no older
record is promoted or transcribed. Candidate-bound evidence and normal gates remain
required. This bounded rework adds only the shared helper and focused regression to
the existing paths; with the sanitized results index the union is 13 paths within 17.

Evidence renewal follows affected inputs: retain every actual executed snapshot,
compare unchanged input scopes, and do not represent an old full source or binary as
the corrected one. This static diagnostic correction intrinsically needs hermetic
proof and independent guard review; no new live run is authorized by it. Required
HTTPS onion load remains unproved after two actual TestOnionLoad failures with
UNKNOWN original causes. T155 remains incomplete; this repair supplies no permission
to retry, change targets/windows/auth-readiness gates, or run final verification/reviews
against a known missing mandatory live property.

**D1 independent closure — 2026-10-04.** The fresh independent falsifier
reverified the bounded Info correction: the exact corrected helper passed all nine
regression controls (exit 0); substituting the exact original helper only in an
isolated copy failed 0x03/0x04/0x06 while the six preservation controls passed
(exit 1). It independently checked the unchanged caller Fatal guards, identical
combined controller argv/source binding and retained original TLS chronology.
Report: `/home/claudia/stargate/.scratch/tmp/T155/D1-closure-falsification/report.md`,
SHA-256 `392920cb97c351ea15a9afec3fab45457ebc320847c6d5a5e7e6285a24b617ed`.
Corrected/original raw SHA-256:
`e7107f76eaaf6e895f95b8e6c94c0acff142ceb7c3e09047b5fc7e51be671718` /
`78023da6cfcce818c1486842636f2d3df9346afea04b7cdac303d4cb2578a0ba`.
D1 is repaired and independently reverified with no bounded survivor. This is
not an ordinary reviewer verdict or whole-ticket approval: mandatory HTTPS onion
load remains unproved after two failures with UNKNOWN causes, and T155 remains
incomplete. This closure supplies no permission for another runtime attempt.

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
