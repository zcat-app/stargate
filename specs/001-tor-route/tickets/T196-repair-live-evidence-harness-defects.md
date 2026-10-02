---
id: T196
title: 'Repair live-evidence harness defects found by the T155 pass'
status: done
created: 2026-10-01
last_updated: 2026-10-02
source: "T155 attempt 3 live pass and cumulative redteam (candidate 989b8f9); harness defects reproduced by the T155 developer, confirmed by both T155 reviewers"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 10  # ticket + generated STATUS.md + inter_plane_wire_test.sh (+ fixture test) + observer.py + test_observer.py + run.py (+ test_run.py); extend with a stated reason if a fix needs more
                  # raised 8 -> 10, pre-granted (rule 2026-10-01): evidence/T196-tests-first.json (fixed overhead);
                  # tests/live-e2e/local-topology/README.md (orphan: its 35 s window, gap and IPv6 prose is made stale by A2/A3)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "VII: Tests First for Privacy-Critical Paths"
  - "VI: Open and Auditable"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/live-e2e/README.md
  - specs/001-tor-route/contracts/control-grpc.md
decision_refs:
  - "T155 live-e2e README D-live-7: a harness defect is fixed by a ticket, not reported as a pass"
reviews: { round: 2, date: 2026-10-02, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T196: Repair live-evidence harness defects found by the T155 pass

## Context

T155 attempt 3 ran the live Local checks on candidate `989b8f9` and found harness
defects. They do not change shipped behaviour; they make evidence unreliable.

## Analysis

- Must hold: a live check prints PASS only if its assertion ran and could have failed,
  and a defective row never reports success.
- Gated: `scripts/verify.sh` (hermetic fixtures for each repaired decision rule); live
  re-runs on the disposable guest.
- Residue: the CP-event window length must stay below the inter-plane channel lifetime
  (T148), so headroom is gained by restructuring what the window contains, not by
  lengthening it; that design choice is for this ticket's planning round.

### Grounding notes (START, 2026-10-02)

- `spec_refs` names `specs/001-tor-route/live-e2e/README.md`, which does not exist on
  `001-tor-route`: the T155 attempt-3 README is parked unreviewed on `wip/T155-attempt3`.
  D-live-2 (fec0:: route) and D-live-7 (harness defects are fixed by a ticket, never
  reported as a pass) were read from that branch. The Acceptance text is self-contained,
  so this is a WARN, not a clarity failure; Acceptance 3 is met in the runner, so no README
  on this branch is needed.
- The CP event server sets `maxConnectionAge(40 s)` with no grace
  (`ControlGrpcService.java`); grpc-java applies about ±10 % jitter, so a subscriber
  can be closed after 36 s. Each observation window must stay well below that.
- `SidecarMonitor` samples, emits at most the transition events, then sleeps
  10 s; the CP's observer call has a 6 s cap. Events only occur at samples.

### Property map

| Must hold | Gated by | Residue |
|---|---|---|
| R2 passes iff the peer UID's real `connect(2)` succeeds; R3 passes iff the out-of-group UID's `connect(2)` fails with EACCES, and any other outcome is not a pass | new hermetic row fixtures (real Unix sockets, mode 0660/0000/0666, missing path) | live run on the guest, plus live mutants |
| R5 fails when any bad major is not rejected with FailedPrecondition or major 1 is refused | fixtures driving the row with stubbed `wireprobe` exit codes | live run plus a live mutant |
| R7 counts only listeners whose socket inode belongs to the DP process | fixtures with a "DP" listener process and a second, foreign listener in the same namespace | live run (host-network DP) plus mutant |
| A row prints PASS only if it recorded no finding | fixtures asserting `Rn: FAIL` and no `Rn: PASS` after a finding | |
| Observer windows: a window asserts silence for a repeat sample only after receiving that phase's transition event (no-event phases rest on the 1 s allowance, disclosed); each window closes well before 36 s; early closure is loud; no reconnect | `test_observer.py` simulated-clock fixtures (slow actions, late duplicate, delayed registration, stale-reply sample) | live `run.py` repeats and observer mutants on the guest |
| `run.py` keeps the IPv6 non-loopback refusal on a QEMU guest whose only IPv6 address is site-local `fec0::` | `test_run.py` fixture | live `run.py` on the guest with IPv6 left enabled |

Design (planning round, superseded in round 2): each CP-event phase became two overlapping
windows relayed across phases. Round-1 review (Astra) showed the second window's silence was
not anchored by a received event; see "Maintainer decision" below for the round-2 design.

## Maintainer decision (2026-10-02, round 2)

Option A, tightened, with four conditions: (1) in every event phase a window whose
silence is asserted must first have received that phase's transition event, and a
successor registered after a duplicate is published must make the harness reject the run;
(2) the no-event phases (malformed, timeout) keep one window each, as before T196, and the
evidence JSON and README state per phase that their silence rests on the 1 s
post-SUBSCRIBED allowance; (3) no `continuous_overlapping_windows` claim and no continuity
statements; (4) every Unix-socket dial is bounded, a timeout fails the row and never counts
as EACCES (with a regression test), the exit-code comment is corrected, and the live suite
is rerun with every window under the T148 lifetime and every rerun disclosed with its count.
If any condition cannot be met without lengthening a window past the T148 lifetime or
weakening an assertion, stop and return.

## Implementation and evidence (2026-10-02)

- **A1 (wire rows).** R2/R3 dial with a real `connect(2)` (perl's socket API in the pinned
  image) as the named UID, bounded by `timeout 5` (round 2): a wedged peer fails the row with
  exit 124, which never counts as EACCES. R3 passes only on EACCES (13); a missing path
  (ENOENT, exit 1), a `socket(2)` failure (exit 3) or a timeout is not a refusal. R5 reads
  wireprobe exit 0 as "the §5.2 rule held". R7 counts only TCP LISTEN sockets whose inode is
  among the DP process's own descriptors (root needed; no verdict without attribution). Every
  row reports through `row_begin`/`row_end`, so it prints PASS only with no finding.
  `svc_running` now captures before matching: under `pipefail`, `docker ... | grep -q` failed
  whenever grep exited early and the writer died of SIGPIPE, which skipped rows at random
  (found while building the fixtures). Hermetic fixture
  `tests/contract/compose/inter_plane_wire_rows_test.sh` runs the real gate against a stub
  Docker with real Unix sockets and processes: all rows PASS on a correct stack; a 0666
  socket, a missing socket and an unreachable peer socket fail R3/R2; a non-rejected major 0
  or 2, a refused major 1 or an accepted metadata-less call fail R5; a second DP listener or
  no listener fails R7 while a foreign listener in the same namespace never counts; a peer
  whose accept queue is full fails R2 with exit 124 and, made world-dialable, fails R3 as
  "exit 124, not EACCES", both within the fixture's 180 s gate bound (round 2).
- **A2 (observer windows), round 2.** `SUBSCRIBED` proves a sent request, not server
  registration, and the CP replays nothing. So in every event phase the window that asserts
  silence for the repeat sample has first received that phase's transition event
  (`silence_anchor`: "transition event received in this window before its repeat sample").
  Reply-triggered phases and observer-down use one window opened about 7 s before the next
  monitor sample (observer-down: right after a sample, the stop inside the window). The
  observer-start phases hold the fake's reply malformed during `docker start` (UNAVAILABLE,
  no event), then a second window attaches before the real reply is set and receives the
  transition; the first window, which covered the action, must also have received it. The
  malformed and timeout phases keep one window each as before T196; nothing can anchor them,
  and the JSON and README say their silence rests on the 1 s post-SUBSCRIBED allowance. No
  continuity is claimed (`continuous_overlapping_windows` removed). Waits are deadlines from
  observed samples (fixed 22 s, 6 s and 1 s sleeps removed); the fake records the reply
  generation of each GETINFO, so only post-trigger samples count, contiguously. No window
  reconnects; an early closure still fails. `test_observer.py` simulates the CP, observer and
  fake Tor on a virtual clock: the pre-T196 code passes it with 1-3 s actions (max window
  32.5-34.5 s) and fails with 6-10 s actions; the round-2 code passes with 10 s actions (max
  30.2 s; 29.7 s with 1 s actions; 33.8 s with 8 s actions and a 5 s connect) and rejects a
  late duplicate at the repeat sample, a false timeout event, a silent publisher and, Astra's
  round-1 falsifier, a successor window registered 15 s late while a duplicate is published
  (round-1 code returned exact_events=true for it). 15-20 s Docker actions now end in a loud
  early closure in the simulation; they did not occur live.
- **A3.** `run.py` probes a site-scope (`fec0::`, RFC 3879) IPv6 egress address like a
  global one; a routed interface with no probe-able address still refuses to run. The guest
  ran with IPv6 enabled, so the IPv6 packet matrix, forwarder, resolver and listener refusal
  ran on the guest's routed `fec0::` path.
- **Tests first.** `specs/001-tor-route/evidence/T196-tests-first.json`, one probe command
  throughout. Round 1: red against the unchanged harness (R2 never passes, R3 passes a 0666
  socket, R5 fails correct verdicts, R7 lists workstation listeners, PASS after findings;
  slow-action windows closed early; fec0 refused), re-captured once after the fixture's own
  `printf | grep -q` checks were made SIGPIPE-safe. Round 2: red against the round-1
  implementation (wedged peer hangs the gate: exit 124 in S8/S9; the delayed-registration
  falsifier passes falsely; `continuous_overlapping_windows` still claimed), then green.
  Earlier records are kept under `superseded`.
- **A4 live, round 2 (disposable QEMU TCG guest, kernel 6.8.0-142, Docker 29.1.3, Compose
  2.40.3, guest IPv6 left enabled, rebooted between rounds).** Candidate = HEAD `c6d6cc2` plus
  this ticket's worktree; guest hashes equal the committed files (`observer.py` a26080e9…,
  `run.py` 46340227…, `inter_plane_wire_test.sh` d78b02ad…). No real browser was needed.
  - `run.py`, six attempts in this order: R2-O1 FAIL (the first subscription right after
    the CP restart printed no `SUBSCRIBED` within 10 s), R2-O2 FAIL (the restarted CP did not
    recreate its event socket within 240 s), R2-O3 PASS, R2-O4 PASS, R2-O5 PASS, R2-O6 PASS (4 consecutive passes; O5/O6 ran after the wire phases with the host reset to run.py's fresh-host precondition). Both failures
    precede every T196 window decision (the CP-restart wait and the first connect are
    unchanged from before T196) and fail loudly. Passing runs: 52 PASS lines each; longest
    window per run 28.2, 28.7, 29.1, 28.4 s (all under the 36 s jitter floor); per-phase windows 19.7-29.1 s;
    malformed/timeout recorded with the 1 s allowance anchor.
  - Observer mutants (unmodified harness, one stimulus wrapped at runtime, 300 s settle after
    `init`): `observer-down`'s stop made a no-op → caught ("event sequence mismatch") on its
    first round-2 attempt; `ready-and-repeat`'s repeat sample answering NOT_READY (real CP
    publishes UNHEALTHY in the anchored window) → first round-2 attempt failed before the
    mutated phase (CP event socket not recreated within 240 s, not counted); the second attempt → caught ("event sequence mismatch").
  - Wire gate on a real `init` stack: the old gate reported R2 findings while printing
    `R2: PASS`, R5 findings for correct majors and R7 host listeners 22/53/44041. The
    repaired gate with mutations enabled: R1-R9 PASS, exit 0. Mutants: `control.sock` 0600 →
    R1 and R2 FAIL (dialer exit 13); ipc dir 0771 with sockets 0660 → R3 still PASS (socket
    mode alone refuses); plus sockets 0666 → R3 FAIL (uid 1234 connected) and R1 FAIL; a DP
    image accepting newer majors with an extra listener on 127.0.0.1:8899 (descriptor check
    bypassed) → R5 FAIL (majors 2, 99) and R7 FAIL (8899 only); restored DP → all PASS. A row
    with a finding printed FAIL, never PASS. A live wedged-peer mutant was not built; the
    bounded dial is covered by fixtures S8/S9.
  - Round 1 (superseded relay design, hashes `observer.py` c23de1e3…, gate a30c75e6…): 4 of
    4 counted `run.py` passes after two environment failures, both observer mutants caught
    on reruns, the same wire results; kept as history only.
  - Raw logs and per-run JSON: `target/runs/T196-vm/guest-evidence/guest-evidence-r2.tar` (round 1: `guest-evidence.tar`; gitignored); wrappers
    and mutant scripts in `target/runs/T196-vm/`.
- **Not changed:** `THREAT-MODEL.md` §"T174 live evidence boundary" says a "non-reconnecting
  35-second window" and that gaps are not continuous-monitoring evidence; both stay true
  (every window is shorter, and no continuity is claimed). T196's THREAT-MODEL wording needs
  separate maintainer approval, so it is left as is.

## Acceptance

1. `tests/contract/compose/inter_plane_wire_test.sh` runtime tier (never run live since
   T045): R2 and R3 open the Unix sockets with bash `exec 3<>socket`, which always fails
   with ENXIO (so R3's refusal check can never fail and R2 can never pass); R5 treats
   `wireprobe` exit 0 (the bad protocol major was rejected) as "accepted"; R7 reads
   `/proc/<pid>/net/tcp` of the host-network-namespace DP and sees host listeners; and every
   row prints `PASS` even after `bail` recorded a finding. Repair each with a real dialer as
   the named UID, correct exit semantics, DP listeners attributed by process, and a row that
   prints PASS only when its assertion succeeded. Add fixtures with discriminating negative
   controls (for example a 0666-mode socket must fail R3; a rejected major must pass R5).
2. `tests/live-e2e/local-topology/observer.py` CP-event windows are fixed 35 s subscriber
   lifetimes with a few seconds of headroom under emulation: `run.py` failed in 3 of 4
   identical attempts at the `initial-not-ready-and-repeat` and `observer-down-and-repeat`
   windows. Make the window robust (for example start counting after the triggering action
   returns and drop avoidable fixed sleeps) without lengthening it past the T148 lifetime,
   keeping early-closure failure loud and no reconnect.
3. `run.py` refuses a guest with a `fec0::` route (QEMU user network): document the
   disposable-host prerequisite or handle it in the runner with the same IPv6 refusal
   checks retained.
4. Re-run the live Local suite on the guest and record that the repaired checks pass and
   that each repaired decision rule fails against its mutant.

## Out-of-scope

Product code, Compose, the extension, and weakening any assertion.
