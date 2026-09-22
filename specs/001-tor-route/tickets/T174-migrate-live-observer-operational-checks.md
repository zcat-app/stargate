---
id: "T174"
title: "Migrate live observer checks to silent operational boundaries"
status: in-review
created: "2026-09-22"
last_updated: 2026-09-22
source: "T152 round-2 GLM review of b0c86f2196a6e58fa02753c2ded961d06b2573245f981e8f73797beed78b9111"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T152"]
parallel: false
files_budget: 10
privacy_critical: true
complexity: "medium"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md Principles II/III/V/VII", "specs/001-tor-route/contracts/foundation-boundaries.md", "specs/001-tor-route/data-model.md §4", "THREAT-MODEL.md §5.18"]
decision_refs: []
remediates: "T152"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T174: Migrate live observer checks to silent operational boundaries

## Context

T152's two round-2 reviewers approved its runtime/storage repair. GLM separately identified
stale live-cadence consumers outside that candidate: `tests/live-e2e/local-topology/observer.py`
still expects Tor's Docker HEALTHCHECK and `State.Health.Status`, and derives CP event coverage
from the DP's now-forbidden receipt journal. `test_observer.py` mirrors those expectations.
These assertions must be migrated before T155 can use fresh integrated evidence. Historical
T165 evidence remains historical; it does not validate the post-T152 operational boundary.

## Analysis

- Must hold: no Docker health history or raw operational journal is restored. Current Tor
  readiness remains authenticated and bounded; CP-down DP authentication/forwarding still works.
- Gated: named absent-health/empty-journal Python regressions, real authenticated Unix-socket
  subscriber tests, current CP pin/certificate validity and wire-shape controls, finite-token,
  duplicate/EOF/overflow and delayed-timeout falsifiers, plus `scripts/verify.sh`.
- Residue: actual Local namespaces, current source/image identities, CP event timing, socket
  recreation and real Tor CP-down bytes require new live evidence. Test-only authenticated
  subscription proves CP publication, not production DP receipt; separate bounded windows
  do not claim continuous monitoring. Skipped checks cannot establish that evidence.

## Acceptance

1. Reproduce the stale live observer assertions against post-T152 behavior before changing them;
   add a named regression that fails for absent Docker health metadata and an empty DP journal
   while the appropriate authenticated current observation is available.
2. Replace Docker-health assertions with bounded authenticated current readiness using the
   existing observer boundary. Preserve the actual CP-down authentication and routed-byte checks;
   a running container or open DP TCP port alone cannot stand in for Tor readiness.
3. Preserve the live CP event/failure matrix, no-duplicate/no-false-event assertions, socket
   recreation and observer stop/start coverage through an authorized ephemeral observation path.
   Do not re-enable production diagnostic receipts or persist raw lifecycle/detail streams to
   make the old harness pass. Retain positive and negative controls and summarize outcomes.
4. Update `test_observer.py` and affected live-run documentation alongside the harness. Run
   `scripts/verify.sh`, focused observer regressions and the documented live Local checks. State
   missing live prerequisites explicitly; no SKIP-to-PASS substitution or reuse of pre-T152
   evidence as proof of the changed observation mechanism.
5. Keep T155 blocked until this repair and its independent review are complete. Record the
   tested source/image identities and invalidate affected evidence after further changes.

## Out-of-scope

Constitution changes, reopening T152's completed implementation, changing auth/routing authority,
restoring Docker health history or per-event logs, and claiming live anonymity from fixture tests.

Existing health/journal expectations in `tests/live-e2e/local-topology/observer.py` and
`test_observer.py` are explicitly superseded by T152. Their underlying authentication, current
readiness, event correctness and CP-down routing coverage must be retained.
The maintainer also authorized replacing `run.py`'s stale confinement-fault journal
expectation and adding `test_run.py` regressions; exit status, absent admission and
restored positive controls remain required.

## Notes

This is the executable follow-up requested by T152's review, not a finding override or a new
permission to retain operational history. The tests-first regression is authored within this
combined test-repair ticket; `tests_first` therefore names no separate always-red test ticket.
Ground the observation mechanism and file inventory before implementation; refine the scope if
the default budget cannot contain the repair.

## Execution evidence (2026-09-22)

The implementation baseline is `6155c94ad69e4da054f54da38a8fc8a8b28000b6`.
Its prerequisite documentation commit preserves the previously completed ticket/review
bookkeeping and T155's explicit T174 dependency; no production implementation was changed.
This candidate touches ten paths including this ticket, generated STATUS and threat model.
The maintainer explicitly approved the expansion from eight to ten files on 2026-09-22.

Tests-first evidence is preserved under ignored `target/runs/T174/`:

- `stale-consumers.log` reproduces both post-T152 failures against the original harness;
  `pre-fix.json` records its source hashes. `regression-red.log` includes named absent-health
  and empty-DP-journal failures with the replacement observation available.
- `event-probe-red.log` records the unimplemented subscriber contracts (compile failure,
  not standalone behavioral evidence). The real-socket authenticated positive control and
  pin/date, finite-event and certificate-shape tests subsequently pass.
- `timeout-classification-red.log` proves a false event four seconds after GETINFO was missed
  before allowing the full CP call deadline; `timeout-classification-green.log` closes it.
- `identity-shape-red.log` and `event-probe-green.log` bind the disposable test identity to
  wire-auth §2.2 rather than relying only on successful key authentication.
- `python3 -B -m unittest discover -s tests/live-e2e/local-topology -p 'test_*.py'` passes
  all 48 tests before the Docker-reader regression (`focused-green.log`), including the Go subscriber's actual TLS/Unix socket.

The first fresh Local attempt (`live-local-1.log`) failed because the emulated guest's
IPv6 default route had no usable source address. It is not a live PASS. The disposable
VM's external interface IPv6 was subsequently disabled; IPv6 loopback stays enabled.
A fresh run must exercise and report the unsupported-routed-IPv6 refusal branch.
Historical T165 evidence is not used as proof of the new observation path.

The second fresh run (`live-local-2.log`) passed the Tor caller matrix, IPv4 packet
controls, IPv6 refusal/loopback controls, individual/combined owner-rule loss, DP restart
and supported re-init recovery. It then stopped at a separate stale receipt-journal
assertion in `run.py`'s confinement-fault check: Docker 29 rejects log reads when its
logging driver is `none`. This run is not a complete Local or observer PASS.

Within the existing scope, the observer archive check now accepts only Docker's exact
static disabled-reader denial with empty stdout, after inspection verifies `logging=none`
and no archive path. Other read errors and any output still fail. Its behavioral
red/green pair is `docker-reader-{red,green}.log`.

The authorized `run.py`/`test_run.py` correction preserves exit status, absent admission
and recovery checks without reading a forbidden journal. `scope-{red,green}.log` records
the original/proposed comparison; `scope-applied-red.log` repeats the behavioral failure
with the new tests installed before changing `run.py`. No acceptance guarantee is waived.

The expanded candidate passes all 51 focused tests (`focused-green-3.log`) and the
repository gate (`verify-3.log`: 27 PASS, 2 opt-in SKIP, 0 FAIL). Live attempt three
(`live-local-3.log`) also passes all three confinement-fault refusal/recovery checks,
then times out while compiling the new observer probe under QEMU TCG. The observer
matrix had not started; this is not a complete live PASS. Warming the guest Go build
cache changes no source or assertion and leaves the harness's 120-second bound intact.

Fresh full Local attempt four passed (`live-local-4.log`, exit 0), with evidence in
`target/runs/T174/live-attempts/T163-20260922-214833/`. Environment: disposable Ubuntu
24.04 QEMU TCG guest, kernel `6.8.0-139-generic`, Docker `29.1.3`, Compose `2.40.3`,
Go `1.26.3`. Routed IPv6 is unavailable; IPv6 refusal and loopback resolver controls
passed, not routed-IPv6 forwarding. The real Tor caller/restart matrix, owner-rule
loss and re-init, and all confinement-fault refusal/recovery controls passed.

The new observer checks passed all eight non-reconnecting CP event windows, including
duplicate suppression, malformed/timeout silence, and observer-down/recovery. Actual
CP-namespace auth/input refusal, Tor socket recreation, observer restart, disabled
health/log capture and raw-marker state scans passed. CP delivered the disposable
verifier on attempt one; with CP stopped, authenticated current readiness was READY,
DP authentication succeeded and Tor returned destination HTTP bytes. No credential,
response bytes or raw lifecycle/detail/timestamp stream is retained. Cleanup succeeded.

Tested source: baseline `6155c94ad69e4da054f54da38a8fc8a8b28000b6` plus this candidate's
harness overlays. SHA-256 values, checked against the local review candidate:

| Artifact | SHA-256 |
|---|---|
| `observer.py` | `30baa4c55cde6b04cf4769ecd3a37754cd949ae8fc35d92bbf1d54ed53d688ef` |
| `observer_probe.go` | `498d42dd3ac19b5ac58fac456eb07e445a49997c271993e579c83785811cfc45` |
| `run.py` | `af31d4898fe6f7d70e4e280fba4365e4fc78be7266ada7109e81219ff8c21c6e` |
| CP image | `f35115fbd9329592283c7e81a942715128a4c98d01308f55977cb770a9b65a93` |
| DP image | `af40582608b005a971e3faffd8116ccede37dd27e567641e528203f0c7cd8104` |
| Tor image | `8c28a2ca69a53ccf65e12e897b4270ea2f7ec25ad97d964da9dec561beb33581` |
| Observer image | `e637439e59bdd30c140c4c0a4150f257e32bc896f35ef65211d37acf997268ec` |
| Observer source label | `e9b42a6ba6abd7cb90245d87a27ebea12babdbd3ef6385e02826ca296ea2c756` |

Image IDs use Docker's `sha256:` prefix. The live identity JSON and finite scenario
summaries are preserved with the evidence. Any source/image change invalidates the
affected result; these checks establish Local behavior, not anonymity or continuous
event monitoring between windows. Independent reviews are still required before done.

Round-one reviews agreed that the test certificate omitted wire-auth §2.2's required
DP URI SAN (Astra: REWORK/Major; GLM: APPROVE/Minor). The finding is fixed, not accepted:
`uri-san-red.log` records the newly asserted exact single URI failing before the fix;
`uri-san-green.log` records all 51 focused tests passing with
`spiffe://stargate.local/dp`. Native verdicts/manifest are preserved under
`target/runs/T174/review-round-1/`. The probe change invalidates attempt four's observer
evidence; its unchanged `run.py` packet/caller/confinement evidence remains applicable.
The complete `observer.validate` sequence was refreshed after a fresh real operator
init, including current readiness, all event windows, recovery, and CP-down routed bytes.
The first refresh (`live-observer-r2-attempt1.log`) failed closed in the initial event
window when its subscriber closed before the final assertion. No raw stream or error
detail was retained, so the exact closure cause is not claimed; GLM had separately
identified limited timing headroom on slow hosts. Cleanup succeeded. An explicitly
recorded repeat uses identical sources, bounds and assertions, without an internal
retry or converting this failure into a pass.

The unchanged repeat passed and cleaned up (`live-observer-r2-attempt2.log`, exit 0;
`target/runs/T174/live-attempts/T174-r2-20260922-224519/`). All eight event windows,
auth/input refusals, socket/restart recovery, silent capture/state scans, and CP-down
authenticated Tor bytes passed; verifier reload succeeded on attempt one. The full
observer refresh runner is preserved with the evidence. No raw event stream was saved.
This pass does not erase the first refresh's failure or establish absence of timing
sensitivity under emulation; any early closure still fails loudly, without reconnecting.

The corrected `observer_probe.go` SHA-256 is
`7b63e9e1779296be5216fc728c02afbb8159c64b51f9a642039ecfa469ac1a32`;
`observer.py`, `run.py`, baseline HEAD and observer image/source label remain as above.
The refreshed CP/DP/Tor Docker image IDs are respectively:

- `sha256:43aa69c4fb1d18b8202b58871dbb5753f878d56ed961163163df82b647a94dbc`
- `sha256:1f6cfe7704e4e0fc8019f868f4f3a1776db1c17312779f313aec340cb0348caf`
- `sha256:a250b28bd24febc8012515c48546624bab796d0fbac35973ccb78518a690f515`

`image-comparison.json` confirms identical ordered RootFS layers, OS and architecture;
the only Config difference is `com.docker.compose.project` naming the fresh project.
Thus no executable/runtime setting change affects attempt four's topology evidence.
Both successful runs' identities are retained separately, and the refreshed harness
hashes were checked against the local round-two candidate. Production sources remain
unchanged; the SAN repair and its tests are the only implementation rework.
