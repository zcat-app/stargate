---
id: T202
title: "Add a scoped host-direct live runner and fresh VM overlays"
status: deferred
created: 2026-10-05
last_updated: 2026-10-16
source: "Post-T155 preparation; exact v2 approved for filing and execution on 2026-10-05"
phase: "Foundation test infrastructure"
story: "-"
blocked_by:
  - "T155"
  - "T210"
  - "T211"
  - "T212"
  - "T220"
deferred_reason: blocked-on-new-ticket
deferred_on: T212
parallel: false
files_budget: 30
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/live-e2e/README.md
  - tests/live-e2e/local-topology/README.md
  - specs/001-tor-route/contracts/foundation-boundaries.md
  - specs/001-tor-route/contracts/wire-auth.md
  - THREAT-MODEL.md
decision_refs:
  - "2026-10-03 host-direct direction preserved in HANDOFF-post-T155.md; exact text and cadence reserved"
  - '2026-10-05: maintainer replied "so approved i guess" to the exact revised T202 text/cadence and filing/execution request; T202 only'
  - "Approved draft SHA256 6291e3b94e0647f4662556b6efc2444b5b9740924be729e23736562105dc59f8; decision brief SHA256 9916a03c4432ffc4266f20f5437e7799d9c33278d5f5df4f093fead3289cd87d"
  - "Fresh native Claude Code Fable 5.1 high final advisory preparation evaluation: READY, no must-fix; not the implementation review gate"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T202: Add a scoped host-direct live runner and fresh VM overlays

## Binding October16 qualification alignment

Retain every original wider selection, wire/reload/recovery/TLS/real-hour/partition and host-
breaking scenario, control, deadline, rehearsal and evidence requirement below. The native
Local A2/A7 matrix belongs to T220 and does not complete these wider rows. T212 full canonical
cadence remains a prerequisite; T215 supplies maintained producer ownership, not stop proof.

For any host-direct selection sharing native runtime/policy, consume the prepared artifact and
shared admission/intent transport from the qualification contract/design. Supersede only the
old allowance to rebuild/rebind :local tags inside that runtime window; source-install/rebuild
coverage remains separately measured by the build-capable cadence/installation path. Preserve
baseline/shared bindings, unresolved request blocking and original candidate/source identity.
Before replay, record a row-by-row command/child/venue/artifact/owner map for every original
selection and identify whether it is native-artifact or build/source cadence evidence. Unknown
or host-breaking selections retain their existing stricter refusal/guest boundary.

The T126/device/profile/site selections must meet current SC-002: same reachable target,
full-partition identity/stream/circuit binding and credential-fusion discriminator. Keep the
100-label/95-circuit corpus only as ancillary sidecar evidence. A failed same-partition sharing
calibration makes that observation inconclusive/non-PASS, not proof the product guarantees one
circuit per partition. Preserve completed historical measurements with their actual claim.

The historical guest overlay authority below is not selection of a new VM for convenience. Use
an actual qualified authorized venue; any necessary guest must retain backing/boot identity,
external stop proof and original disks/evidence. Do not invent guest qualification from a cold
compile timeout or call a T220 rescue drill all-scenario completion. Original wider caps and
current tests remain; no source/native resumption or review-counter reset follows this edit.

## Context

T155 is done at `d4c1755`. Focused live tests currently pay QEMU TCG overhead even when their
effects can be scoped to disposable test resources. Add a host-direct runner for those selections
and fresh VM overlays for the rest. Keep ordinary contract tests, Docker cadence and the existing
host-browser tier on their current paths. The recorded 2.5-hour T155 pass stays VM evidence;
host-direct does not eliminate Tor latency or the real UTC-hour publication wait.

The earlier 50-path proposal expanded into general test-lifecycle control and moved existing
Docker tests behind a guest guard. The requested Fable consultation identified that unnecessary
scope and its CI conflict. This revision instead wraps selected live work. Shared development
`:local` build tags remain normal build outputs, not resources that must be absent. No separate
image archival/deletion operation is required. This does not authorize replacing a real deployment.

`run.py` currently combines ordinary topology/observer checks with owner-loss/re-init and a
whole-table firewall restore. `t155_stack.py` has fixed backup paths and invokes a global kprobe
through `connect_refusal.py`. Their live entrypoints need selection and lifecycle changes before
host-direct execution. CONNECT-refusal remains VM-only in this proposal; no new tracing permission
is inferred from the consultation. No T202 implementation or new host-safety measurement is claimed.

## Analysis

- **Must hold:** the selected live run cannot overwrite or remove a foreign deployment, profile,
  firewall rule, project or state file. Host-breaking phases cannot execute on this host through
  the new runner or the changed live entrypoints. Missing checks, lost controls and cleanup failure
  cannot become PASS. Evidence records its actual candidate, environment and selected checks.
- **Existing gates:** topology/observer selftests, the T155 mandatory-completion regression,
  wire-row decision tests and ordinary verify. None proves the new runner's admission or cleanup.
- **Residue:** transitive child effects, fixed-project collisions, partial setup and interruption,
  actual kernel confinement, changed environment, and overlay/backing identity. Acceptance below
  requires tests and live evidence. Same-user/root actors and non-cooperating concurrent build jobs
  are not contained by a local lock; host-direct requires an exclusively scheduled test window.
- **Constitution Check:** I/II runtime behavior stays unchanged. III/V require scoped synthetic
  probes and honest observation boundaries. IV/VI retain input pins and record deployed immutable
  image IDs. VII requires red-before-green behavior tests without reducing ordinary coverage.
  VIII retains the native reviewer pair and cumulative/release obligations. Runtime compliance is
  pending evidence, not established by this draft.

## Acceptance

1. **Bound the live tier.** Add a runner and explicit scenario manifest under `tests/live-e2e/`.
   Each selection records its command, child selections, resources, `host-safe` or `host-breaking`
   tier, and evidence purpose. Unknown or undeclared live selections default to host-breaking and
   refuse host-direct dispatch. Mixed selections inherit the strictest child's execution limit.
   A focused result names its subset and never reports its full parent suite complete.

   | Selection | Proposed execution boundary |
   |---|---|
   | Clean-volume production init; ordinary topology/observer/CP-down bytes in `run.py` | Host-safe through the runner after qualification |
   | `TestTorSocketCallerMatrix`, called by the topology selection | Host-safe child; include its fixed project, builds and temporary helpers in the parent's preflight and cleanup |
   | Per-container Landlock/seccomp-unavailable fault cases in `run.py` | Host-safe: owned DP container overrides only; preserve refusal and restored positive controls |
   | Wire R1–R9; reload/revocation/recovery checks; focused TLS resumption and real-hour publication in `t155_stack.py` | Host-safe selected phases with their prerequisite setup and mandatory-check lists |
   | T126 profile/device/site isolation and T182 onion-load/different-destination selections | Host-safe through a runner adapter around their unchanged Go tests and synthetic provisioning |
   | Owner-jump loss and re-init fault cases; parser.conf ABI changes; masked feature files; mutants changing host-global policy | VM-only; retain the maintainer's conservative classification even when a particular owner-rule fault is scoped |
   | CONNECT-refusal and any selection containing it; full default `run.py` and `t155_stack.py` | VM-only; CONNECT probe definitions are host-global despite the separate trace buffer |
   | Standalone `apparmor_signals.py`, `legacy_timeout_probe.py`, and `cp_listener.py` package matrix | VM-only in this change; they receive a guest guard, not a new host adapter; existing CP calibration/PID helpers remain available |
   | Existing browser probes | Existing host tier unchanged; record separately, reserve their fixture ports by exclusive scheduling |

   Inventory other existing live/release selections with the same fail-closed runner default;
   this ticket does not add them to the host-supported selection set. The ordinary gate and Docker
   cadence are a separate existing test layer: `control_mount_test.sh`, `operational_logs_test.sh`,
   `init_docker_test.sh`, `init_fixture_cleanup_test.sh`, the T162 Docker tier and Docker-tagged Go
   suites retain their assertions, opt-ins, direct commands and CI execution. Do not add guest-only
   SKIPs or active-run tokens to them. Listing those paths does not claim new safety qualification.

2. **Host admission and resource ownership.** Require root, an exclusively scheduled test window
   and one runner lock held through teardown. Reject a remote/rootless or ambiguously matched Docker
   daemon; occupied 8881 or another required fixture port; any pre-existing selected project,
   container, volume or network; any non-owned Stargate deployment, including stopped containers;
   existing `stargate-dp` profile in any mode; existing `STARGATE_DP_OUT` chains/jumps in either IP
   family; conflicting fixture UIDs; and unavailable/unsupported prerequisites. Use actual daemon,
   container/image and resource identities, not a test-looking name alone. Inspection ambiguity
   refuses admission. Coordinate no ordinary verify, Docker build or browser run concurrently;
   unexpected foreign changes invalidate the live attempt rather than being silently cleaned up.

   Initial qualification is scoped to the inspected host: Ubuntu 24.04.5, Linux
   `6.8.0-146-generic`, amd64, Docker server 29.1.3, Compose 5.1.4. These are inventory values,
   not prior live qualification. Qualification uses all guards; ordinary host dispatch requires
   the resulting successful measured record. Changes outside that qualified tuple require explicit
   requalification; do not infer support from a kernel-series or Docker-major match.

   Use unchanged production init/profile/rules. Check AppArmor af_unix, Landlock and seccomp
   prerequisites without changing parser policy, kernel features, sysctls or daemon configuration.
   Qualification must bind the actual DP process to its local container and read its enforcing
   label from `/proc/<pid>/attr/apparmor/current`, falling back to `attr/current`. Separately,
   a helper under the same loaded `stargate-dp` profile in the host network namespace must be denied
   an abstract-socket connection that an unconfined byte-exchange control completes. This is a
   profile behavior control, not a claim that the production DP attempts an abstract connection.
   A loaded profile or
   Docker's profile field alone is not proof. Retain that actual-process check at runner-controlled
   startup/recovery checkpoints; record the observed instances and limits, not a continuous
   enforcement claim over unchanged Go tests. For Go-adapter selections, a concurrent runner
   observer samples the actual test DP's identity and enforcing label while it runs; no sample
   means no qualification. Record sampling gaps and process identities without claiming continuous
   enforcement. T209's production checks and release blockers remain.

3. **Scoped lifecycle and cleanup.** Record resources created by the run, including transitive
   socket-matrix/helper resources. Fixed test-project names may be used sequentially only after
   their absence is proved. Use fresh synthetic keys/tokens/state; relocate `/root/t155-*` backups
   to a run-owned directory. Production init may create the unchanged owner chain/jumps and profile
   only after admission proves them absent. For the Go-test adapter, the runner installs that same
   profile and owner rule set through production init on a run-owned bootstrap project, or identical
   installation commands, and provisions the selected project's synthetic keys and token. The same
   absence checks and owned teardown apply; the legacy guest wrapper's pre-emptive project deletion
   is not permitted on the host.

   Permitted additional effects are Docker-managed interfaces, routes and firewall entries
   attributable to owned test networks, transient loopback fixtures, helper processes under the
   fixture UIDs, filter-limited packet capture on `any`/egress/`lo`, and synthetic probe packets to
   documentation-only addresses that leave through the host's real egress interface. Raw captures
   include the host source address and remain local. These are existing F1 test effects, not a
   permission for DP/CP public-network egress.

   Run host-direct work from a run-owned export of the staged candidate, with its content manifest
   recorded and checked against the working candidate before measurement. Rebuild helper binaries
   from that export; never reuse `target/` binaries from the developer checkout. Give the export its
   own local metadata needed by existing harness git queries; root execution must not write to the
   source checkout's index or leave root-owned build artifacts there.

   The canonical build may rebuild its existing development `stargate/*:local` tags during this
   exclusive window. Refuse foreign deployments by inspecting containers/projects and their image
   identities; absence of a mutable tag is not required. Record immutable IDs of the images
   actually executed and their source/package identity. A tag name is never candidate evidence.
   Do not prune/delete images, archive or remove existing tags as a preflight workaround, or
   silently restore old tags. Build outputs/caches and evidence are explicitly retained artifacts.

   Install cleanup before effects. On success, partial setup, failed child, timeout, INT or TERM,
   stop owned processes/captures and remove only owned test containers, volumes, networks, exact
   owner jumps/chains, profile and temporary fixtures. Never restore or flush the whole host
   firewall. Preserve unrelated state, including changes made after the initial snapshot. Inspect
   residue independently; exit zero requires all selected mandatory checks and cleanup to pass.
   Retain both original and cleanup failures. SIGKILL/host loss cannot guarantee teardown: retain
   durable ownership records and refuse the next run with a residue report. Ambiguous ownership
   never authorizes deletion. Retained VM disks and scratch/evidence remain subject to the existing
   maintainer-deletion rule; automatic owned-fixture teardown is the runner behavior being reviewed.

4. **Selection and guest guards.** Make `run.py` and `t155_stack.py` phase-selectable while retaining
   every assertion, deadline, positive control and default full guest sequence. Focused phases
   include their real prerequisites and mandatory completion accounting. Defaults stay VM-only.
   Guard the privileged drivers before setup: `run.run_live`, the `t155_stack` entry,
   `connect_refusal.run`, `apparmor_signals.main`, `legacy_timeout_probe.main`, and
   `cp_listener.package_matrix`. A VM-only phase requires a provisioned guest
   marker; host-safe phases require the scoped runner's admission context or a valid guest context.
   Neither the old disposable-host environment opt-in nor importing a function waives this check.
   Place host-breaking checks at the actual fault/trace operation as well as dispatch where needed.
   `run.py --probe` child mode, `cp_listener.calibrate`/`--calibrate`/`--pid`, and pure decision
   helpers remain available without privileged admission, including their existing ordinary-gate
   tests. Calibration already creates transient wildcard listeners; this change adds none. Those
   helper modes do not authorize a privileged live driver or constitute full live-suite evidence.
   Stubbed privileged-driver selftests use explicit test fixtures for admission. No generic `force`
   switch or weakening of existing selftest assertions.

   The marker lives in `/run`, binds the current guest boot and run, and is written by per-boot
   provisioning after checking the intended disposable guest/overlay identity. Do not rely on
   cloud-init `runcmd` repeating from the saved base. It guards accidental execution, not malicious
   root. Changed VM-only entrypoints must refuse on this host before effects. Existing ordinary
   tests and unmodified Go entrypoints gain no marker requirement; direct execution of them is not
   certified host-direct evidence from the new runner.

   Provision a new qcow2 overlay over the recorded `guest-t182.qcow2`, with explicit formats,
   resolved backing path and backing-chain identity. Refuse reuse or missing/changed backing
   state. The base is an explicit read-only input at
   `/home/claudia/stargate/target/t165-vm/guest-t182.qcow2`; exact-ticket approval includes read-only
   access to that asset, not other changes in the preserved checkout. Write overlays under the
   active worktree's ignored `target/`. Never boot or modify the base. Each measurement boots its
   own fresh overlay and provisions
   clean test state; it is not claimed to be a newly installed OS. Record candidate/package transfer,
   tool versions and base hash before/after. Stop owned guests; retain disks/evidence and report
   leftovers. An overlay alone does not generate a guest marker on the development host.

5. **Tests first, preserving existing coverage.** Add runner/provisioning regressions to the
   existing topology contract gate; that gate currently discovers only `local-topology/test_*.py`,
   so explicitly wire the new root-level tests. Capture meaningful RED then identical-command GREEN
   with `scripts/test-first-evidence.py`: a regression against the current live entrypoints must
   demonstrate an unguarded effect or unsafe cleanup using substituted privileged tools, not fail
   merely because a new runner file or tool is missing.

   Cover mixed/unknown selection, direct and nested forbidden operations, environment-only and
   stale-boot guest claims, collisions/inspection failure, unsupported environment, lock contention,
   partial setup per resource class, signal/timeout/child failure, foreign-resource preservation,
   cleanup failure and incomplete-result rejection. Successful controls prove the guarded path can
   run. Overlay tests exercise backing identity/reuse/marker refusal. Update suite selftests for
   selection without weakening their completion/capture invariants. Put the `apparmor_signals`
   host-refusal regression in the new `test_runner.py`; update the existing legacy-timeout selftest
   for explicit stubbed admission. The normal verify and Docker
   cadence commands must still execute their prior coverage without guest provisioning, including
   the four shell fixtures and T162's Docker tier; no new SKIP is accepted for those obligations.

6. **Live qualification and evidence.** Before host mutations, pass hermetic guards, rehearse
   partial-setup/interruption cleanup on real owned resources in a fresh guest, and inspect the
   actual ownership/cleanup preflight. Then run every newly admitted host selection sequentially:
   ordinary F1 topology/observer/CP-down checks and container-scoped faults, the socket-matrix child,
   F2 wire/reload/recovery/resumption/real-hour selections, and T126/T182 through their new adapter.
   Validate actual confinement and normal/controlled-interruption cleanup on this host. Any need
   for additional host-global mutation or unreliable teardown stops for the maintainer; do not
   quietly drop a promised selection. Mandatory SKIPs, lost controls and incomplete runs block done.

   Re-run complete F1/F2 on a fresh overlay because their harnesses change, plus real execution
   of each newly guest-guarded standalone entrypoint and its host-refusal regression. Actual ordinary
   and Docker-cadence coverage must remain evidenced. Unchanged F4/F7/browser mechanisms may carry
   prior evidence only through the existing explicit reviewed comparison of all affected source,
   image, harness, provisioning and environment inputs (D-live-6); otherwise renew it. New host
   execution paths always require their own measurements, never carried guest results.

   Save sanitized `specs/001-tor-route/evidence/T202-live-results.json`, with actual host/guest
   identities and versions, source/packages/deployed image IDs, commands, selected/required checks,
   attempt counts and failures, cleanup outcomes and observation limits. Host results say
   **development host, not clean-host**. Never relabel T155/T208 results. Keep raw captures and
   synthetic secrets local. Report elapsed times honestly without promising a fixed speedup.
   Driver verification and the normal native reviewer pair remain required before completion.

7. **Cadence and documentation.** Focused per-ticket evidence may use qualified host-safe live
   selections. Host-breaking tests and foundation/milestone/release stack closure remain on fresh
   disposable VMs. Ordinary contract/Docker cadence, existing host-browser checks and physical-NIC
   obligations retain their current boundaries. Update the canonical tracker, local suite README,
   feature plan Constitution Check and THREAT-MODEL in the same ticket. Reconcile the tracker and
   local README's current blanket disposable-host wording. Unmodified Go headers describe direct
   invocation, which remains unsupported as qualified development-host evidence; the runner adapter
   is the newly supported path. Fix F3's stale
   `strace-traced` description to match its kprobe. Preserve historical records and release blockers.
   T209 overlaps the CONNECT harness, its selftest, local README and threat model; whichever ticket
   lands second must re-ground those paths. Use the exact approved paragraphs below; return any materially different final wording for
   approval. After reviewed delivery, update the unversioned memory
   `/home/claudia/.claude/projects/-home-claudia-stargate/memory/live-vm-procedure.md` to point to
   the versioned runner/procedure. Memory is not a substitute for the contract or evidence.

## Out-of-scope

Production DP/CP/extension code, shipped Compose/security policy, installer behavior and dependency
pins; Constitution or SECURITY-DECISIONS changes; ordinary Go/shell test guards or cadence changes;
new supported platforms; a host-global kprobe permission; T200/T201/T209 implementation. Stop if
these are needed. Changes to existing tests are limited to the named live entrypoints, their
selftests, wiring new runner regressions and fixing directly affected documentation. No assertions,
production deadlines, mandatory capture controls or real-hour waits may be weakened.

## Approved exact documentation wording

**D-live-8 (focused development-host evidence).** Qualified host-safe live selections may provide
focused per-ticket evidence through T202's scoped runner, with ownership, environment and cleanup
checks. Their results are development-host evidence, not clean-host evidence. Host-breaking and
undeclared live selections remain VM-only, including the CONNECT-refusal probe and selections that
invoke its host-global kprobe. Foundation, milestone and release stack closure stays on fresh
disposable VMs; a new qcow2 overlay over the recorded unchanged base is permitted with fresh test
state and per-boot provisioning. Ordinary contract tests, Docker cadence and the existing
host-browser tier retain their current execution paths. Physical-NIC and other release obligations
retain their own observation boundaries. Missing checks, failed cleanup and incomplete runs are
not PASS; earlier guest results are not relabelled as host-direct evidence.

**THREAT-MODEL §3.1 addition.** T202's opt-in live tier distinguishes focused development-host
evidence from disposable-VM stack closure. Host-direct live evidence requires the scoped runner's
qualified selections and checks; ordinary contract tests, Docker cadence and existing browser-host
checks remain separate. Host-direct runs temporarily use the host kernel, exclusively reserved
test-owned AppArmor profile and owner rules, and Docker-managed resources attributable to test
networks. Existing F1 probes also use transient loopback fixtures, helper processes under fixture
UIDs, filter-limited packet capture on `any`/egress/`lo`, and synthetic packets to documentation-only
addresses through the host's real egress interface. Raw captures include the host source address
and remain local. These test effects do not authorize DP/CP public-network egress. Runs require an
exclusively scheduled test window and a trusted host administrator and
Docker daemon. Local ownership records and the guest marker guard accidental misuse, not malicious
host root or arbitrary concurrent external jobs. Results apply only to the recorded candidate,
environment, selected checks and observation limits. T209's production confinement obligations
remain open. This test tier does not expand production support or establish physical-NIC,
routed-IPv6, LAN/VPS or hypervisor guarantees.

## Implementation inventory and budget

27 identified paths including the post-review scorecard, budget 30. No requirement to touch an unaffected path:

| Count | Paths |
|---|---|
| 4 | Ticket, STATUS, T202 tests-first JSON, T202 live-results JSON |
| 5 | New `tests/live-e2e/runner.py`, `tiers.json`, `test_runner.py`, `provision_guest.py`, `test_provision_guest.py` |
| 11 | Under `tests/live-e2e/local-topology/`: `run.py`, `test_run.py`, `t155_stack.py`, `test_t155_stack.py`, `connect_refusal.py`, `test_connect_refusal.py`, `apparmor_signals.py`, `legacy_timeout_probe.py`, `test_legacy_timeout_probe.py`, `cp_listener.py`, `test_cp_listener.py` |
| 2 | `tests/contract/compose/topology_capture_test.sh`; `tests/contract/workflow/live_e2e_tracker_test.sh` |
| 5 | Canonical tracker, local-topology README, THREAT-MODEL, feature plan; reviewer scorecard in the normal done follow-up, never the implementation review candidate |

The five extra paths beyond the consultation's 22-path estimate are actual test-gate wiring,
the CP-listener guest guard/selftest, the affected legacy-timeout selftest and the post-review
scorecard. There is no new host CP-listener adapter. The existing
budget pre-grant applies to acceptance-local tests and own-change orphans, with every added path
recorded. Out-of-scope work or more than twice the original budget still stops. Raw evidence,
scratch and the explicitly named post-delivery memory update are outside the tracked budget.

## Filing state

Filed after the maintainer replied "so approved i guess" to the explicit request to approve the
revised exact T202 text and cadence and authorize filing and running T202 only. The approved draft
and decision brief identities are recorded in `decision_refs`. The final exact preparation packet
received a fresh native Claude Code Fable 5.1 high advisory evaluation: READY, no must-fix.
That preparation is not implementation review or live qualification. Evidence remains under
`.scratch/tmp/T202/evaluation-record-v2.md` and `claude-fable51-v2-final/`.

Filed between tickets with no ticket in flight. T200/T201 retain their reserved decisions. The
previous 50-path and image-tag proposals are superseded suggestions. Acceptance, scope, cadence
and the exact documentation paragraphs are preserved from the approved draft.

## Verification prerequisite deferral

The maintainer authorized implementation of the reviewed repair plan after guest15's failed
aggregate cadence. The final plan is retained at
`.scratch/tmp/T202/repair-plan-2026-10-07/plan-final.md`, SHA256
`cd5fc2e88e255bab31bfe34d34cc5e01f8200244d29d91810f588d0d190b637c`.
Its individual F1/F2 and nine cleanup rehearsals remain partial candidate10
results; later cadence/standalones and host qualification were not completed. Ordinary helper,
fixture and aggregate/CI repairs are outside this ticket's explicitly approved scope.
T210 -> T211 -> T212 owns that work; all are blockers and T212 is the scalar final prerequisite.
This administrative filing claims no T202 implementation approval, live GREEN or completion.

The exact25-path candidate10 staged implementation, full793-file source/index/mode manifest,
binary patches, authentic baseline bundle and original tests-first JSON were preserved in owned
ignored storage and exact rollback/replay was proven before removing the owned changes.
Retained disks, evidence, archives, current cache, backing inputs and unrelated worktrees remain.

After prerequisites deliver, manually record blocker resolution, set pending and clear resolved
defer fields; append a `reopens:` entry recording the date, resolved blockers T210 through T212
and the guest15 deferral trigger. Run the documented reset to archive review/aborted-attempt history before the
reviewed ordinary-GREEN metadata-only reopen commit, with regenerated STATUS. START then sees
clean tracked pending metadata and records its new baseline. Restore/stage the preserved original
T202 tests-first JSON before replaying/staging the original test-only RED patch and recording a
fresh meaningful substituted-effects RED on that baseline. Keep earlier baseline/red/green in
superseded; do not overwrite the newly captured JSON with the preserved copy. Only then restore
and reconcile implementation, rerun identical GREEN, re-ground changed inputs/path budget and
renew candidate-bound live qualification and native GLM/Astra implementation review. Reset does
not erase stale green-code state; unchanged driver hashes must reject it rather than manually
claiming freshness. Existing constants, assertions, coverage and live acceptance remain binding.
