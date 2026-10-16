---
id: T220
title: "Qualify the complete artifact-native Local A2 and A7 matrix"
status: deferred
created: 2026-10-11
last_updated: 2026-10-16
source: "T209 Acceptance 7 refinement, 2026-10-11 R3 reassessment and consolidated R4 decision"
phase: "Foundation audit remediation"
story: ''
blocked_by:
  - "T224"
  - "T222"
  - "T223"
  - "T209"
  - "T227"
parallel: false
files_budget: 12
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned and Auditable Dependencies"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Independent Review"
complexity: high
risk: high
round_cap: 3
decomposed_from: T209
spec_refs:
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/design/qualification.md"
decision_refs:
  - "2026-10-11 T209 R4 consolidated decision: one infrastructure prerequisite owns private names, finite effects, receipts, result accounting and cleanup; T209 keeps full A7 live acceptance"
  - "SECURITY-DECISIONS 2026-09-20 (T162): trusted host administrator and Docker daemon; direct Compose starts unsupported"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
deferred_on: T223
deferred_reason: blocked-on-new-ticket
files_scope:
  - "specs/001-tor-route/tickets/T220-own-native-local-qualification-effects-and-cleanup.md"
  - "specs/001-tor-route/evidence/T220-native-results.json"
  - "specs/001-tor-route/evidence/T220-native-qualification.md"
  - "specs/001-tor-route/STATUS.md"
  - "specs/001-tor-route/tasks.md"
  - "THREAT-MODEL.md"
  - "specs/001-tor-route/live-e2e/README.md"
  - "tests/live-e2e/local-topology/README.md"
---

# T220: Qualify the complete artifact-native Local A2 and A7 matrix

## Context and acceptance migration

This is the full native qualification owner after T223 source integration, T209 source hardening
and T227 platform capability. It owns every original T209 A7 native clause and the separate
A2-live unconfined-DP Docker leg. The old source-only checkpoint and in-window build/rebuild/join
mechanism are superseded; their failed source and native evidence is preserved, never passed.
T223/T225/T226 own corrective source. No additional per-finding live ticket is created.

## Analysis

- Must hold: exact approved source/artifacts and actual runtime identity, every required named
  scenario/control, bounded owned effects, safe settlement and exact baseline restoration.
- Gated: actual native source-plus-results/receipt review; no model or recorder supplies live facts.
- Residue: trusted host/root/daemon and disclosed helper authority remain; a lock is cooperative.

## Acceptance

1. Validate the actual T227 venue/backend/separation/loading/completion and storage enforcement/
   durability evidence against this candidate's tools/platform. Before admission, match actual
   state/evidence roots, mount/device/filesystem/options, writer access and the complete producer/
   temp byte/file/inode envelope; drift, unsupported durability or limits outside the qualified
   envelope refuse. A representative fixture does not prove actual consumer ordering. Obtain the existing separate maintainer residual-helper and first
   protected-policy-mutation authority before such operations. Rootful local-kernel, no-remapping
   constraints remain; this ticket does not select T209's reserved broader support wording.
2. Preserve original A7 preflight: same measured kernel for daemon/helpers/procfs/securityfs/netns,
   UID mappings/features/pins/bind paths, common host-policy maintenance lock through cleanup,
   exclusive scheduling, fixed UID/port/project/policy/profile/chain collision refusal and exact
   baseline identities. Refuse stale/ambiguous drift; never overwrite foreign state to repair it.
3. Validate/import the complete T226 closure under T225/T223 shared pre-effect admission, then
   admit no import/build/pull/compile/retrieval during runtime. Exercise actual init and production
   topology with its reviewed build-free transform, helper/probe/A2 artifacts, first/re-init and
   recovery paths. Bind each image/container generation to expected source/OCI/config/payload;
   shared :local bindings and foreign baseline resources remain exact. Source-install/rebuild
   coverage remains with T202/T212/T215, not falsely certified by this artifact-only run.
4. Execute the full original run.py native Local matrix, production kernel-label/observer/packet
   and fault controls, Tor caller matrix and complete STARGATE_TEST_TAGS=docker T162 tier.
   Separately execute the STARGATE_TEST_TAGS=t209-docker A2 real-image unconfined-DP refusal leg.
   Consume actual named Go run/unique terminal PASS/package/command outcomes and full T162 marker.
   Mandatory SKIP, missing, duplicate, truncated or absent receipts fail; intent is not execution.
5. Demonstrate normal and safely authorized fault lifecycle: partial init, handled signals,
   timeout, late/lost response, peer/phase/identity substitution, foreign replacement, monitor/
   capture loss, cleanup failure and policy drift. T227's acceptable quarantine disposition is a
   prerequisite to response-loss injection; do not strand an unqualified shared host. Existing
   captures/controls/real scenario requirements are not replaced by a generic infrastructure drill.
6. Before exact policy removal, settle every relevant request/effect and stop/reap/prove absence
   of all test-capable workloads, helpers, descendants, nested projects and volume/network
   references. Retain both nested and primary enforcement until that proof; cleanup-only actor
   then removes exact owned deltas and must itself be absent. Never whole-host restore/prune.
   Unknown request/result or lost owner retains pending/necessary enforcement; no quiet inventory,
   dead client, artifact equality or generic restart oracle. Late settled publication cannot
   grant another candidate without actual original owner AND observer completion observation.
7. Record every mandatory scenario/control, all actual attempt/review counts and failures,
   original baseline and cleanup/restoration, exact source/tool/artifact/runtime identities,
   finite deadlines/resources and privacy-safe output limits in the declared sanitized results.
   Keep raw host/packet data local. Distinguish NOT RUN before effects from FAIL afterward;
   useful measurement with failed cleanup is not overall PASS. Source mocks cannot supply facts.
8. Independent exact source-plus-native-result review must approve all required rows before done.
   Source defects discovered here return to their existing source owners with retained evidence;
   do not patch source during a measurement or reset failed counts via another ticket. T218
   readiness, T034f onion/egress, T034a DNS and T077 human UX retain their separate claims.

## Out-of-scope

Implementation changes, new backend/fork, automatic recovery, shared resource deletion, VM for
convenience, broader production support, T209 A3/A4/A8/A9 decisions and T078/T079 execution.

## Execution and evidence boundary

This is a ticket reconciliation, not authorization to execute source or native work. Root authors
and independently reviews the exact implementation/experiment plan before dispatch. New code is
spec-derived tests-first through real supported consumers: preserve genuine behavioral RED before
implementation, identical GREEN afterward and affected regressions. Missing tool/import/API/build,
invalid setup and a refusal stub are not the missing safety property's RED or healthy PASS.
Retain every original candidate, verdict, actual review/episode count and NONCOMPLIANT chronology;
new child IDs do not reset parent failures. Pure document work uses consistency/adversarial review.
No automatic native/host authority, shared-tag repair, evidence deletion, VM for convenience or
T078/T079 execution follows. Apply the applicable ticket review matrix and explicit session
exceptions honestly; advisory plan approval is not the paired implementation/delivery gate.

## Historical pre-reconciliation ticket body — preserved verbatim

The body below records the superseded direction and original evidence/approvals. Active acceptance
and scope above govern new work. Historical approvals do not approve changed source or reset counts.


# T220: Own native Local qualification effects and cleanup

## Current lifecycle disposition — 2026-10-15

T220 is deferred as decomposed into T223 after the fourth failed full-source
review and the root-authored whole-model reassessment. Preserve all prior
source, review, RED/GREEN, backend and runtime evidence. The reviewed candidate
is not approved or integrated. T223 owns the source-level real-writer
ownership rebuild; T220 retains full native/backend/cleanup qualification and
all original acceptance, including strict T209 A7. This disposition does not
establish backend support or authorize Docker/native/host-policy operations.

## Context

T209 A7's native Local run must use actual init, the checked-in Compose
contract and nested Go/T162 suites without changing shared image bindings or
removing enforcement while a Docker effect or test-capable actor may survive.
R3 review found five concrete defects across image tags, cross-UID receipts,
publisher cleanup, nested resource ownership and Go result accounting. This
single infrastructure prerequisite owns allocation, transport, every effect's
lifetime and scenario-result receipts. T209 retains its original application
assertions, mandatory A2 Docker observation and complete A7 live run. T220 is
a source-only checkpoint, not native qualification or host-policy authority.

T220 starts from a clean implementation candidate based on the active feature
state, where T081 is already done. The T219 browser-measurement amendment exists
only in an isolated scratch integration copy and is not a prerequisite for
native Local resource ownership; do not import it or add its absent ticket as
a blocker here. Preserve all currently staged user changes when materializing
the candidate. Do not use the unreviewed R3 25-file patch as a wholesale
implementation.

## Analysis

- **Must hold:** ordinary Local deployment retains three `:local` image
  references; qualification's three private names remain tied to one durable
  run identity and actual built/deployed immutable IDs. Principles III/IV
  retain the Compose actor/traffic, security, build and observer contracts.
  Every external effect has pre-effect intent, an observed result or explicit
  uncertainty, exact ownership and a verified cleanup/absence oracle.
  Pre-existing containers, networks, named volumes, protected policy and the
  three shared tag bindings survive in both directions. Enforcement remains
  until all test-capable workloads and backend mutators are quiescent.
- **Gated:** tests-first command recorders through real entrypoints; static
  checked-in Compose equivalence; cross-UID and stateful fake-daemon tests;
  selected Go JSON terminal PASS and full T162 marker; focused installer,
  native launcher, observer, Compose, AppArmor and nested-suite checks; exact
  candidate Astra/high and Luna/high source reviews under the session
  exception.
- **Residue:** source mocks cannot prove Docker/BuildKit daemon-side
  cancellation or live Local behavior. The approved backend needs a controlled
  terminal/cancel contract before protected mutation. Host root, daemon and
  non-cooperative privileged writers remain trusted; a cooperative lock and
  before/after inventory cannot prove atomicity against them or every ABA
  replacement. Private names are neither host containment nor source
  provenance.

## Internal development stages

These are work steps within one ticket, not separate approval gates or done
states. Retain RED and GREEN evidence for each spec-derived falsifier and
review one integrated source candidate.

1. **Configuration transport:** issue and validate the run suffix; compare
   checked-in Compose with identical other inputs; exercise first init,
   re-init, observer, fault/recovery, Go and full T162 through command
   recorders. Direct probes consume the phase's current immutable Tor ID.
2. **Ownership ledger:** prove private 0700/0600 cross-UID atomic receipts;
   persist intent before each named/labelled effect; inventory baseline and
   refuse foreign, stopped and volume-only collisions; capture build and
   deployed generations after every build-capable invocation.
3. **Cleanup and results:** recover lost creation responses; stop/reap and
   prove absence of test-capable actors and resource references; keep deferred
   T162 profile enforcing until cleanup-only finalizer removes exact owned
   policy after global quiescence. Preserve shared tags, report private
   artifacts, require actual named Go PASS and full T162 marker.

## Naming and propagation contract

`STARGATE_LOCAL_IMAGE_SUFFIX` is unset in ordinary deployment and then
Compose renders `local`. Native qualification requires a persisted suffix at
every writer and probe; missing input fails before a build or probe. Issue
`native-` plus the first 24 lower-case hexadecimal digits of the durable run
UUID after removing hyphens: 31 characters total. Validate against
`[a-z0-9][a-z0-9_.-]*` and a 32-character maximum; refuse empty, `local`,
malformed, overlong, disagreeing process/env-file values and collisions with
foreign or baseline names before mutation. Re-init/recovery may reuse only
this run's receipted names after verifying ownership and prior generations.
The unset-only `${STARGATE_LOCAL_IMAGE_SUFFIX-local}` interpolation preserves
the ordinary default without silently treating present-empty as unset. This
is a qualification input, not an operator-facing direct-Compose promise.

| Boundary / writer | Required propagation and receipt |
|---|---|
| `compose/docker-compose.local.yml` | Only DP, CP and Tor image values vary; `pull_policy: build`, build contexts, Dockerfiles, security, mounts, networks, UIDs and observer ID stay exact. |
| `scripts/subcommands/init` and `scripts/lib/compose.sh` | First init, re-init and every installer Compose call use the validated suffix in env file and process environment. Preserve the exported `STARGATE_OBSERVER_IMAGE` refusal; its immutable ID belongs in env-file/evidence, not installer process environment. |
| `tests/live-e2e/local-topology/run.py` and `observer.py` | Main init, re-init, observer validation and every direct Compose call carry one suffix. Fault/recovery `up` without `--build` remains build-capable under `pull_policy: build`; record each generation and deployed ID. |
| `tests/contract/tor/port_exposure_test.go` and shared Go Compose runner | Use a run-derived project, explicit private env file and current verified immutable Tor ID for direct probes. Named test execution is proved separately by its JSON result. |
| `tests/contract/stargate-cli/t162_enforcement_test.sh` | Full T162 project and Compose `up` carry the suffix despite use of `local.env.example`; direct Tor probes use the phase's verified immutable ID. Full-tier completion marker remains mandatory. |

Other Docker-cadence suites are outside this native matrix. They are not
changed merely because they also call Compose. This same ticket owns helper
names/labels, effect receipts and cleanup at the shared call sites above.

## Planned file allocation

Twenty-five named paths are planned: `compose/docker-compose.local.yml`,
`scripts/subcommands/init`, `scripts/lib/compose.sh`,
`scripts/t209-native-live.sh`,
`tests/live-e2e/local-topology/native_coordinator.py`,
`tests/live-e2e/local-topology/run.py`,
`tests/live-e2e/local-topology/observer.py`,
`tests/contract/tor/port_exposure_test.go`,
`tests/contract/internal/compose/compose.go`,
`tests/contract/stargate-cli/t162_enforcement_test.sh`,
`tests/contract/compose/local_compose_test.sh`,
`tests/contract/stargate-cli/init_docker_test.sh`,
`tests/contract/stargate-cli/init_apparmor_test.sh`,
`tests/contract/stargate-cli/init_countprobe_test.sh`,
`tests/contract/stargate-cli/release_init_test.sh`,
`tests/live-e2e/local-topology/test_run.py`,
`tests/live-e2e/local-topology/test_observer.py`,
`tests/live-e2e/local-topology/test_native_coordinator.py`,
`tests/contract/stargate-cli/t209_native_launcher_test.sh`,
`tests/contract/internal/compose/compose_test.go`,
`tests/live-e2e/local-topology/native-tools.json`,
`specs/001-tor-route/evidence/T220-tests-first.json`, `THREAT-MODEL.md`,
this ticket and `specs/001-tor-route/STATUS.md`. The two T081 installer tests
are included because helper changes share init's release/count-probe path.
The four remaining budget slots are for named, spec-derived test/fixture
paths required by falsifiers; record each before use. Parent T209 application
assertions and reserved wording do not move into this infrastructure scope.

## Finite effect and call-site ledger

For every row, persist private durable intent with the exact run-derived
name before creation; record the observed ID/state after creation. On a lost
response, inspect that exact name and its run ownership label/receipt. If
identity or backend termination is uncertain, fail and retain enforcement.
Cleanup is by the named actor only after dependent work stops; destructive
calls recheck name, ID and ownership and then verify absence. `--rm` alone is
not an absence receipt. All run names are checked against physical-name and
labelled collisions before mutation, including stopped containers and
unlabelled volumes. The table is the required effect inventory, not a claim
that the current code already implements it.

| Effect; current call sites | Precondition, owner and durable intent | Lost response, cleanup and absence oracle |
|---|---|---|
| Non-root coordinator, privileged inventory helper, UID-0 worker and cleanup-only finalizer; `tests/live-e2e/local-topology/native_coordinator.py:create/run` and `run.py` native launcher | Non-root coordinator holds private 0700 run directory, ledger and run UUID; root actors have exact names/labels/IDs. Record intent before spawning each actor and descendant. | Recover by actor identity/process/container inventory. Inventory helper identity and absence are receipted, including lost create response. Worker and every test-capable descendant must terminate before finalizer removes policy; finalizer itself absent before PASS. Ambiguous child retains policy. |
| Primary Compose project and DP/CP/Tor/observer containers, network and named volumes; `scripts/subcommands/init:ensure_volumes,compose_run up`, `run.py:compose_args`, `observer.py` | T220's run-derived project/suffix, validated physical names and Compose labels; baseline project objects inventoried before init. Record each `up`, `restart`, `down` and container generation. | Inspect project labels and exact IDs after response loss. Exact owned `down`/container-volume-network removal only after workloads stop; inventory proves owned absence and baseline preservation. A removed baseline object fails. |
| Installer key/count/observer-key probes; `scripts/subcommands/init:generate_keys` (`docker run` around lines 449, 454, 547) | Digest-pinned helper, network none, exact run-derived helper names/labels and intent before create; key volume identity verified. | Recover helper by name/label/ID, stop/remove only that ID, verify no helper/container or key-volume reference survives. Never infer absence from `--rm`. |
| Installer volume-root, config-mountpoint and CP-public-key helpers; `scripts/lib/compose.sh:init_volume_root`, `init_control_config_mountpoint`, `refresh_observer_cp_pub` | Same digest-pinned helper and specific verified volumes; each invocation has its own name/intent and no network. | Recover each exact helper after interrupted create, then stop/remove/verify absence and no extra volume reference. Exact owned volume effects remain in primary-project receipt. |
| Digest-pinned keygen helper pull; `scripts/subcommands/init:supply_chain_guard` | Inventory the pinned reference and pre-existing local image presence before possible `docker pull`; record pull intent and observed immutable digest. | A lost pull response is an uncertain daemon image effect, not proof of absence. Retain/report a newly fetched pinned helper image or prove exact ownership before removal; never remove a pre-existing image or prune cache. |
| Observer image build and publisher fixture; `scripts/subcommands/init:build_observer_image`, `observer.py:validate` publisher fixture | Record tagless build intent, reviewed source hash, Buildx/backend identity and immutable output ID. Publisher gets durable exact name before create, labels/ID and verified primary-volume references. | Backend uncertainty retains policy; publisher response loss recovers exact identity. Stop/remove/verify absence on normal, failure and signal paths before volume cleanup/finalizer. A foreign replacement is never swept. |
| Private DP/CP/Tor builds and images; `scripts/subcommands/init:compose_up`, `run.py` fault/recovery `up`, Go Tor caller `up -d --build`, T162 Tor `up -d --build` | T220 names; each `up` is build-capable under `pull_policy: build`. Persist phase/generation, CLI and backend receipt, image IDs and actual deployed container image IDs. Preexisting shared `:local` binding IDs recorded. | Normal terminal CLI+daemon result or independently correlated backend terminal/cancel receipt required. Timeout/lost response without it retains enforcement. On success remove only exact private tag bindings after their containers are absent; never delete shared/unowned IDs. On failure report retained private names/IDs/size; preserve cache/base layers. Shared bindings compared exactly before/after and never repaired by overwrite. |
| Separate mandatory T209 A2 unconfined-DP refusal leg; `tests/contract/stargate-cli/t162_enforcement_test.sh` `STARGATE_TEST_TAGS=t209-docker` branch, direct DP build, temporary key fixture and unconfined host-network container | T209 owns A2 execution/evidence; T220 inventories this branch's private image/name, immutable build ID, container, key fixture and policy refusal as a separate receipt. Full `STARGATE_TEST_TAGS=docker` does not execute it. | Recover exact owned IDs after lost build/create responses, verify stop/image/container/fixture cleanup and absence. An A7 matrix receipt cannot substitute for the mandatory A2 receipt. `connect_refusal.py` is a T173 effect only if separately invoked, with its own inventory. |
| Native Go Tor caller project and anonymous socket/state probes; `tests/contract/tor/port_exposure_test.go:TestTorSocketCallerMatrix,socketProbe,stateSocketProbe` | T220 run-derived project, verified Tor immutable ID, project containers/network/volumes and unique probe names/labels with intent. | Recover each probe after lost create response. Exact project/probe cleanup and absence including stopped containers and volume-only collision; Go JSON execution proof below. |
| Full T162 project and hostsim/sink/abstract/control containers, internal network, IPC volume, profile, policy helpers and application probes; `tests/contract/stargate-cli/t162_enforcement_test.sh` | T220 private Tor ID and run-derived project; all fixed resources and repeated `docker run --rm` helpers gain unique run-derived identities/intent. Record profile load and host rule effects before mutation. | Trap/outer coordinator reconcile exact IDs/labels on every exit and signal. Verify nested test-capable containers/helpers/descendants and their volume/network references absent before finalizer. In deferred mode, retain the exact owned nested AppArmor profile enforcing with a durable identity/source/digest receipt. Only the cleanup-only finalizer, after global workload/mutator/backend quiescence and ownership checks, removes that profile and the primary policy; verify both profile absences after removal and finalizer absence before PASS. A failed absence/ownership/removal check retains enforcement and FAIL; full T162 completion marker remains required. |
| Host AppArmor profile, owner chains/rules, fixed port/UID and policy-load helpers; `run.py`, installer and T162 | Prove no collision with protected baseline; write effect intents and measured pre/post rule/profile digests. Reserve separate authority before first protected mutation. | Reverse only exact owned rule/profile changes after Docker/build/workload quiescence, verify baseline exact. Uncertain receipt retains enforcement. Fixed port/UID collision or drift fails. |
| Private evidence, injected files and probe binaries; native `run.py`, `observer.py`, T162 and Go build paths, plus init temporary key directory, observer IID/env-file atomic replacement and `target/observer-build` receipts | Run-scoped 0700 paths, 0600 ledger, source/patch/input IDs and exact file intents; no key material in exported evidence. | Remove only exact owned temporary files after all users stop; retain sanitized failure evidence and private image/build artifact report. No unrelated host deletion or broad permission. |

The maintenance window covers Docker/BuildKit builders and cache-pruning
writers as well as container/policy writers. Baseline preservation applies to
pre-existing containers, networks, named volumes, protected policy and the
three shared image tag bindings. Normal build cache/base-image additions and
new private image content are reported, not treated as a failed global image
set comparison. No global prune, shared-tag rewrite or unowned sweep is allowed.

The supported backend must be measured before native qualification: daemon
endpoint/identity, rootful Engine and builder instance. The current VPS was
read-only grounded as Engine 29.1.3 and `default` Docker-driver BuildKit
v0.26.2. `docker buildx history ls --format json --no-trunc` may provide a
correlated terminal solve record, but a missing record cannot prove no build
started. A dead CLI, worker container, unchanged tag or quiet delay cannot
prove backend quiescence. A controlled backend cancellation/terminal-contract
check must pass on that exact approved backend before host-policy mutation.

## Acceptance

1. **Tests-first configuration falsifiers:** before code, record RED/GREEN
   with `scripts/test-first-evidence.py`. Ordinary unset deployment renders
   `:local`; qualification refuses absent, empty, malformed, `local`,
   overlong, conflicting or foreign/colliding suffix before any build/probe.
   Owned re-init/recovery reuses its exact names. With identical project,
   path and observer inputs, compare default/private checked-in Compose
   field by field: only three image references differ. Security, mount,
   network, UID, build context/Dockerfile and `pull_policy: build` mutation
   fail comparison.
2. **Actual writer-chain transport:** stateful command recorders exercise
   first init, re-init, observer validation, main fault/recovery `up`, Go
   caller and full T162. Omit suffix/env-file/project transport independently
   at each boundary or conflict process/env-file values; each fails before a
   shared-name build/probe. Observer env-file rewrite retains suffix without
   exporting its immutable ID into installer calls. Probe a changed current
   Tor ID and require that ID, never stale first ID or `:local`.
3. **Generation and backend results:** after each Compose `up` and direct
   build in this matrix, record private name, build generation, immutable
   output and actual deployed container image ID. Legitimate later DP/Tor
   rebuilds may change IDs; stale first-generation evidence fails. Include
   tagless observer output. Treat recovery `up` without `--build` as a
   possible writer. A forced timeout/lost CLI response needs independently
   correlated terminal/cancel proof for that exact build; dead CLI/worker,
   unchanged tags or delay cannot establish quiescence. Failure retains
   enforcement, reports private artifacts and never rewrites shared tags.
4. **Cross-UID and exact ownership:** tests first with coordinator UID 1002
   and UID-0 actor demonstrate atomic ledger write/read/update preserving
   0700/0600 modes and ownership. No broadly readable ledger or root
   coordinator shortcut. Stateful fake Docker interrupts after each effect
   and before receipt, including inventory-helper and publisher create,
   installer helper families, nested Go/T162 helpers, A2 direct build,
   first/re-init and later recovery. Recover exact owned ID or fail/retain
   enforcement; `--rm` is not an absence receipt.
5. **Collision, baseline and cleanup falsifiers:** seed stopped publisher,
   fixed-project container, labelled network/volume, unlabelled physical
   volume and foreign ID replacement. Refuse collision before mutation,
   revalidate ownership before deletion, verify exact owned absence and
   preserve baseline objects in both directions. Removing a baseline
   container fails. Partial later build/readiness failure keeps initially
   present or absent shared tag bindings exact and reports private artifacts.
   No global prune, unowned sweep or shared-tag rollback.
6. **Enforcement ordering:** nested T162 may succeed while its worker lives;
   profile unload remains forbidden. Prove nested test-capable containers,
   helpers, descendants and volume/network references absent first. The
   owned nested profile stays enforcing with source/digest receipt until the
   cleanup-only finalizer proves global worker/descendant/backend quiescence
   and removes exact nested and primary policy. Verify both profiles absent
   after removal and finalizer absent before PASS. Failed ownership,
   absence or quiescence retains enforcement and FAIL. Preserve R1–R3
   timeout, signal, descendant and policy-drift falsifiers.
7. **Scenario receipts:** parse `go test -json` for the expected package and
   selected named test: require run event, unique terminal PASS, successful
   package/command completion and no SKIP, FAIL, absent, duplicate or
   truncated result. A Docker-info SKIP with exit zero fails. Full T162 needs
   its explicit completion marker. Inventory the separate
   `STARGATE_TEST_TAGS=t209-docker` A2 build/container/key-fixture branch;
   T209 owns mandatory A2 execution/evidence, which full T162 cannot replace.
8. **Source checkpoint:** run only affected native launcher, observer,
   installer, T162, Compose and AppArmor source tests, then one fresh
   independent Astra/high plus Luna/high review set binding exact candidate
   and identities under the session exception. This source approval does
   not imply normal `scripts/verify.sh`/GLM-Astra delivery approval, T209 A7
   live PASS, host-policy authority or backend capability. If the approved
   backend cannot provide correlated terminal/cancel proof, leave native
   qualification blocked with enforcement/private artifacts retained and a
   concrete FAIL/NOT RUN as appropriate. After three fresh failed source
   review rounds, reassess the architecture and acceptance as a whole.

## Out-of-scope

T209 owns original A1–6/A8–9, including mandatory A2 application proof,
reserved constitutional/wording decisions and SECURITY-DECISIONS text. It
owns final combined native Local matrix, source/image evidence, rerun counts,
limits and final independent gate. This ticket performs no Docker, live,
build, full verification or protected host mutation at the amendment/source
checkpoint. No VM, shared-tag rollback or weakened Local actor/traffic
boundary is introduced.


### Historical chronology gate — T222

The initial-six missing raw RED/intermediate tests-only history is separate from the later path-stage caller-specific gap. Neither current source tests nor the earlier G preparation option resolves both automatically. T222 is the dedicated governed disposition of those two finite past classes only. Until explicit acceptance and adoption, no retrospective exception is available. Source defects, scope orphans, additional implementation, complete real-entrypoint coverage and exact independent source review remain ordinary obligations; no T220/native/A2/A7 completion follows amendment adoption.
