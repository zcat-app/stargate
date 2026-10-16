---
id: T215                         # Ticket filed after allocator check through T214.
title: "Instrument full Docker cadence using shared operation ownership"
status: pending
created: 2026-10-09
last_updated: 2026-10-16
source: "T212 §Acceptance 8: separately declared prerequisite; independently reviewed source census"
phase: "Integration"
story: "-"
blocked_by:
  - "T211"
  - "T213"
  - "T225"
  - "T223"
parallel: false
files_budget: 44
files_scope:
  - go.work
  - go.work.sum
  - tests/contract/go.mod
  - tests/integration/go.mod
  - tests/dockerowner/go.mod
  - tests/dockerowner/dockerowner.go
  - tests/dockerowner/dockerowner_test.go
  - tests/dockerowner/cmd/docker-owner/main.go
  - tests/dockerowner/cmd/docker-owner/main_test.go
  - scripts/verify.sh
  - scripts/go-workspace-gate.py
  - .github/workflows/docker-cadence.yml
  - scripts/lib/compose.sh
  - scripts/lib/docker-owner.sh
  - scripts/subcommands/init
  - compose/docker-compose.local.yml
  - THREAT-MODEL.md
  - specs/001-tor-route/tickets/T215-maintained-resource-ownership.md
  - specs/001-tor-route/STATUS.md
  - specs/001-tor-route/evidence/T215-tests-first.json
  - specs/001-tor-route/evidence/T215-resource-ownership-inventory.md
  - tests/contract/internal/compose/compose.go
  - tests/contract/internal/compose/compose_test.go
  - tests/contract/tor/control_port.go
  - tests/contract/tor/control_port_live_test.go
  - tests/contract/tor/port_exposure_test.go
  - tests/contract/tor/username_less_isolation_test.go
  - tests/contract/torrc/isolate_socks_auth_effect_test.go
  - tests/contract/torrc/live_sidecar_test.go
  - tests/contract/compose/network_hardening_test.go
  - tests/integration/circuit_isolation_corpus_test.go
  - tests/integration/same_origin_shared_circuit_test.go
  - tests/integration/stack_smoke_test.go
  - tests/contract/compose/operational_logs_test.sh
  - tests/contract/compose/control_mount_test.sh
  - tests/contract/compose/inter_plane_wire_test.sh
  - tests/contract/stargate-cli/t162_enforcement_test.sh
  - tests/contract/stargate-cli/init_docker_test.sh
  - tests/contract/stargate-cli/init_fixture_cleanup_test.sh
  - tests/contract/workflow/docker_ownership_test.py
  - tests/contract/workflow/docker_ownership_shell_test.sh
  - tests/contract/workflow/verify_skip_convention_test.sh
  - tests/contract/workflow/verify_discovery_test.sh
  - tests/contract/workflow/ci_inputs_test.sh
out_of_scope:
  - Docker daemon/service starts, live Docker commands, VM creation, or host canaries
  - build-cache pruning, shared image-layer deletion, global firewall snapshot restore
  - changing T212 implementation, evidence, acceptance, or H/J claims as part of T215
  - changing the review scorecard; it is not in this implementation union
  - weakening canonical verify, Docker cadence coverage, test timeouts, or CI limits
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/design/qualification.md"
  - "specs/001-tor-route/spec.md §FR-016"
decision_refs:
  - "T212 §Acceptance 8: maintained adapter is a separately declared prerequisite"
  - "T212 source census promoted to specs/001-tor-route/evidence/T215-resource-ownership-inventory.md"
  - "Maintainer batch instruction 2026-10-09: finish T211/T212/T202; independently evaluate necessary prerequisites; use GLM and Astra reviews"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T215: Instrument full Docker cadence using shared operation ownership

## Context and retained scope

Retain complete maintained producer instrumentation for T212's canonical Docker cadence and
T202's forced-stop consumer. T225 now owns the common tests/dockerowner module/API/command;
this ticket consumes it instead of creating a competing admission authority. T223 supplies the
bounded privileged intent/ACK transport. The original broad source census and cadence obligations
remain; they are not replaced by T220's narrower native matrix or T227's platform-only probe.

## Analysis

- Must hold: every reachable cadence mutation has exact durable pre-dispatch ownership; ordinary
  verify does no daemon operation, while named cadence runs all required tiers with honest SKIPs.
- Gated: actual producer entrypoints with controlled Docker/HTTP/policy tools and unchanged opt-ins.
- Residue: full-cadence request drain/cache isolation, quotas, H/J and rollback need separate
  evidence in T212/T202. A source owner adapter cannot establish those native properties.

## Acceptance

1. Retain the exact public named entrypoint STARGATE_TEST_TAGS=docker bash scripts/verify.sh,
   workspace discovery, ordinary-user execution, existing per-module concurrency/race/vet/scanners
   and all-SKIP refusal. Ordinary verify permits local Compose config rendering only, no daemon
   API. Named mode dispatches every required daemon tier, not a new hidden opt-in subset.
2. Repeat the full original source producer/cleanup/SDK/opt-in census at exact START. SDK calls
   currently read-only remain so; do not invent a mutating SDK adapter. Cover all original nine
   tagged Go suites, named shell tiers, init/key/volume/publisher helpers and host-policy writes.
   Retain source identity, search expressions, exact line anchors and omitted-path dispositions
   in evidence/T215-resource-ownership-inventory.md before implementation plans are approved.
3. Use T225's public module/API and same canonical domain, deadlines, capacity and daemon identity.
   T215's invocation/effect ledger is subordinate, never a second global gate. Native and cadence
   operations that overlap policy/UID/runtime state cannot be admitted independently by new roots.
   Build/CI tools remain outside deployed runtime authority; record their own source/build effects.
4. Intent/ACK/durability precedes each actual CLI/Compose/policy mutation, including normal teardown;
   returned IDs and generations bind the exact operation. Use T223's non-root phase-owner channel
   for privileged nested callers; no root replacement of canonical/effect state. Unknown/torn
   state remains preserved and blocking. The old automatic torn-tail repair allowance is retired:
   do not erase uncertainty or infer no dispatch from a dead client/empty inventory.
5. Retain original named-mode preflight before any daemon work: identity/locality, complete owner
   context, original absolute deadlines and opt-in refusal for network/repro/existing-stack wire
   mutation, with ground-check offline. Missing/malformed/partial context refuses; with owner
   context entirely absent ordinary production init still writes no test-ownership artifacts.
6. Keep unique project/name/label identity, exact foreign/baseline preservation and policy intent
   for real init plus T162's host-global AppArmor only; its firewall controls stay in hostsim.
   This ticket records ownership, not rescue cleanup or whole-table rollback. T202 consumes the
   delivered API for forced-stop recovery only after real child/request settlement.
7. Preserve redacted exported receipt and job-local raw logs. Explicitly test endpoint, host-path,
   credential, argv/environment sentinels cannot enter uploads. The workflow supplies only the
   declared state context and cannot upload raw target/verify.log or packet/user data.
8. Before each correction, a valid real-producer controlled-tool falsifier demonstrates missing
   intent/preflight/privacy behavior, then identical GREEN. Preserve framed/corrupt/concurrent,
   lost-response/late-create, daemon substitution, partial start and exact policy ordering controls.
   For absent APIs establish real executable consumers first; no import/compile failure is RED.
9. Do not call source delivery full-cadence admission: T212 still needs bounded request drain OR
   a qualified invocation-isolated daemon, cache isolation/hard quota, complete compile/runtime/
   cleanup H/J within actual CI limits, and the privileged DNS complement; T202 still needs real
   stop/rollback and broader live scenarios. T227 does not qualify this build-capable full cadence.
10. Deliver the full affected source candidate with exact required native reviewer pair under
    applicable repository rules, inventory and evidence/T215-tests-first.json. Preserve T212's
    archived original tests/implementation/driver history and reviewed selective-RED-before-source
    reopen sequence. No reset can manufacture prior chronology or erase failed attempts.

## Scope and completion

Retain the 44-path ceiling and original cadence consumer families, but shared-module establishment
belongs to T225 and native transport to T223. Before START enumerate the exact post-prerequisite
union; any API change returns to its owner/review rather than silently expanding this ticket.
No actual Docker/service/host/VM execution, source-cadence weakening, cache pruning or rescue
cleanup is part of this source ticket. Its completion alone still cannot pass T212 AC8/9.

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


# T215: Instrument Docker cadence resource ownership

## Context

T212 acceptance 8 requires a separately declared maintained adapter before any
complete Docker cadence can be considered for admission. An independent
read-only producer/mutation/cleanup census on 2026-10-09 against HEAD
`bc1bc67c7a9bd8076c6aa16be710ec1288a125d8` found Compose/standalone Docker CLI resource creation and host-policy mutation
paths that an external runner cannot identify safely without a durable
producer-side ledger. The live-sidecar Docker SDK calls are read-only
Ping/List/Inspect; they are not resource producers and need no mutating owner
adapter. It reconciled the
current 44-path candidate union. Repeat the census at clean START and amend the
union if source changed. This ticket adds invocation-scoped, durable ownership
intent and resource identity to those creation paths; it does not admit or run
a live cadence.

## Analysis

- **Must hold:** every supported Docker/Compose resource-creating or normal
  teardown operation writes and fsyncs an invocation-scoped intent before the
  daemon call; unique run ownership and returned IDs are recorded; the adapter
  refuses ambiguous or changed-daemon reconciliation; and test-triggered
  host-policy mutations are journaled before they occur. The adapter never
  performs rescue teardown. T202's maintained runner consumes the durable
  ledger for forced-stop recovery only after proving child/workload stop and
  preserving foreign resources.
- **Gated:** fake Docker CLI/HTTP endpoints, synthetic torn-ledger and lost
  response cases, test-source wiring checks, and the existing canonical gate.
- **Residue:** Docker daemon request drain after a client timeout, BuildKit
  cache isolation, privileged host behavior, and end-to-end H/J/CI measurement
  remain outside what offline tests can prove and block T212 admission.

## Acceptance

1. Keep the public invocation exact: `STARGATE_TEST_TAGS=docker bash scripts/verify.sh`.
   In named Docker mode `verify.sh` creates a fresh
   invocation ID, secure run directory, ledger, and built `docker-owner`
   helper beneath `STARGATE_DOCKER_STATE_DIR` (local default:
   `${XDG_STATE_HOME:-$HOME/.local/state}/stargate/docker-ownership`; the
   `docker-cadence.yml` job sets it under `${{ runner.temp }}`). It exports
   `STARGATE_DOCKER_RUN_ID`, `STARGATE_DOCKER_LEDGER`,
   `STARGATE_DOCKER_OWNER_BIN`, daemon identity, and D0/deadline to
   `go-workspace-gate.py` and shell children. At `verify.sh` entry, before
   `ground-check` or any Docker-capable phase, named mode rejects remote Docker
   context/host overrides and nonzero `STARGATE_RUN_NETWORK_TESTS`,
   `STARGATE_WIRE_RUNTIME_MUTATE`, or `STARGATE_VERIFY_REPRO`; it forces and
   exports `STARGATE_GROUND_ONLINE=0`. `go-workspace-gate.py` independently
   rejects missing or malformed ownership context before tagged tests launch.
   A fake-backed regression proves these checks happen before any Docker-tagged
   suite, daemon operation, or release-cadence build begins. Uploaded artifacts
   contain only a redacted receipt with a run-scoped pseudonymous daemon token;
   they never include the raw daemon endpoint/identity, host paths, credentials,
   or auth-bearing argv/environment. Assert this in the fake artifact test.
2. Resolve module placement without crossing Go `internal` boundaries: create
   the standalone module `tests/dockerowner` with package
   `github.com/zcat-app/stargate/tests/dockerowner` and command
   `cmd/docker-owner`; add it to `go.work`. In each consumer,
   `tests/contract/go.mod` and `tests/integration/go.mod`, add
   `require github.com/zcat-app/stargate/tests/dockerowner v0.0.0` and
   `replace github.com/zcat-app/stargate/tests/dockerowner => ../dockerowner`
   (relative to that module directory). Keep matching sums/workspace wiring
   generated and checked. The command is
   built once by named `verify.sh`; shell helper functions and Go callers use
   that shared owner API. Tests in both modules import the public shared
   package. Do not place it beneath either module's `internal/` tree.
3. Define the ownership API only; do not recreate the guardian. Its bounded
   calls are `Begin(runID, daemonID, D0, deadlines)`, `Intent(operation,
   argvHash, resourceKind, uniqueNameOrLabel, deadline)`, `Result(intentSeq,
   exit, returnedIDs, observedState)`, and read-only `Reconcile(daemonID)`.
   `Intent` fsyncs a framed, flock-serialized ledger row before each mutating
   Docker/Compose or host-policy operation; `Result` binds returned IDs/digests
   and state. Repair a torn tail under the lock before any producer appends;
   fail closed on interior corruption, daemon changes, or ambiguous results.
   Compose and standalone CLI resources get invocation-unique projects/names
   and labels where supported. Existing test `t.Cleanup` and shell traps remain
   normal teardown and record their operations through the owner wrapper. The
   API never stops processes, finalizes artifacts, removes resources, or rolls
   back policy. Instrument the shared Compose producer in
   `tests/contract/internal/compose/compose.go` and the direct control-port
   Docker command path in `tests/contract/tor/control_port.go`; update
   `compose_test.go` to pin the shared owner wrapper. T202's maintained scoped
   runner is the forced-stop rescue consumer; it may act only after proving
   workload stop and uses this public ledger contract, not ignored scratch code.
4. Record the source-only producer/mutation/cleanup census in
   `specs/001-tor-route/evidence/T215-resource-ownership-inventory.md` and
   preserve its full path/line anchors in this ticket. An independent source
   census reconciled the current HEAD to the 44-path candidate union. The
   durable artifact must retain source identity, search expressions, exact
   line anchors, and dispositions before filing; repeat the census at clean
   START and amend paths/budget if source changed. Search expressions include
   `rg -l -i '(docker|apparmor|iptables|ip6tables|nft)' tests/contract tests/integration scripts`,
   `rg -l '^//go:build.*docker|^// \+build.*docker' tests/contract tests/integration`,
   and structured scans for Docker CLI producer verbs, Docker SDK mutator methods (the source scan must confirm none are reachable),
   Compose up/down/build/pull calls, host-policy writes, and cleanup
   handlers. Spot-check anchors include `control_port_live_test.go` (project 44,
   Docker info 63, cleanup 78-81, up 88), `isolate_socks_auth_effect_test.go`
   (project 98, info 155, cleanup 174-177, up 184), `live_sidecar_test.go`
   (project 77, SDK client 159, cleanup 190-193, up 208, further Compose
   operations around 495-568; SDK methods are read-only Ping/List/Inspect),
   `stack_smoke_test.go` (Docker info 121, Compose
   cleanup 160-168, standalone runs 248 and 370), and `control_mount_test.sh`
   (daemon guard 11-18, cleanup 27-29, local Compose config render 62-63,
   Compose build 76-80, volume/container operations 93-151). The complete grouped action/cleanup anchors and source
   search dispositions follow; repeat source tracing at START to catch drift.

   | Source | Create/mutation and normal cleanup | Forced-stop gap / required ownership |
   |---|---|---|
   | Nine tagged Go files (all `//go:build docker` at line 1): `tests/contract/tor/{control_port_live_test.go,port_exposure_test.go,username_less_isolation_test.go}`, `tests/contract/torrc/{isolate_socks_auth_effect_test.go,live_sidecar_test.go}`, `tests/contract/compose/network_hardening_test.go`, `tests/integration/{circuit_isolation_corpus_test.go,same_origin_shared_circuit_test.go,stack_smoke_test.go}` | Key create/cleanup anchors: control_port_live 63, 78–89; port_exposure 33, 41, 57, 151–165; username_less 127, 143–154, 391; isolate_socks_auth 155, 174–185, 450; live_sidecar SDK Ping/List/Inspect 159/510–526/568, cleanup 190–194, up 209 and Compose 503–568; network_hardening 37,45,77; circuit corpus 115,132–164,343,479–487; same-origin 136,152–179,267,408; stack-smoke 121,168–181,248,370,388. Compose projects `stargate-t032-test`, `t058-test`, `t058a-test`, `t060-test`, `t061-test`, `t062-test`, `t131-test`, `t162-socket-test`, `t162-topology-test`; project containers/networks/volumes. `live_sidecar_test.go` uses the SDK only for read-only Ping/List/Inspect; resource creation is through Compose CLI. `stack_smoke_test.go` invokes real init. | SIGKILL skips cleanup; some errors are logged rather than failed; fixed project collisions; images/cache remain. Every mutating CLI/Compose intent needs a run label/project and returned ID. |
   | `tests/contract/compose/control_mount_test.sh` | Daemon guard 15, cleanup 27–29, local Compose config render 62–63, Compose build 76–80, volume/container calls 93–151. Real CP build; physical volumes without Compose labels; named standalone containers and `--rm` probes; EXIT/INT/TERM cleanup attempts IDs/volumes. | No Docker API deadline; traps bypassed by SIGKILL; image/cache remains. Ordinary verify currently reaches this if daemon exists. |
   | `tests/contract/compose/operational_logs_test.sh` | Local `docker compose config` render 9; Docker-tier guard 54–57; fixture pull and seven detached `docker run` calls 60–85; EXIT cleanup 24. | No command deadline; SIGKILL bypasses trap; image/cache remains. Keep config-render assertions in ordinary verify; gate daemon calls to named mode. |
   | `tests/contract/compose/inter_plane_wire_test.sh` | Structural checks/render 280–299, 451–452; Docker runtime calls include 461, 467, 546/550, 558, 642–697. With `STARGATE_WIRE_RUNTIME_MUTATE=1` (guard 530–532), it operates on an existing stack, stops/restarts CP and changes test data rather than owning that stack. | Runtime mutation can be interrupted; canonical invocation must reject the opt-in. Docker runtime portion is named-only; structural checks stay ordinary where separated without turning partial execution into PASS. |
   | `tests/contract/stargate-cli/t162_enforcement_test.sh` | Docker tier guard 134–143; creates/removes network and containers 165–194, policy probes 387–394 and cleanup 165–177/519–521. Loads a temporary host-global AppArmor profile. Its iptables/ip6tables calls at 204–210 and 357–375 run inside the `hostsim` container network namespace, not the host. | Trap bypassed by SIGKILL; Docker/AppArmor cleanup has no deadline. Ordinary path already emits a Docker-tier SKIP after source assertions. |
   | `tests/contract/stargate-cli/{init_docker_test.sh,init_fixture_cleanup_test.sh}` | `init_docker_test.sh`: daemon guard 55–63, cleanup 75–90, real init 109 onward, volume operations 138–153, direct create 275/284 and helpers 313–350. `init_fixture_cleanup_test.sh`: daemon guard 8, foreign volume create 17–18, fixture init 20–22, cleanup/assertions 30–41. | SIGKILL bypasses traps; returned IDs/pulls may persist; Compose stop grace does not bound API operation. Both are real-Docker shell paths. |
   | `scripts/subcommands/init`, `scripts/lib/compose.sh`, `compose/docker-compose.local.yml` | `compose.sh`: Compose wrapper 129–134, volume query/create 142–170, helper containers 181–240. `init`: host firewall mutation 144–157 and AppArmor load 253–255; daemon checks/pull/volume at 287–375; helpers 449–458/547–554; image build/load 601–626; Compose up 650–655. `stack_smoke_test.go` enters real init at 181. Compose YAML names the persistent service volumes and `stargate-egress`. | Normal init has no uninstall/rollback for global policy, and images/BuildKit cache remain. Init writes host-global AppArmor plus IPv4/IPv6 OUTPUT rules for UID 5102. T162's firewall test rules are confined to `hostsim`; only its temporary AppArmor profile is host-global. Exact deltas and process-safe rollback require journaling. |
   | Hermetic and opt-in exclusions | `tests/contract/compose/{local_compose_test.sh,inter_plane_wire_rows_test.sh}`, `tests/contract/stargate-cli/{init_test.sh,init_t198_test.sh}` use structural/fake tools or local Compose rendering; rendering with `docker compose config` is local and remains allowed in ordinary mode, while daemon operations are gated. `tests/reproducibility/tor_sidecar_manifest_test.sh` builds/creates images only under `STARGATE_VERIFY_REPRO=1`; `scripts/ground-check.sh` may call buildx only with `STARGATE_GROUND_ONLINE=1`. Integration `onion_load`, `stream_isolation`, `stream_isolation_dp_uname` require `STARGATE_RUN_NETWORK_TESTS=1`. | Named cadence rejects those opt-ins and sets grounding offline; their extra source paths are therefore not in this ownership union. Future opt-in inclusion requires new census and scope review. |

   Independent read-only source tracing on 2026-10-09 confirmed that the 44
   candidate paths cover the nine Docker-tagged Go files, the named installer
   and Compose producers, and the Docker-backed contract shell tiers. It also
   found opt-in-only integration producers in
   `tests/integration/{onion_load_test.go,stream_isolation_test.go,stream_isolation_dp_uname_test.go}`;
   their creates/up calls are at onion_load 204, stream_isolation 266/316/381/405,
   and stream_isolation_dp_uname 372/393/728/735. These remain excluded only
   because named verify rejects `STARGATE_RUN_NETWORK_TESTS=1` before the Go
   gate. `tests/reproducibility/tor_sidecar_manifest_test.sh` is excluded only
   because named verify rejects `STARGATE_VERIFY_REPRO=1`; `ground-check.sh`
   is kept offline even if the caller exports `STARGATE_GROUND_ONLINE=1`.
   `scripts/subcommands/status:201` has a Docker info check but no invocation
   path from the verify dispatcher. Local-only `docker compose config` checks
   in `local_compose_test.sh:16`, `operational_logs_test.sh:9`, and
   `inter_plane_wire_test.sh:288,451-452` remain ordinary gates; fake-only
   `inter_plane_wire_rows_test.sh:15-130` does not reach a daemon. The durable
   inventory must include these exact line anchors and record the search
   expressions and dispositions. If implementation source tracing finds a
   different match or a changed call graph, revise the exact files and budget
   before START; never infer coverage from this candidate list or from live
   Docker/host inspection.
5. Make ordinary and named shell cadence explicit and honest. `docker compose
   config` and equivalent YAML rendering are local computations and remain
   allowed in ordinary verify; distinguish them from daemon APIs such as
   `docker info`, pull/build/run/create/up/down, SDK calls, and Docker HTTP.
   Ordinary `verify.sh` must never invoke those daemon operations. Split
   structural/config checks from daemon tiers where possible; report
   `SKIP: requires STARGATE_TEST_TAGS=docker` for daemon-only tiers. Named mode
   executes every required daemon tier and records its result. Preserve
   source-only assertions as ordinary gates; never label partial execution
   PASS. Keep `inter_plane_wire_test.sh` runtime mutation as a separate opt-in
   rejected before named cadence work; T215 does not claim that existing-stack
   runtime tier ran in the canonical cadence. Extend `verify_skip_convention_test.sh` with fake Docker/Compose tools
   proving config rendering remains allowed in ordinary mode while no daemon
   API operation occurs, inherited opt-ins are rejected or disabled before
   named work, and named mode dispatches each required daemon tier.
   This acceptance changes `verify_discovery_test.sh` to assert owner-context
   preflight ordering and changes `ci_inputs_test.sh` to assert the cadence
   workflow supplies only the state directory, uploads the redacted receipt, and
   does not upload `target/verify.log`. Keep both named in scope; neither is
   incidental test churn.
6. Journal test-triggered AppArmor mutation intents in the real-init and T162
   paths, and IPv4/IPv6 firewall intents in real-init only. Enable this journal
   only when the complete validated named-cadence owner context (run ID, ledger,
   owner executable, daemon token, and finite deadline) is present. With all owner
   context absent, production `stargate init` follows the existing path and
   creates no ownership files or records; a partial or malformed context fails
   before any Docker or host-policy mutation. Fake tests prove both cases.
   T162's firewall rules are confined to `hostsim`; only its AppArmor load is
   host-global. This ticket records intents and exact mutation results but does
   not roll policy back. T202's maintained scoped runner owns forced-stop
   rollback after proving owned containers/processes/threads are stopped. Baseline
   conflicts, unrelated concurrent policy, unavailable query, and any uncertain
   delta fail closed; remove only exact invocation additions, never flush or
   restore a whole table. Update `THREAT-MODEL.md` in this ticket because
   production init/Compose host-policy behavior is in scope. Ordinary installer
   behavior and the policy guarantees remain unchanged.
7. Tests-first RED/GREEN record path is exactly
   `specs/001-tor-route/evidence/T215-tests-first.json`. Before implementation,
   stage a named assertion for every privacy-critical falsifier: fsync-before-
   create for CLI/Compose; unique Compose project/labels; torn-tail repair and
   concurrent append; daemon identity and lost CLI/Compose-response reconciliation; exact
   host-policy intent-before-mutation. Use fake Docker CLI/HTTP and policy
   tools. Existing read-only SDK Ping/List/Inspect tests remain unchanged; no
   SDK mutation adapter is in scope. Do not test rescue teardown here; T202
   owns child-stop proof, delta-only rollback, and cleanup-failure controls
   against this public ledger contract. Each RED must reach its intended assertion against the
   existing behavior; missing import/module/symbol or compile failure is not
   RED evidence. Record a separate RED result per assertion group before
   implementing that group's adapter. For new API tests, a compileable
   fail-closed seam may be staged with the tests, but the test must execute and
   fail on its named safety assertion; absent production symbols are never the
   failure. If a property cannot be made to fail through an existing producer
   or such a seam, stop and revise the RED design before implementation. Run
   each assertion group's recorded RED command, including:
   `python3 scripts/test-first-evidence.py red T215 -- python3 tests/contract/workflow/docker_ownership_test.py`.
   The test file is staged alone against the genuine T215 START tree. It runs
   the existing `control_mount_test.sh` in a disposable fixture with fake
   Docker/Compose, returns healthy daemon/build/inspect results, and asserts
   the falsifiable property “every resource create has a preceding fsynced
   invocation intent.” Pre-fix RED must reach the fake `docker volume create`
   or `docker run` and fail exactly on the missing owner-intent property; a
   missing module/import/tool is not valid RED. After implementation, stage
   the same source paths and rerun each identical command through `green`; use
   the same fake schedule and assertions. The separate shell dispatcher tests
   fake healthy Docker in ordinary mode (expect no daemon operation plus
   truthful SKIP) and named mode (expect the control_mount and other Docker-only tests
   to execute). Separately run
   `cd tests/dockerowner && go test ./...` and
   `bash tests/contract/workflow/docker_ownership_shell_test.sh` for framed
   ledger/torn-writer/concurrent-producer, CLI/Compose, mutation and cleanup
   controls. Do not use a real Docker daemon, service, privilege, or VM.
8. Required adapter falsifiers cover lost CLI/Compose response after fake
   daemon commit, late create after client timeout, missing/duplicate labels,
   daemon-identity change, foreign/baseline resources, torn/interior ledger
   corruption, and partial create/start. Ambiguous outcomes never yield a
   successful ownership receipt or authorize deletion. T202 separately tests
   process-stop proof, rescue cleanup, exact policy-delta rollback, and
   independent cleanup-result accounting against the stable ledger schema.
9. After T215 has a genuine clean START, run the canonical
   `scripts/run-task.sh T215` lifecycle. Its ordinary `scripts/verify.sh`
   pre-review gate, exact named skip/dispatch contracts, and focused fake
   suites must pass before review. The
   existing public named command must remain the one launched by
   `.github/workflows/docker-cadence.yml`; the workflow supplies
   `STARGATE_DOCKER_STATE_DIR` and uploads only the redacted ownership receipt;
   the potentially sensitive raw `target/verify.log` remains job-local and is
   not uploaded by the Docker cadence workflow. The upload test inserts endpoint,
   host-path, credential, argv, and environment sentinels into child output and
   verifies none appears in any uploaded file. No live Docker/service/privileged-host/VM action is part
   of this ticket. Both native GLM/Astra reviews are mandatory on the same
   unchanged candidate after canonical verification. Do not bypass either
   reviewer, substitute another model, or mark T215 done until both matching
   verdicts approve.

## Out-of-scope

This ticket instruments test resource ownership and narrowly journals the
existing test-triggered installer policy writes. It cannot claim Docker daemon
request-drain guarantees, isolate or bound shared BuildKit cache/API work,
remove shared images/layers, establish a finite full-gate H/J projection, meet
the 120-minute CI cap, or demonstrate host-kernel rollback behavior. No
resource pruning or whole-host policy restore is permitted. T215's delivery
alone does not satisfy T212 AC8/9.

The T212 in-review candidate, its index and worktree variants, five
`target/runs/T212*` files, and hashes were archived at
`.scratch/preserved/T212-before-T215-20261009/`; the manifest validated. The
8.4 GiB ignored T212 evidence remains in place and was not duplicated. T212 is
now deferred behind T215 with `blocked_by: [T211, T213, T215]`. Its lifecycle
was committed as `3c88576`, then corrected by `d4e28ea` after verification
caught that the first commit had left `status: pending`; the current ticket
must remain `status: deferred`, `deferred_on: T215`, and
`deferred_reason: blocked-on-new-ticket`. STATUS reflects that state. Before
T215 START, revalidate a clean tree, this exact blocker state, and the archive
manifest; independently inspect both lifecycle commits against the archive.
The maintainer's batch instruction authorizes this prerequisite and the
post-T215 T212 reopen/reset/replay sequence.

After T215 is done, reopen T212 per `run-task.sh`'s deferred instructions
(clear deferred fields, record the reopen, retain the completed dependency,
regenerate STATUS), commit that lifecycle change, then run
`scripts/run-task.sh T212 --reset` and `scripts/run-task.sh T212` on a clean
tree for a genuine new START. Selectively reapply archived T212 body/source
changes while preserving new lifecycle fields and review history; reconcile
T215/T212 overlap in `go-workspace-gate.py`, `docker-cadence.yml`,
`ci_inputs_test.sh`, and STATUS against the post-T215 base. Stage only the
original T212 tests first, then capture fresh RED against the genuine post-T215
T212 START tree using the same prior probe command:
`python3 scripts/test-first-evidence.py red T212 -- bash -c 'status=0; bash tests/contract/workflow/verify_discovery_test.sh || status=1; bash tests/contract/workflow/ci_inputs_test.sh || status=1; exit "$status"'`.
Restore selected implementation paths only after that RED, and capture GREEN
with the exact counterpart:
`python3 scripts/test-first-evidence.py green T212 -- bash -c 'status=0; bash tests/contract/workflow/verify_discovery_test.sh || status=1; bash tests/contract/workflow/ci_inputs_test.sh || status=1; exit "$status"'`.
Never replay the full old implementation and call it RED. Preserve T215's tests
and discovery assertions in overlapping test files; selectively restore the
original T212 regressions into the post-T215 versions instead of replacing
those files with archived copies. This lifecycle and replay are not included
in the 44-path T215 implementation union. T212 cannot claim AC8/9 until T215
is done and all remaining admission blockers are independently closed.

## Notes

The proposed 44-path union includes workspace wiring for the shared module;
the two consuming module manifests; named verify/workflow context; nine
Docker-tagged Go files; six shell Docker-capable contracts; installer/Compose
and threat-model changes; the ticket, generated STATUS, tests-first record and
durable inventory; and new helper/test files. The inventory output is required
so the source-only producer/mutation/cleanup census is durable in the ticket
candidate, not only scratch. The ticket allocator had no T215 collision when
checked; T214 was the highest existing ticket. Do not freeze or file this
budget until the source census and union are independently checked.

The runner-shim alternative remains insufficient alone: every direct Compose/CLI
producer must pass through the same ownership contract; existing named shell
contracts execute real Docker in ordinary verify; and opaque argv rewriting can
desynchronize project labels from test queries and cleanup. The proposal uses
an explicit shared Go module/package across both Go modules, a shell helper and
Go call sites backed by the same `docker-owner` command, and explicit cadence
dispatch. Read-only SDK Ping/List/Inspect calls remain unchanged.

Before any live cadence, separately prove bounded Docker API request drain or
an invocation-isolated daemon boundary; prove tag/reference ownership without
deleting shared image content; solve builder-cache isolation or hard quota and
cleanup; close complete H/J with all non-Go gates and the current 120-minute
CI limit; and obtain independent host-policy behavior evidence. If any of
these cannot fit existing caps, record NO-GO rather than widening them or
claiming T215 as admission.

## Plan review and start boundary

This proposal is not implementation approval. The source census and 44-path
union were independently reconciled. GLM returned conditional GO with two MAJOR findings; Astra identified the SDK
producer census error, artifact-log privacy gap, and cleanup-owner ambiguity.
This revision addresses those findings and records the source-level falsifiers.
Both independent reviewers must approve this exact revised hash before clean
T215 START. The maintainer's batch
instruction authorizes the prerequisite and the already-completed T212
archive/deferral; after matching GLM and Astra plan GO, T215 may receive a
clean START on the recorded candidate. Any new scope or host/filesystem
mutation beyond this reviewed plan requires re-evaluation before execution.
