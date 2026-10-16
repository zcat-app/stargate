<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Qualification design — 2026-10-16

Required implementation design for the [qualification contract](../contracts/qualification-boundary.md).
This selects owners and interfaces; it does not claim they exist or authorize source/native work.
It replaces the old reusable T218 and in-window-build T220 design, preserving failed history.

## DQ1. Selected architecture and alternatives

Use existing roles, sequentially: an artifact producer outside runtime authority, the native
coordinator, the Go readiness owner and its bounded Python invocation observer. Keep a cleanup-only
privileged actor solely where existing native policy removal requires it; it is never a competing
workload owner or unattended recovery service. No new daemon, Docker derivative or benchmark runner.

Start from the private, unintegrated and unapproved T218 fixture reservation code as the reuse
candidate for one canonical admission-state mutator. Main integration has no such shared component.
Extraction requires real-consumer establishment, reconciliation and source review; it is not
adoption of that failed candidate or native-qualified code. Expose the shared component in the prepared Go
qualification executable for coordinator use. The coordinator invokes bounded record operations,
not a second reservation implementation. These short-lived commands do not own effects, perform
cleanup or decide readiness. This interface is proposed source work, not an existing capability.
The Go readiness owner calls the same functions directly. The Python observer never writes state.

T220's per-run ledger becomes subordinate effect/result evidence referencing the enrolled domain
and current run/candidate. It cannot authorize a run, clear the global reservation or infer global
settlement. This retains useful effect records without creating two independent admission gates.
The native coordinator owns import and outer-runtime phases; Go exclusively owns readiness effects
while its phase is active. An outer coordinator cannot settle Go's uncertain effects after owner
loss. Conversely Go cannot mark the outer coordinator/observer command complete.

Alternatives rejected: independent T218/T220 gates permit cross-harness overlap; one giant owner
rewrite abandons useful existing role boundaries; another supervisor adds a terminal handoff rather
than settling it. Shared narrow admission mutation preserves one schema/checker and phase ownership.
No claim is made that sharing a module alone supplies correct ownership or cross-UID access.

## DQ2. Domain and state transitions

Keep the authority-pinned home, reservation root, enrollment and stable scope lock. Enroll the actual
host/runtime/policy/UID conflict set once. All overlapping T218/T220/installer/native callers use
that enrollment; do not hash arbitrary caller-selected scopes into independent locks. Same-kernel
policy/UID overlap conflicts even when daemon endpoints differ. Different host boots/daemon epochs
are identity changes needing reviewed reconciliation, never an automatic empty/new scope.

The single state graph is:

`BOOTSTRAPPED -> AUTHORIZED(candidate) -> PENDING(imports) -> PENDING(runtime/readiness)
-> SETTLED(candidate)`.

Any uncertain transition remains blocked; no automatic uncertain-to-authorized transition exists.
A published SETTLED record is provisional for admission until the original owner AND observer
commands actually complete successfully. Late close/output/receipt failure may leave those same
settled bytes visible; the missing truthful external decision keeps the domain ineligible. Do not
rewrite history to manufacture a pending marker or infer completion from a new observation.
SETTLED does not authorize replay. Next candidate authorization validates the immediate previous
settlement plus the trusted manual observation of the completed original owner/observer commands.
A second authorization before this candidate's attempt, or a second attempt afterward, refuses.
Bootstrap/authorization need their own independently observed completion before first use. A
post-publication command failure cannot be cured by a later process reading the same receipt.

All mutations are under the stable no-follow scope lock with latest-authority reread, exact expected
state identity and durable atomic replacement/readback. Do not hold one lock as a substitute for
persisting pending; process death releases locks. Partial/fsync/close/readback uncertainty blocks.
The existing six-frame Go/observer protocol is unchanged; admission-record commands are a narrow
closed command interface, not a general event stream or new cleanup protocol.

One current record contains bounded domain/enrollment identity, monotonic metadata generation,
candidate/source/authority identity, state/phase/owner identity, immediate predecessor references,
subordinate effect-summary identity and cumulative capacity counters. A phase handoff binds exact
prior owner result and incoming owner identity; it neither renews deadlines nor changes source.
Closed per-command schemas, byte/file maxima and temporary-write census must be derived and reviewed
in the implementation plan before tests for those commands. Do not copy old B/W/S quota bridges
or silently accept arbitrary JSON fields. This document does not invent numerical evidence limits.

## DQ2a. Privileged nested intent and dispatch transport

Select a synchronous, run-private Unix request/ACK channel served by the existing designated
non-root phase owner while it waits for its privileged worker. This is a finite allowlisted
operation adapter in that owner's existing lifecycle, not a new daemon or supervisor. The native
coordinator serves its outer-runtime worker; during readiness the Go owner serves only its own
registered helpers, and outer-phase dispatch is closed. Phase handoff closes the old endpoint,
settles its requests and binds the incoming endpoint/owner before admitting the next phase.

Replace the private T220 root worker's direct `RunState.open/_write` and nested `compose-up`,
`create-resource`, `intent/observe` accesses with this client path. A final helper result or one
"worker started" intent cannot replace per-operation pre-dispatch intent. Root callers never open,
replace, chown or repair canonical state or the non-root effect ledger. Read-only inspection stays
separate and cannot mutate state by falling back to the old CLI path.

For every nested init/T162/helper mutation:

1. The caller sends one bounded request naming enrolled domain, reviewed candidate/source,
   phase/owner epoch, unique operation ID, inherited absolute deadline and exact operation kind,
   resource identity, expected inputs and invocation digest. No arbitrary shell/command payload.
   Validate the peer's actual UID/PID/start identity and its registered owned ancestry; endpoint
   path or a supplied PID alone is insufficient. The authority boundary remains trusted-root/
   cooperative-user, not containment from a hostile root.
2. The current phase owner validates the request against its finite callsite/operation allowlist,
   current enrollment/authority/phase, remaining original budget and resource/evidence envelope.
   Through the shared Go component it confirms canonical pending, commits the exact subordinate
   effect intent durably and binds its generation/digest into canonical admission evidence.
3. Only after successful durability/readback does the owner return an exact operation-bound ACK.
   The caller may dispatch precisely that one operation once, then returns its bounded result
   or explicit uncertainty on the same channel. The owner records it before any dependent grant.
   Missing/stale/wrong-phase ACK, timeout, unknown commit or channel failure grants no new dispatch.
4. Owner loss closes new grants. An operation already acknowledged may still execute or arrive
   late; do not promise revocation of that grant. Its durable intent remains uncertain, so no
   other candidate or policy-removal path is admitted. Lost ACK/result cannot be repaired by
   retrying, scanning empty inventory or replaying a token. Keep pending/necessary enforcement.

In a Go phase the Go owner can call the shared mutator directly for its own operations; privileged
helpers still receive only exact precommitted grants. A root worker cannot request an outer-phase
operation while Go owns readiness, and the native coordinator cannot settle Go effects. Before
policy-removal dispatch, the existing cleanup-only actor uses the same exact-intent/ACK boundary,
with every earlier relevant request settled and ownership revalidated. Its result/absence and
external command completion remain mandatory.

Source acceptance must trace real nested init/T162 request -> durable intent -> ACK -> dispatch ->
result, with cuts before/after commit/ACK and owner death. Before grant, refuse before effects;
after grant, preserve the recorded potential late effect. Test ordinary success without chmod
widening, root replacement or a second admission authority. The implementation plan supplies the
closed messages, finite operation census, channel byte/request/file/PID limits and nonrenewable
budget accounting before source tests. No native experiment is required to select this transport.

## DQ3. Storage and actor access


- **Enrollment, stable lock, state/evidence roots**
  Explicit Go bootstrap, pinned non-root UID — All same-domain admission; survives every disposable
  workspace

- **Current authority and next-candidate authorization**
  Explicit maintainer-invoked Go writer — Shared validator; immutable source identity per candidate

- **Canonical admission/capacity state**
  Shared Go component; designated phase invokes its bounded operation — Go owner/coordinator; no
  root-helper or observer direct replacement

- **Phase effect records**
  Current owner via DQ2a intent/ACK transport — Coordinator/Go as applicable; subordinate to
  canonical admission

- **Privileged helper result**
  Named helper emits bounded sanitized result to owning coordinator — No traversal/write of
  caller-private state by arbitrary root helper

- **Candidate, observer receipt, original proof/output**
  Existing named producer; immutable bounded files — External invoker/reviewer; preserved across
  candidate changes

Use private 0700 directories and 0600 records, no-follow relative operations, original held FD facts
and exact UID/mode/device/inode/link checks. Cross-UID actors do not atomically replace the canonical
non-root record. The caller retains ownership and validates their fixed bounded response. A denied
traversal, root-owned replacement or lost response is failure, not an invitation to chmod broadly.

Before any writer starts, precharge its complete bounded output and all simultaneously live temp
files in the common capacity account, including current-record replacement and authority growth.
Initial bootstrap reserves its own metadata envelope explicitly. Cumulative capacity remains charged
after settlement; no fresh-candidate reset, history scan, refund or deletion. Source tests can check
precharge ordering/arithmetic; actual filesystem/quota/durability enforcement is a platform gate.
Workspace removal never removes canonical state or retained evidence. Observer evidence cannot
require a file already removed by Go E5: freeze it before removal and retain its bound reference.

## DQ4. Artifact contract and actual consumers

A trusted reviewed producer exports data-only finite candidate metadata and artifacts. Separate
archive SHA256, OCI root/platform manifest digest, config/Engine image ID and shipped payload hashes.
Authenticate source-to-build origin and independently expected identities; a revision label or a
manifest listing source and image hashes does not establish which source produced the image.
Use the existing release retained-candidate graph/payload/provenance checks where applicable, with
internal validation policy. Do not call signed `verify-install` with fabricated release fields.

Reuse the release Compose topology transformation with a separate internal image validator. Preserve
security, mounts, UIDs, networks and production topology; remove build directives/build pull policies,
require explicit no-build/no-pull, and refuse missing helpers before protected policy/volume/key
mutation. Treat image load as an external mutation: claim the domain and record pending before it.
Validate all archive members/tags before load, then verify exact loaded IDs and platform afterward.
Runtime uses only validated image bindings; exact Engine/Compose syntax and config-ID resolution
must be qualified before native admission. No registry digest/config-ID substitution is permitted.


- **`scripts/subcommands/init`**
  Only source and signed-release modes exist; internal validated path must retain
  topology/host-boundary/key/readiness guards — T223 source

- **`scripts/lib/compose.sh`, init supply-chain guard**
  Missing key/volume helper can pull; include pinned helper and refuse missing image — T223 source

- **`tests/live-e2e/local-topology/{run.py,observer.py}`**
  Primary/re-init/recovery/publisher paths must use the same candidate, no fallback to source builds
  — T223 source

- **`tests/contract/internal/compose/compose.go`, Tor caller matrix**
  Pass validated project/env/candidate and exact Tor image through actual builders/probes — T223
  source

- **`tests/contract/stargate-cli/t162_enforcement_test.sh`**
  Precompile probe and include A2 variant; full Docker tier and A2 leg remain distinct — T223
  source, T220 native

- **`tests/integration/egress_observer_test.go`**
  Source init, Buildx mounts, test-binary compilation and exact `--build` shim classifier must
  change together — T223 common artifact adapter; T218 readiness binding

- **Other in-scope nested integration tests**
  Hardcoded source Compose/`--build`, installer consumers and exact-argv classifiers need explicit
  artifact transport — Existing affected consumer owners; census in T223 plan

- **Full workspace/cadence outside the native matrix**
  No implicit artifact conversion or skip; preserve compile/race/vet/scanners, source
  install/rebuild and DNS complement — T212/T215/T202

The first six rows are the bounded initial native artifact-consumer scope. The seventh row is not
permission to expand to every suite: enumerate only actual reachable nested callers before source
planning; unsupported artifact callers refuse. Preserve separate required source/cadence runs.
The source freezer runs before producer builds; native runner verifies the prepared source/runner/
Go binary/helper/tool identities against that closure. It never recompiles inside runtime authority.

## DQ5. Settlement, failure and experiment order

Normal acknowledged runtime effects need exact generation-bound create/start/exec/stop/remove
results, all child/descriptor/reader outcomes and baseline checks. Acknowledged deletion plus empty
inventory is not a generic proof of all hidden prior requests. Every request must be either covered
by the qualified completion predicate or recorded uncertain. Policy removal requires all relevant
requests/effects settled, exact actor absence and restoration. Keep the separately privileged
cleanup-only actor bounded and prove its own absence before success publication.

Uncertain effects, request responses or durability retain pending and necessary enforcement.
After effects settle, a later owner/observer command failure may leave provisional SETTLED bytes;
admission still blocks without truthful successful original-command observation. Never promise a
new pending write after the sole owner is dead. No supported automatic recovery exists yet. Inventory diagnoses
but cannot clear pending. The plan does not pick restart, reboot or VM teardown as a known oracle.
A fault experiment needs acceptable quarantine or a separately qualified terminal procedure first;
never discover that requirement by stranding the shared host. No new VM or host operation is
selected or authorized by this design.

Platform qualification must use existing commands and a pinned existing fixture before the future
internal consumer exists. Name actual separate producer/runtime venue capabilities, concrete commands,
limits, expected identities, acknowledged normal operation and quarantine disposition in the finite
experiment protocol. Those values are not available from the current source audit and remain
unqualified. Source fixtures then establish the real bounded consumer and safety behavior through
its actual entrypoint; native measurement follows source/platform/authority qualification. This
removes the circular requirement to execute nonexistent consumer code as a prerequisite for writing it.

## DQ6. Acceptance migration and implementation order

This design's owner map is the required ticket reconciliation target, not a lifecycle transition.
Before implementation, update exact affected acceptance/dependencies/files scope and retain old
clauses as history. The current T218/T223 episode and formal review counts do not reset. Existing
source findings are not accepted. No new ticket IDs or worktrees are required for this amendment.


- **T209 A1/A5/A6/A8; A2 source regression**
  T209 source hardening; artifact adapter prerequisite only where actually consumed

- **T209 A3 daemon scope, A4 constitutional reading, A9 decision wording**
  T209 retains reserved maintainer decisions; this design does not choose them

- **A2-live and complete A7 native matrix**
  T220 after T223 source and platform/host authority; keep full T162 and separate A2 receipt

- **T218 readiness, witness/deadlines, exact private candidate**
  T218 after common artifact/admission capability, not after all T220 live completion

- **Common artifact/admission source interface**
  T223 after exact acceptance/scope reconciliation; source fakes cannot close backend/native rows

- **T034f component onion/egress measurement**
  T034f after T218 and common runtime capability; original same-run controls unchanged

- **T202 wider scenarios; T212 cadence/history/CI/DNS; T215 executor drain/cache ownership**
  Existing owners, separate feasible venue/evidence; no blanket retirement

- **T077 first-time-human walkthrough and T080 sweep**
  Direct T220/native and other actual prerequisites retained; T200 profile repair before final
  measurement

- **T034a 600-second DNS**
  Reviewed profile/analyzer/safe venue and actual browser capability; Alpha-only allowed with
  disclosure

A source-artifact component is a capability dependency, not proof that every live T209/T220 row is
complete. Avoid creating a T218->T220-live->T218 cycle. Keep installation/native observation windows
serial and avoid installing a persistent stack before qualification that requires an empty baseline.
Disjoint T200/T201 product source work can remain independent once separately authorized.

## DQ7. Constitution and completion checks

I/II: application bytes remain opaque; valid DP routing survives CP outage. III: no new runtime
public egress, telemetry or traffic journal; test helpers retain disclosed residual privilege.
IV/VI: prepared bytes bind reviewed source and exact input/tool identities; signed release remains
unchanged. V: required targets/source evidence/platform/native/human results stay separate; Alpha
results do not imply stable support. VII: genuine real-consumer RED/fix/GREEN for new source; pure
normative changes use consistency and independent adversarial review. VIII: exact independent
review, preserved failures and external human release gate remain. No Constitution exception.

Documentation completion does not mean implementation/native readiness. Unqualified platform
separation, image load/resolution, runtime settlement, quota/durability and healthy timing remain
explicit execution prerequisites. Reserved T209 policy choices remain human decisions. This design
is sufficiently scoped for preparing exact source plans and fixtures; it cannot authorize a native
positive path or claim all original tickets runnable. Revisit only the contradicted boundary if a
specific capability check fails; do not restart broad model consultation or invent successor chains.
