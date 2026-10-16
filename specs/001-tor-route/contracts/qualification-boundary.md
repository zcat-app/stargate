<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Qualification boundary — required target, 2026-10-16

This contract governs T218 readiness and the T220 native Local qualification window. It changes
qualification architecture, not deployed routing. It is a required implementation target, not a
claim of installed capability, current-source compliance or permission to execute native work.
Constitution I–VIII and the foundation boundary contract remain authoritative.

## Q1. Scope, authority and evidence

Build/source evidence, platform capability, native measurement and human usability are separate
claims. A source gate must exercise real supported entrypoints with controlled external effects;
a fake daemon result proves source behavior only. A native gate requires the actual pinned
platform and every named scenario/control. Neither can substitute for the other.

Changing these documents does not reopen an exhausted episode, reset a review count, accept failed
source or grant host/Docker/policy/capture authority. Existing T222 chronology acceptance remains
finite; NONCOMPLIANT history, failures, rejected candidates and authentic RED/GREEN stay preserved.
Missing tooling, imports, compiler output, invalid fixtures or unreachable assertions are setup
failures, never behavioral RED. Establish absent executable consumers in tests-first slices before
claiming later safety behavior through them. Correct existing refusal receives retrospective
coverage and must not be weakened to manufacture RED.

## Q2. Separate artifact production from runtime authority

The artifact producer must lack credentials, sockets, policy access and writable channels capable
of mutating the runtime venue or its admitted inputs. Moving a build earlier on the same daemon,
a private tag, or a separate process does not establish this boundary. A shared physical host is
not excluded categorically, but its actual capability separation must be demonstrated; otherwise
use an already authorized suitable build venue. A VM is not selected for convenience.

The producer exports a finite manifest-bound closure: all runtime and helper images, every A2
variant, precompiled test/probe binaries, scripts and interpreters/tools actually executed. Bind
reviewed source bytes and executable modes including declared overlays/untracked inputs, toolchain
and dependency identities, platform, exact artifact identities, archive sizes and allowed members.
HEAD alone or a newly observed hash cannot replace independently expected reviewed identities.

The consumer validates the complete closure before import, rejects foreign/shared tag bindings,
path traversal and extra members, copies it to runtime-owned non-writable inputs, and revalidates.
It validates archive image/layer/config identity separately from registry manifest identity.
Loading artifacts mutates the runtime and is covered by Q3/Q5 before its first request. After
imports, no image load/import, build, pull, compilation or dependency retrieval is admitted in
the workload window. Every nested init, observer, T162, Tor suite, helper, recovery and A2 caller
must consume the same closure or refuse before dispatch. No-build/no-pull configuration is
necessary but does not alone prove the absence of other producer paths.

Internal candidate artifacts cannot masquerade as a signed release. Preserve the existing signed
release verifier, exact-source/tag/clean-tree checks and operator promotion rules unchanged.
Source-mode install/rebuild remains a separate required claim; artifact consumption cannot pass it.

## Q3. One exclusion domain, including imports and later candidates

All supported operations that can affect the same host policy, UID/process boundary or runtime
manager must share one enrolled exclusion domain, independent of checkout, run directory, project
name, environment variables and new candidate IDs. Overlapping scopes cannot be enrolled as
independent domains. The existing pinned-home reservation/enrollment anchor is retained; it must
be extended/reconciled as the common admission authority, not paired with a competing T220 gate.

The domain binds the actual host boot/kernel context, runtime endpoint/identity, affected policy
and UIDs, authority-pinned canonical state/evidence roots and lock identity. A changed boot or daemon
identity is not evidence that old work finished. Missing, stale, corrupt, replaced or unreadable
state refuses; supported live code never recreates it or selects a fresh root to bypass it.
This is cooperative trusted-maintainer/single-UID coordination, not protection from malicious root,
uncooperative privileged users or a malicious same-UID process.

Before the first import or other external mutation, acquire the stable lock, reread current
authority/enrollment/state, reserve the complete resource/evidence envelope and durably commit the
run's pending ownership. Release of a lock is not settlement. Commit failure or uncertain durability
prevents dispatch. Record each external operation's exact intent/identity before submission and
its acknowledged result or uncertainty afterward. Import requests are not exempt.

There is one canonical admission state for the domain. Phase-local effect records reference that
state; they cannot independently authorize, clear pending or override an unresolved prior effect.
Only the designated current phase owner settles its recorded effects. Phase transfer requires
verified completion of the prior phase and explicit bound handoff; simultaneous cleanup owners,
background finalizers and automatic human attestations are prohibited.

## Q4. One authorization and one attempt per candidate

A candidate lifecycle has one immutable source/authority identity, one explicit authorization and
at most one effectful attempt. Once any effectful attempt starts, successful reuse, retry and
source/authority replacement inside that lifecycle refuse. Administrative writer revisions before
another attempt and quota-image bridges are not supported operations in this new lifecycle.
This removes those operations, not their underlying safety properties.

The same exclusion domain survives candidate changes. A next candidate requires the trusted
maintainer's deliberate per-operation decision after personally observing successful completion
of all required original owner AND observer commands and reviewing exact retained evidence.
A visible receipt, settled bytes, PID absence or successful publication cannot certify the
publisher subsequently finished. The decision binds the actual previous candidate/authority,
settlement and observer outcomes, the next candidate/source/operation and current domain state.
The independently expected previous identities stay historical; never replace them with new hashes.

The first candidate requires completed bootstrap and authorization observations. Later candidates
require the last completed candidate plus the new authorization observation; no reference may
assert completion of its own still-running command. Checks remain bounded to selected immediate
predecessor/bootstrap/authorization records, without recursive archive search. Concurrent or stale
decisions refuse under the stable lock. The existing literal, bounded, closed manual carrier and
native-versus-fixture separation remain required; its new schema must distinguish candidate
handoff from forbidden same-candidate reuse. No unattended generator may supply native decisions.

Failed/unknown/late owner, observer or writer completion forbids a next-candidate decision and
keeps the domain blocked. A fresh directory, another checkout, tag, UID alias or daemon restart
cannot bypass this. There is no automatic recovery path in this contract.

## Q5. External effects, deadlines and quarantine

Client exit, canceled context, process-group absence, quiet inventory, container terminal state,
image equality and generic daemon restart are not general external-request settlement oracles.
Use a supported predicate for the exact pinned backend/operation and correlate the exact request,
object generation and result. Missing or lost responses remain uncertain even with empty inventory.
A finite experiment can falsify a predicate; one passing trial cannot prove a universal join.

Separate timely refusal, active-owner completion, actual external-effect settlement and healthy
success within a cap. Carry the original absolute deadlines through every actual operation; no
fresh nested budget or detached helper extends them. Preserve the existing six bounded witness
frames/ACKs, DI35/DN20/G40, D120/A15/B33/C24/D35/E8 and cumulative E3/E5 accounting, launch/output
limits and native controls until an exact reviewed protection mapping changes them. Build work
moved outside runtime authority is separately measured/accounted, never silently counted as free.
Healthy timing remains a platform/live measurement. No physical interruption of an already
admitted blocking syscall or cleanup after sole-owner death is promised.

On uncertain effects, preserve pending state, evidence and necessary enforcement. A command may
publish provisional settled bytes and then fail during close/output/observer completion. Those
bytes do not grant admission: missing successful original-command observation forbids a truthful
manual handoff. Do not require a dead owner to rewrite pending or manufacture historical completion.
Removing enforcement requires proof that every relevant effect/request/descendant is settled, exact owned cleanup and
baseline restoration. A trusted observer disappearing leaves no PASS. Scenario results, cleanup
state, process/observer outcomes and next-admission eligibility are distinct fields; overall PASS
requires every mandatory component, not just useful measurement or cleanup.

A lost-response experiment is permitted only in a separately approved venue whose quarantine or
supported terminal procedure is acceptable. On an unqualified shared host, do not inject the fault.
Stopping a daemon plus inventory, reboot and destruction of a disposable guest are unqualified
recovery candidates, not approved commands or automatic reset rules. Qualifying one requires exact
runtime boundaries and retained external proof; deleting a disk alone does not prove execution
stopped. Until qualified, uncertainty leaves that domain unavailable. A separate venue must have
no channel to the blocked domain; it cannot erase the blocked record.

## Q6. Bounded persistent evidence

Keep authority, pending state and immutable evidence outside active effects/disposable workspace.
Retain the pinned state/evidence paths, no-follow access, UID/mode/device/inode/link validation and
original held-directory identity. Preserve original outputs, receipts, proof and settled bytes;
substituting an empty same-path directory or rewriting old evidence refuses.

Capacity has both per-candidate bounds and cumulative domain byte/file/inode ceilings. Precharge
all producer, observer, writer, temporary replacement and coexisting artifact envelopes before
those producers can write. Charges are monotonic across candidates; a new candidate cannot refund
or reset them. Bootstrap/authorization growth counts too. Producers enforce their declared maxima;
source counters alone do not qualify filesystem enforcement. Exhaustion refuses before effects,
without arbitrary attempt-count limits, deletion, pruning or automatic archive reclamation.

The implementation plan must bind closed schemas, exact producer census, numerical maxima and
overflow-safe aggregate arithmetic before the corresponding tests/implementation. Existing native
caps do not increase. Platform quota/durability behavior belongs to platform qualification, not a
source-only PASS. Export/reclamation or uncertain-state repair requires a separately reviewed policy.

## Q7. Qualification sequence and retained coverage

First record a finite platform protocol using existing tools/commands: actual build/runtime venue
identities and separation, pinned fixture, command/resource limits, normal acknowledged lifecycle,
source/artifact identity and safe quarantine disposition. Do not require the unimplemented internal
candidate mode as a precondition for this platform-only observation. Its result is not evidence of
project-consumer behavior. No benchmark framework or replacement runner is required.

Next establish the smallest real project consumer using spec-derived behavioral RED before each
new behavior, then identical GREEN and affected regressions. Exact-source review covers all actual
writers and nested consumers. Native/live qualification follows only when source, platform and
separate authority gates are satisfied. A safe refusal cannot pass a missing healthy path.

T218 readiness remains distinct from T034f onion/egress acceptance. Pre-init UID/socket and artifact
checks differ from post-init production-DP identity/enforcing-label checks. Neither SOCKS negotiation
nor a private readiness candidate proves routed application traffic. Canonical readiness publication
requires exact source plus external post-exit receipt review and successful command observation.

T209 retains source hardening A1/A5/A6/A8, source portions of A2, and A3/A4/A9 decisions/obligations.
T220 owns the migrated A2-live/A7 native matrix. Every original row needs an explicit retained owner;
T077 and every closure consumer must retain a direct native-qualification dependency after the split.
This contract does not change ticket statuses or make a conflicting old ticket runnable. Reconcile
its exact acceptance/dependencies/files scope before source dispatch; preserve all counters/history.

T202 broader scenario/venue work, T212 full compile/race/vet/scanner/cadence/history/CI and privileged
DNS complement, and T215 executor ownership/drain/cache isolation remain distinct obligations.
No blanket retirement follows from artifact mode. Source install/rebuild and artifact-only runtime
have separate rows and cannot certify one another. T223 is the existing source-adapter owner after
its old in-window BuildKit-join target and scope are explicitly reconciled. No partial source batch
is represented as completion of its still-conflicting old acceptance.

## Q8. Observation and product boundaries

Maintain separate claims for browser SC-003 DNS, namespace/component egress and native qualification.
SC-003 needs the full 600-second successful-load/capture/control interval; missing analyzer/venue or
post-browser observations cannot be waived. Use the pinned analyzer until an independent equivalence
experiment supports a reviewed replacement. No unrelated-user capture is authorized by a conservative
zero-match predicate. T034a/T077 may use a pinned qualifying Alpha build with explicit disclosure;
stable Gecko153/MV2 remains a v1 release gate, not a blanket prerequisite for those Alpha-only rows.

SC-002's ancillary 95/100 count does not establish no sharing between full device/profile/site
partitions. Required evidence must distinguish same-target partition forwarding and cross-partition
circuit separation, plus a control that would detect credential fusion. Same-partition reuse is
permitted, not guaranteed. Preserve historic corpus results as sidecar-only ancillary evidence.

Feature001 is the Local Tor preview. Full admin monitoring, other routes and completed-v1 deployment
support remain product obligations. Admin monitoring uses finite current lifecycle states and
completed immutable hourly aggregates; it cannot expose browsing histories or current-hour traffic.
CP outage must preserve valid DP forwarding. T200/T201 product repairs remain independent; the final
browser measurement uses the final reviewed profile. Human walkthrough and release review remain
human obligations. T078/T079 execution is not authorized by this document change.
