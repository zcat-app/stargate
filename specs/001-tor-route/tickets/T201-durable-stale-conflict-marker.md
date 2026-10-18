---
id: T201
title: 'Durable STALE_CONFLICT marker: no changed push until recovery'
status: in-review
created: 2026-10-03
last_updated: 2026-10-18
source: "T155 attempt 4 cumulative redteam (index tree 6e70e622): area 2 m3, survived falsification as Minor (E4: real TokenLoader against a model of the DP reload rule); maintainer chose the durable marker over disclosure, 2026-10-03"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 20  # exact refined candidate union:
                  # control-plane/core/src/main/java/app/zcat/stargate/auth/TokenLoaderContract.java,
                  # control-plane/core/src/main/java/app/zcat/stargate/auth/TokenLoader.java,
                  # control-plane/core/src/test/java/app/zcat/stargate/auth/TokenLoaderTest.java,
                  # control-plane/persistence/src/main/java/app/zcat/stargate/persistence/SqliteTokenState.java,
                  # control-plane/persistence/src/main/resources/db/migration/V003__durable_auth_delivery.sql,
                  # control-plane/persistence/src/test/java/app/zcat/stargate/persistence/SqliteTokenStateTest.java,
                  # control-plane/runtime/src/main/java/app/zcat/stargate/runtime/GrpcReloadChannel.java,
                  # control-plane/runtime/src/main/java/app/zcat/stargate/runtime/StargateControlPlane.java,
                  # control-plane/runtime/src/test/java/app/zcat/stargate/runtime/StargateControlPlaneTest.java,
                  # control-plane/runtime/src/test/java/app/zcat/stargate/runtime/PeerVersionStartupTest.java,
                  # specs/001-tor-route/data-model.md, specs/001-tor-route/quickstart.md,
                  # specs/000-architecture/spec.md, specs/001-tor-route/contracts/control-grpc.md,
                  # THREAT-MODEL.md, scripts/subcommands/status,
                  # specs/001-tor-route/tickets/T201-durable-stale-conflict-marker.md,
                  # specs/001-tor-route/STATUS.md, specs/001-tor-route/evidence/T201-tests-first.json,
                  # specs/001-tor-route/evidence/T201-recovery-decision-draft-v2.md
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "II: Plane Separation"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: high
risk: medium
round_cap: 3
spec_refs:
  - specs/001-tor-route/data-model.md
  - specs/001-tor-route/contracts/control-grpc.md
  - specs/001-tor-route/quickstart.md
decision_refs: []
reviews: {}
overrides:
  - date: "2026-10-18"
    by: user
    decision: "Affected-part tests only for T201; omit scripts/verify.sh and unrelated suites."
    reason: "The maintainer's fresh-session prompt explicitly directs affected-part tests only and says not to launch the full verify suite or unrelated suites. This records a verification-scope override only; no acceptance, privacy, security, or native requirement is waived."
aborted_attempts: [{ date: 2026-10-18, round: 2, reason: "run-task --reset", history: target/runs/T201.review-history }]
reopens: []
redteam_findings: []
clarity_check: {}
---

# T201: Durable STALE_CONFLICT marker: no changed push until recovery

## Context

`STALE_CONFLICT` is terminal only for the running CP process: `GrpcReloadChannel.recordStale`
keeps it in memory, and data-model §1.8 "Read" lets changed `tokens.yaml` content propose
`generation + 1` with no conflict condition. After the CP state is restored from an older
backup and the DP refuses its generation as stale, each further changed `tokens.yaml` load
plus CP restart reserves the next generation. Enough of them overtake the DP's generation and
are accepted, carrying any credential the restored file still lists. Falsification ran this
with the real `TokenLoader` against a model of the DP reload rule (`server.go:114-121`): three
changed loads after a restore from a backup two generations old re-authorized a revoked token,
without the explicit rollback procedure. Each step is an operator edit and each refused step
shows `STALE_CONFLICT`, so this is not an automatic promotion (Constitution II), but it defeats
T159's must-hold ("the CP never promotes rejected stale credential content to a newer
generation") and the quickstart and THREAT-MODEL §5.15 do not warn about it.

## Analysis

- Must hold: once the DP refuses a candidate as stale, the CP durably records the conflict and
  makes no `ReloadTokens` push of changed content, and none can be accepted, until the
  documented stale-conflict recovery clears the marker; restarts do not clear it.
- Gated: CP unit tests (TokenLoader, GrpcReloadChannel), persistence migration test.
- Residue: host/root rollback of all trusted state stays outside the guarantee (Constitution II).

## Acceptance

1. **Tests first through real consumers.** Before production repairs, write the discriminating
   real SQLite/JTA/bootstrap/Go-UDS stale-revival regression in the existing
   `T159ProductionAuthorityRecoveryTest`: DP generation 2 excludes the synthetic credential;
   restored CP generation 1 retains it; the actual stale reply is observed; after CP recreation
   against the same DB and at least four distinct changed YAML inputs retaining that credential,
   assert there is no later reload/application, generation or row promotion, and DP continues to
   refuse the credential. Record the genuine current-code RED and identical GREEN with
   `scripts/test-first-evidence.py`; setup/compiler/tool failures are not behavioral RED.
   Write real Flyway/SQLite state-schema tests before V003/adapter changes, and status CLI
   regression assertions in the existing status test before changing its script. Preserve each
   actual result and do not fabricate chronology.
2. Before parsing YAML, minting credentials, reserving generations, mutating rows or pushing,
   read a required durable auth-delivery state. A persisted `STALE` blocks all token loads and
   reconstructs the existing `STALE_CONFLICT` status; unreadable state refuses delivery without
   claiming known stale. A CP restarted with `UNRESOLVED` also makes no token push until explicit
   offline recovery; the previous process may have received a stale reply before persisting it.
   No changed YAML, restart, timeout, transport success, reconnect or ordinary edit clears either
   gate.
3. Persist only one current `CLEAR`/`UNRESOLVED`/`STALE` state with its associated generation in
   SQLite. Prearm `UNRESOLVED(G)` durably before each actual initial, same-process retry or
   authenticated reconnect RPC for the complete durable candidate. Prearm failure/ambiguity means
   no dispatch. Only an authenticated exact generation-and-commitment acknowledgment followed
   by a committed conditional clear may clear `UNRESOLVED(G)`; legacy/wrong-generation/wrong-
   commitment replies and transport/version errors cannot. Stale immediately stops in-process
   delivery, discards queued work, and persists `STALE(G)`. If that write fails, the prior durable
   unresolved state remains the restart barrier and the current process stays stopped. `STALE`
   is absorbing until explicit recovery; stale or older/delayed acknowledgments cannot clear a
   newer state. Preserve generation reservation before credential-row commit and never arm an
   incomplete candidate. No generic history, token copies, timestamps, default no-op store
   methods or DP/wire changes.
4. Recovery option 1 restores known matching newer CP state; if that state retains a gate, clear
   it explicitly. Option 2 requires the operator to stop both planes, select and preserve the
   intended CP credentials/configuration, move the DP snapshot aside, then explicitly clear only
   the CP delivery gate before normal reseeding. Document a literal bounded Python3 `sqlite3`
   snippet in quickstart only: fixed existing DB, `mode=rw`, V003 schema/singleton validation,
   explicit rollback confirmation, bounded busy/process/output handling, one marker-only
   transaction, and writes as the existing DB owner. Test the literal snippet against private
   synthetic SQLite databases; do not run it on deployed state. Native root/chroot/UID transition
   behavior remains NOT RUN unless separately authorized and actually exercised.
5. Keep the existing status vocabulary and exit behavior. `PENDING` means unresolved delivery,
   including restart inhibition; it does not establish whether DP installed credentials.
   `ACKNOWLEDGED` requires exact ACK plus durable local clear. `STALE_CONFLICT` means recorded
   stale refusal. Preserve unknown/unavailable semantics and do not expose history, labels,
   timestamps or secret content. `scripts/stargate status` must say
   `token delivery: PENDING (delivery is unresolved; credential application and revocation are not confirmed)`
   and, when CP is down,
   `control plane: not running (token delivery state unavailable; the data plane routes using its existing valid credential state)`.
   It must not claim revocations are “NOT effective yet” or that DP has its last acknowledged
   state. Existing `StargateControlPlaneTest.statusCommandPrintsValidatedStatesAndRefusesUnreadableState`
   exercises the CLI through its Docker stub.
6. Update data-model §1.8, control-grpc contract, architecture §5.2/§6.7, quickstart recovery,
   `scripts/subcommands/status`, and THREAT-MODEL §5.15 to match the approved policy. Preserve
   healthy acknowledged startup replay, same-process retry and acknowledged-peer recovery.
   Correct the overclaim that DP admission waits for CP to observe ACK: DP installs before
   returning the ACK, so a lost response can leave CP pending while DP already admits the set.
   Do not describe automatic restart replay of ambiguous `UNRESOLVED` state or DP-current-based
   generation renumbering. Apply only the exact THREAT-MODEL wording approved in the byte-pinned
   artifact `specs/001-tor-route/evidence/T201-recovery-decision-draft-v2.md` (SHA-256
   `bde30ee9b2d0b8881bf22aa68d3fa3d8b74a46b3c3e5d1ac360a06aa678fd2f6`), including its
   correction of the equivalent surrounding ACK/admission statement. No additional policy
   expansion is authorized.
7. Exact 20-path source union: `TokenLoaderContract.java`, `TokenLoader.java`, and
   `TokenLoaderTest.java` under `control-plane/core`; `SqliteTokenState.java`,
   `V003__durable_auth_delivery.sql`, and `SqliteTokenStateTest.java` under
   `control-plane/persistence`; `GrpcReloadChannel.java`, `StargateControlPlane.java`,
   `StargateControlPlaneTest.java`, and `PeerVersionStartupTest.java` under
   `control-plane/runtime`; `specs/001-tor-route/data-model.md`,
   `specs/001-tor-route/quickstart.md`, `specs/000-architecture/spec.md`,
   `specs/001-tor-route/contracts/control-grpc.md`, `THREAT-MODEL.md`,
   `scripts/subcommands/status`, this ticket, `specs/001-tor-route/STATUS.md`, and
   `specs/001-tor-route/evidence/T201-tests-first.json`, and the approved byte-pinned
   `specs/001-tor-route/evidence/T201-recovery-decision-draft-v2.md`. T190 overlaps loader/tests and
   data-model/quickstart; serialize shared hunks and reconcile against its final source. No
   `tasks.md` edit: the selected actual tasks file has no T201 owner checkbox.
8. Run only the approved affected Maven selector from `control-plane`:
   `./mvnw -B -pl runtime -am -Dtest=TokenLoaderTest,SqliteTokenStateTest,StargateControlPlaneTest,T159ProductionAuthorityRecoveryTest,PeerVersionStartupTest -Dsurefire.failIfNoSpecifiedTests=false test`.
   Capture the same command for RED/GREEN through the approved bounded wrapper/evidence path;
   do not impose `RLIMIT_FSIZE` on Maven/Go/Java or run full verification, Docker, deployed
   recovery, privileged operations or native qualification. Keep original retry/backoff and
   fixture deadlines, and describe scoped tests as source evidence only.

9. **Refined concurrency regression and completion ordering.** The initial push's
   exact-ACK path must not clear or overwrite a replay admitted by an authenticated
   reconnect after the initial durable ACK-clear commits. Add a deterministic test
   in `StargateControlPlaneTest` that holds the initial completion at the boundary
   between its committed `UNRESOLVED(G) -> CLEAR` and queue/status bookkeeping,
   admits a reconnect replay of the same generation, and then releases the older
   completion. The replay must remain queued and status must remain `PENDING` while
   its RPC is held; the CLI remains exit 30. Return a non-stale delivery failure,
   then allow the replay's exact ACK and committed clear; assert the queue drains,
   status becomes `ACKNOWLEDGED(G)` only then, CLI exits 0, and SQLite is `CLEAR(G)`.
   The test must fail against the pre-fix implementation and pass against the fix.
   Fix by making the complete initial completion bookkeeping atomic with replay
   admission, or by identifying attempts so an older completion cannot mutate a
   newer one. Preserve authenticated reconnect, normal retry/backoff, stale-stop
   semantics, and the approved unresolved-restart recovery policy. Do not add a
   timing sleep as the synchronization point; any test seam must remain
   package-private/test-only in effect, bounded, and inert in production. No
   DP/wire contract, generation rule, or recovery-policy expansion; stay within
   the exact 20-path files_budget.
10. **Before-clear attempt ordering.** In addition to the after-clear case above,
    pause an older initial exact-ACK completion immediately before its durable
    `UNRESOLVED(G) -> CLEAR` transaction. Admit an authenticated reconnect replay
    of the same generation and wait for its SQLite `UNRESOLVED(G)` prearm and
    held RPC before releasing the older completion. The older attempt must leave
    SQLite `UNRESOLVED(G)`, status `PENDING`, and CLI exit 30. Return a stale
    refusal from the held replay and prove SQLite `STALE(G)` persists. Restart
    through production bootstrap with changed YAML and assert no reload RPC,
    generation reservation, or credential-row mutation. A deterministic
    package-private seam may pause before the clear; it must be inert in
    production and bounded in the test.
11. **Reconnect prearm failure truthfulness.** From `ACKNOWLEDGED(G)`, inject a
    reconnect `prearmDelivery` storage failure. Publish `PENDING` synchronously
    at authenticated reconnect admission before the fallible prearm; prove no
    RPC is sent and the actual CLI no longer reports `ACKNOWLEDGED` or exits 0.
    Restore storage and prove an exact replay ACK plus durable clear returns
    `ACKNOWLEDGED(G)` and CLI exit 0. Prearm failure remains fail-closed.
12. Keep `contracts/control-grpc.md` explicit-rollback wording synchronized
    with retained CP `STALE`/`UNRESOLVED` gates: ordinary restart, reconnect, or
    file edits do not clear a gate; the documented operator-confirmed offline
    recovery clears it before normal reseeding, and the CP remains `PENDING`
    until exact authenticated ACK plus committed local clear. Pin the approved
    wording artifact at the Acceptance 6 path and verify its exact SHA-256.

## Approved recovery decision

The maintainer's conditional instruction “Re-review; proceed if approved” was applied to the
exact v2 recovery decision; the independent review returned APPROVE. This selects explicit
offline recovery for any CP restart inheriting unresolved delivery, including the ambiguity
where a stale reply may have arrived before a failed/unwritten stale marker and the DP later
loses its newer authority. The tradeoff is loss of automatic unresolved-candidate replay across
CP restart. It does not change DP reload/admission rules or exclude ordinary missing/corrupt DP
snapshot recovery. See `T201-recovery-decision-astra-r2.md`; review of this source candidate is
still required separately.

## Review refinement disposition — 2026-10-18

The round-2 Astra ESCALATE identified a source-established race between initial ACK completion
and authenticated reconnect replay admission; it was not a local execution limitation or a
recovery-wording disagreement. The maintainer directed resolution. Refine Acceptance 9 to name
the exact interleaving and terminal-state assertions before restarting the bounded review loop.
Both round-2 reports and the root finding verification remain preserved in the review history;
the approved restart-recovery policy above is unchanged. The original 12-path budget omitted
seven supporting architecture, contract, wiring, status, and test paths that were already part
of the reviewed candidate; the refined budget now names the exact 19-path union. This correction
adds no paths to that candidate.

## Out-of-scope

The DP's reload rule; DB-wipe recovery (T159); generation exhaustion by a compromised CP.


## Maintainer-directed round-3 continuation — 2026-10-18

The maintainer directed reevaluation of T189/T200/T201 against all failed
reviews and resolution accordingly. T201's preserved history contains four
completed paired sets: original round 1 (`13c29320…`, GLM APPROVE/Astra REWORK),
original round 2 (`c8921114…`, GLM APPROVE/Astra ESCALATE on the ACK/reconnect
race), the recorded 2026-10-18 09:05 reset, post-reset round 1
(`c27f6d93…`, GLM APPROVE/Astra REWORK on the reconnect findings), and
post-reset round 2 (`65654f1c…`, GLM APPROVE/Astra REWORK on the literal
`UNKNOWN` exit-60 mismatch). The reconnect race was repaired and re-reviewed
in the later paired sets. This bounded continuation targets only the latest
remaining `UNKNOWN` finding. Its round counter 3 is the third review in the
post-reset sequence and the fifth paired set overall. The continuation
interpretation was independently assessed as reasonable; it changes no
acceptance, waives no requirement, authorizes no reset and permits no fourth
post-reset review. The original start SHA, all four paired sets, reset record,
round-1/2 reports, and prior RED/GREEN records remain unchanged.

The high-complexity classification reflects this ticket's 20-path durable
control-plane delivery-state change: SQLite migrations and transactions,
asynchronous reconnect/retry ordering, exact-ACK completion, restart recovery,
and deterministic concurrency regressions. It is grounded in the ticket's
existing implementation scope and not assigned solely to obtain a third
review round. The review-loop cap of three applies to this explicitly
high-complexity ticket.
