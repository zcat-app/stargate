---
id: T041
title: 'Implement `control-plane/runtime/src/main/java/.../StargateControlPlan'
status: done
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T041
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T089, T092, T093, T035, T038, T039]
parallel: false
files_budget: 8   # counted set: 9 at /start → 11 final (the two jandex poms; see §Analysis "Counted set"); specs/ regen exempt per T039 r2 precedent
privacy_critical: true
complexity: low   # confirmed at /start 2026-09-06: straight-line wiring of landed collaborators; the behaviors are already pinned by T035a/T093 suites
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/tasks.md#T041 (verbatim task body; torrc step removed by T089)
  - specs/001-tor-route/spec.md §FR-017 (tokens.yaml path/format; plaintext never persists)
  - specs/001-tor-route/spec.md §FR-018 (startup-only load; failure ⇒ no ReloadTokens; explicit `tokens: []` = sole revoke-all)
  - specs/001-tor-route/data-model.md §1.5 (HMAC-SHA-256 verifier), §1.6 (entity invariants), §1.7 (pepper.key), §1.8 (token_generation), §1.9 (configured_tokens)
  - specs/001-tor-route/data-model.md §2 (events advisory), §4 (audit vocabulary)
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens" (incl. T092 reconciliation fields) + §"WatchEvents"
  - specs/000-architecture/spec.md §6.6/§6.7 (schema), §5.4 (UDS-only inter-plane); plan.md (CP DB at /var/lib/stargate/control.db)
decision_refs:
  - T089 amendment (static slice bakes torrc at build time; the render step is REMOVED from this sequence)
  - T092 amendment (a: pepper→minter wiring; b: pepper never logged/persisted/pushed; c: seed/migrate token_generation + configured_tokens on start = Flyway migrate-at-start)
  - T035 §Analysis (production adapters + the FR-017-path/pepper-file wiring are THIS ticket's; loader is path/pepper-agnostic)
  - T035a pinned TokenLoader surface (constructor order; one no-arg load())
  - T038 (StargateControlPlane is the production caller of ReloadTokensClient; ControlGrpcService.startServer's production invocation)
  - T039 §Analysis (T041 adapts SidecarMonitor.EventSink → ControlGrpcService.publish and supplies the §1.8 generation LongSupplier)
  - T093 landing notes (#3 decomposed: CP-side proposal rule + failure-semantics already pinned; this ticket consumes)
  - T040 §Out-of-scope (quarkus-maven-plugin activation in runtime/ + application.properties = T041)
reviews: { round: 2, date: 2026-09-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T041: Implement `control-plane/runtime/src/main/java/.../StargateControlPlan

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/runtime/src/main/java/.../StargateControlPlane.java` (`@QuarkusMain`) — wires the startup sequence: render `torrc` (T037) → start `SidecarMonitor` (T039) → load `tokens.yaml` (T035) → push `ReloadTokens` (T038); on missing/empty token file, log warning and proceed with empty list per FR-018.

**Refined by T089 (spec-amend).** T089 amended FR-011 so the static
Tor-only slice bakes the safe `torrc` into the Tor image at build time
(T087) and the control plane does NOT render `torrc` at boot
(Constitution Principle II / sol-review B2). The **"render `torrc`
(T037)" step is removed from the startup sequence**; T037 is deferred
(`deferred_reason: spec-amend`, `deferred_on: T089`). The v1 startup
sequence is: start `SidecarMonitor` (T039) → load `tokens.yaml` (T035)
→ push `ReloadTokens` (T038); on missing/empty token file, log warning
and proceed with empty list per FR-018. The CP no longer writes to
`stargate-tor-config` in this slice.

## Analysis

Required (`privacy_critical: true`) — full property map. Grounded 2026-09-06
against the landed collaborators this ticket wires: `TokenLoader` (T035 —
names T041 as the `load()` caller; "production wiring reads the FR-017 fixed
path and the §1.7 pepper file and injects both"), `TokenLoaderContract`
(T035a — ports only), `SidecarMonitor` (T039 — names T041 as the
`EventSink`→`ControlGrpcService.publish` adapter and the generation
`LongSupplier` supplier), `ControlGrpcService` + `ReloadTokensClient` (T038
— StargateControlPlane is the production caller), `AuditLogService` (T036 —
the production `AuditSink` bean, `@Transactional(REQUIRED)` so it joins an
enclosing store transaction), `V001__init.sql` (§6.6/§6.7 tables exist),
`events.proto` (SidecarEvent shape), `control-grpc.md` §"ReloadTokens"
(T092 reconciliation fields). Module DAG verified: runtime aggregates
api/core/persistence/ui; persistence→core exists (T036); CDI beans across
reactor siblings are the standard multi-module Quarkus discovery path.

**Retired body wording.** The verbatim body's "on missing/empty token file,
log warning and proceed with empty list per FR-018" is SUPERSEDED by the
T092 contract (same treatment as T035 §Analysis): a missing/unreadable/
invalid/unparseable file makes the wiring log a warning and NOT call
`ReloadTokens` at all — the DP keeps its last-known list (Principle II).
Only a successfully-parsed explicit `tokens: []` pushes the empty
(revoke-all) generation. T089 already removed the body's render-torrc step.

**Counted set (11 files; budget 8).** T092 amendment (c) (seed/migrate
`token_generation` + `configured_tokens` on start) pulls the JPA store
adapters + entity into this ticket — without them no token push can
happen. Counted: `HmacVerifierMinter.java` (core/auth), `ConfiguredToken.java`
(persistence entity), `SqliteTokenState.java` (persistence),
`StargateControlPlane.java` + `GrpcReloadChannel.java` (runtime),
`runtime/src/main/resources/application.properties`, `runtime/pom.xml`
(quarkus-maven-plugin activation + test deps), `persistence/pom.xml` +
`ui/pom.xml` (Jandex index — see the discovery finding below), and the two
tests-first suites. Every counted file traces to an acceptance item or to
a defect the verify run exposed in this ticket's own wiring; specs/ regen
is exempt (T039 r2 precedent).

### Property map

- **Must hold**
  - **Startup order (body + T089).** Bind the CP `control.sock` server →
    start `SidecarMonitor` → `TokenLoader.load()` (the push happens inside
    `load()`, strictly last per §1.7). NO torrc rendering anywhere
    (T037 deferred via T089; the CP never writes `stargate-tor-config`).
  - **Pepper handling (T092 a/b).** Read `/etc/stargate/keys/pepper.key`;
    edge-validate exactly 32 bytes (§1.7; provisioning is T088's); fail
    fast on missing/short pepper (a CP that cannot mint verifiers cannot
    fulfill its one token function — same fail-fast class as the §2.1
    key-file errors ReloadTokensClient already propagates). The pepper is
    NEVER logged (fail-fast messages name path/length, never bytes), never
    persisted (the CP writes no snapshot), never pushed (only minter
    output crosses `ReloadChannel`; §1.6).
  - **Verifier mint (§1.5).** The production `VerifierMinter` is
    `HMAC-SHA-256(pepper, tokenUtf8)`, 32-byte tag, deterministic,
    does NOT clear or retain the input buffer (the LOADER's mint-then-clear
    is the §1.1 narrowed erasure claim — a clearing minter would make
    TokenLoaderTest's buffer assertion tautological).
  - **Failure ⇒ no push; boot survives (FR-018 + T092 M1).** Missing or
    empty `tokens.yaml`: the wiring logs and continues — the CP comes up
    healthy so the DP keeps serving (Principle II). The real loader never
    throws on file input; the wiring adds NO catch that could mask a
    collaborator's infrastructure failure silently — a broken store at
    load time is contained with a loud error (advisory-plane resilience)
    rather than a crash-loop the operator cannot distinguish from a DP
    outage.
  - **Generation proposal (§1.8).** `lastGeneration()` of the persisted
    singleton; 0 when the row is absent (DB-wipe row); proposal = last+1
    (restarted CP never restarts at 1); `record()` upserts the singleton.
    Stale reconciliation is the loader's, already pinned (T035 note (c)).
  - **Store adapters (§1.9/§6.6/§6.7).** `upsert`/`delete`/diff labels
    within ONE JTA transaction (`UserTransaction`); the loader's audit
    rows are written inside that window and JOIN it via
    `@Transactional(REQUIRED)` — a rollback therefore discards the diff
    rows with the store writes (§4 atomicity). `delete` stamps
    `revoked_at` and removes the label from `storedLabels` (soft delete);
    `created_at` stamped once at first sight.
  - **WatchEvents surface (control-grpc §"WatchEvents"; data-model §2).**
    The monitor's neutral `Event` maps onto `stargate.v1.SidecarEvent`
    (sidecar/kind/detail 1:1, fixed vocabulary; `ts` stamped at emission)
    and fans out through `ControlGrpcService.publish` — advisory only;
    zero live subscribers lose nothing (Principle II).
  - **Push transport containment.** A `ReloadTokens` UNAVAILABLE/deadline
    (DP not up yet — compose has no CP→DP ordering) is contained in the
    channel adapter: warning + non-stale result; the generation is already
    recorded (§1.7 order), the DP keeps its last-known list, and the next
    boot's §1.8 read reconciles. The CP must not crash-loop because the
    DP booted later.
  - **Schema on start (T092 c).** Production `application.properties`
    boots Agroal SQLite at `/var/lib/stargate/control.db` with Flyway
    `migrate-at-start` (V001 lands `configured_tokens` + `token_generation`)
    and Hibernate `database.generation=none` (Flyway owns the schema —
    the T036 test wiring, promoted to production).

**Grounding findings resolved during implementation (all in-ticket):**

1. **Cross-module CDI discovery.** The first runtime `quarkus:build` failed
   with ArC "Unsatisfied dependency" for `AuditLogService`/
   `SqliteTokenState`: a reactor-sibling jar WITHOUT a Jandex index is
   treated as a library and its beans are NOT discovered. Fix: the
   jandex-maven-plugin on `persistence/pom.xml` (beans consumed by the
   runtime boot) and `ui/pom.xml` (`HealthEndpoint`'s `@Observes Router`
   — without the index the compose healthcheck would silently 404 at
   runtime-boot tier).
2. **T022 row-10 wire-gate interaction.** The production-caller probe
   greps the literal `getStatus(` across CP production sources; three
   innocent matches tripped it: the proto enum getter
   (`response.getStatus()`), the JTA `utx.getStatus()`, and a gRPC
   `Status` getter in the channel's catch. Fixed in MY code per the T093
   wire-gate precedent (the coarse FAIL-forcing probe stays): the enum is
   compared via the semantically identical proto3 `…Value`/`…_VALUE`
   accessors (commented why), and the store reads unconditionally open
   their own short JTA transaction (production reads always run outside
   the loader's window: boot thread before `begin()`, monitor poll thread
   via the generation supplier), so no status poll exists.
3. **Two audit ports, one shape.** `SidecarMonitor.AuditSink` (T039) and
   `TokenLoaderContract.AuditSink` (T035a) are distinct, identical-shaped
   ports; the runtime wiring adapts by method reference (`audit::write`).

**Tests-first evidence.** Both suites authored and RED (compile-fail on
the five absent classes) before the implementation landed; driven green
inside this ticket's own verify runs.
- **Gated** (verify.sh catches fail-closed once these land)
  - `StargateControlPlaneTest` (runtime module; plain JUnit — real
    `TokenLoader`/`ControlGrpcService`/`ReloadTokensClient`, fakes for the
    store/audit seams, real UDS bind + real absent-socket): pepper
    fail-fast ×2; missing-file and empty-file boot survival (empty file
    emits exactly one `config_error` validation row, no push); valid-file
    push contents (N×32-byte verifiers == reference HMAC under the pepper,
    ≠ plaintext, ≠ pepper; generation = 1); broken-store boot survival;
    event→proto delivery through the production sink + a registered
    WatchEvents stream; PushResult mapping; transport containment;
    minter known-answer (§1.5).
  - `SqliteTokenStateTest` (persistence module; `@QuarkusTest` on the real
    Agroal/SQLite/Flyway stack — the same wiring the runtime boot relies
    on): port conformance; generation 0-fresh/record/re-read;
    upsert/label-diff/soft-delete with timestamps; audit rows JOIN the
    store transaction (commit persists them; rollback discards).
  - Maven `verify` compiles runtime under the inherited Error Prone +
    NullAway gate (T104); license headers; `lint-ticket.py`.
- **Residue** (no gate catches; scoped for review/redteam)
  - Production config correctness (real `/var/lib/stargate` DB,
    `/run/stargate/*.sock` paths, tor DNS name) is exercised only at
    compose-up — the unit suites bind temp sockets/files. The compose-tier
    runtime gate is T070's.
  - quarkus-grpc's auto-server behavior with zero `@GrpcService` beans (no
    stray TCP 9000 on the CP) is asserted nowhere — a compose-tier TCP
    concern (T022 / `inter_plane_wire_test.sh` runtime tier).
  - "No future code path logs the pepper or a verifier" — the suites pin
    today's messages; future logging discipline is review + redteam
    (THREAT-MODEL §2.8 scopes process-memory attackers out; no zeroing
    claim exists for the pepper itself, which lives for the process).
  - The monitor's real dial (cookie mount, GID 5103 alignment, tor DNS)
    is docker-tier; the unit tier proves the wiring seam only.

## Acceptance

Tests-first (Principle VII: authentication is a mandatory test-first
category — the pepper/verifier wiring): suites authored first, RED
(compile-fail on the absent classes), then the implementation driven green
inside this ticket's own verify run (the T035a established pattern).

1. **Named test `StargateControlPlaneTest`**
   (`control-plane/runtime/src/test/java/app/zcat/stargate/runtime/StargateControlPlaneTest.java`):
   - `missingPepperFailsFast` / `shortPepperFailsFast` — boot aborts on a
     missing / non-32-byte pepper (§1.7; fail-fast, no partial start).
   - `bootsWithoutTokensFile` — missing `tokens.yaml`: boot COMPLETES
     (monitor thread live, `control.sock` bound), NO push, NO audit row
     (first-boot exemption; FR-018 + §1.1/§1.6).
   - `bootsWithEmptyTokensFileAndWritesConfigError` — empty file: boot
     completes, exactly one `config_error` (kind=validation) row, NO push
     (the failure ⇒ no-push rule; only explicit `tokens: []` pushes).
   - `validTokensFilePushesHmacVerifiersUnderPepper` — one valid record:
     the push carries exactly one 32-byte verifier equal to the reference
     `HMAC-SHA-256(pepper, token)`, ≠ plaintext bytes, ≠ pepper bytes;
     generation 1 (persisted 0 + 1).
   - `brokenStoreDoesNotKillBoot` — store seam throwing at `begin()`:
     boot completes (Principle II advisory containment), error logged.
   - `sidecarEventsReachWatchEventsAsMappedProto` — through the production
     event-sink adapter and a registered WatchEvents stream: monitor
     `Event` arrives as `SidecarEvent` with sidecar/kind/detail mapped
     1:1 and a non-null `ts` (fixed vocabulary, data-model §2).
   - `staleAndOkResponsesMapToPushResult` + `transportFailureIsContained`
     — `APPLY_STATUS_STALE_GENERATION`+`current_generation` →
     `PushResult(true, N)`; OK → non-stale; a real `ReloadTokensClient`
     dialing an absent `dp.sock` (UNAVAILABLE) is contained to a non-stale
     result + warning, never thrown.
   - minter known-answer rows (§1.5): deterministic, 32 bytes, input
     buffer left intact (the loader owns the clear).
2. **Named test `SqliteTokenStateTest`**
   (`control-plane/persistence/src/test/java/app/zcat/stargate/persistence/SqliteTokenStateTest.java`,
   `@QuarkusTest`): port conformance (assignability to
   `ConfiguredTokenStore` + `GenerationStore`); `lastGeneration()`==0 on a
   fresh DB and reads back a recorded value; upsert/label-diff round-trip
   (32-byte verifiers, `created_at` stamped once); `delete` stamps
   `revoked_at` and removes the label from `storedLabels`; the audit sink's
   rows written between `begin()`/`commit()` persist, and a `rollback()`
   discards them (the §4 diff-row atomicity the loader relies on).
3. **Startup wiring**: `StargateControlPlane` (`@QuarkusMain` +
   `QuarkusApplication`) executes server-bind → monitor-start →
   `load()` in order, closes monitor/client/server on shutdown, and its
   nine `stargate.*` config properties default to the production topology
   (`/etc/stargate/tokens.yaml`, `/etc/stargate/keys/pepper.key`,
   `/etc/stargate/keys` keypair dir, `/run/stargate/{control,dp}.sock`,
   `tor:9051`, `/run/tor/control_auth_cookie`, 10 s poll) — verified by
   the suites above driving the same `bootstrap` seam the production
   `run()` drives.
4. **Runnable command**: `scripts/verify.sh` GREEN — in particular
   `cd control-plane && ./mvnw -B verify` compiles the runtime module
   under the inherited Error Prone + NullAway gate and passes both suites.
5. **Build wiring**: `runtime/pom.xml` activates the quarkus-maven-plugin
   (build goal) so `mvnw package` produces the fast-jar the Dockerfile
   ENTRYPOINT expects (`runtime/target/quarkus-app/` — the T003a↔T041
   contract; T040 §Out-of-scope assigned this to T041);
   `runtime/src/main/resources/application.properties` carries the
   production datasource (SQLite at `/var/lib/stargate/control.db`,
   Flyway `migrate-at-start` = the T092 (c) seed/migrate, Hibernate
   `generation=none`).

## Out-of-scope

- **compose/** — the `stargate-control` healthcheck block stays a separate
  ticket (T016 note; would modify T015's contract surface). The compose
  CP→DP ordering question (none exists today) is untouched.
- **control-plane/Dockerfile** — after the maven-plugin activation the
  documented T003a contract holds with no Dockerfile edit (runtime/src
  exists once this ticket lands; the COPY paths already match).
- **data-plane/** (T042–T050), **extension/** (T051+), **ui/** (T040 done).
- **THREAT-MODEL / data-model amendments** — T092 already recorded the
  pepper residue (§5.14) and the T094a/T039 entries cover the monitor;
  this ticket introduces no new claim, surface, or secret (it wires the
  amended contract verbatim; Principle V honesty = the residue list above).
- **tests/contract/** compose-tier runtime gates (T070) and any live-tor
  coverage — unit tier only here.
- **torrc rendering** — removed by T089 (T037 deferred); the CP never
  writes `stargate-tor-config`.
- **TokenLoader / SidecarMonitor / ControlGrpcService / ReloadTokensClient /
  AuditLogService behavior changes** — their surfaces are pinned by
  T035a/T039/T074/T038/T036 suites; T041 only consumes them.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.** The CP
runtime wiring must: (a) read the install-time pepper from
`/etc/stargate/keys/pepper.key` (mode `0640`, group `stargate-ipc`) and pass it
to `TokenLoader` for HMAC-SHA-256 verifier construction (`data-model.md`
§1.7); (b) ensure the pepper is NEVER logged, persisted to
`dp-snapshot.json`, or sent over the RPC (only verifiers cross the wire);
(c) seed/migrate the `token_generation` singleton + `configured_tokens`
table on start (arch §6.6/§6.7). T093 (blocked_by T092) gates this ticket
test-first.

**Landing record (2026-09-06).** Round-1 review: REWORK (1 Major, 3 Minor) —
the Major was real (no test observed the `monitor.start()` wiring; deleting
it kept the suite green). All four items addressed and mutation-verified in
round 2 (`monitorStartIsWiredAtBootAndFeedsTheAuditAdapter` via a fake
ControlPort; `teardownReleasesTheControlSockForRebind`;
`absentGenerationRowReadsAsZeroDeterministically`; frontmatter 9→11), round-2
verdict APPROVE (0 findings; all four dispositions SATISFIED; six candidate
concerns falsified-and-dropped). Reviewer RECOMMENDED-FOLLOW-UP (non-blocking,
not an acceptance item): pin the §1.9 un-revoke sub-case (upsert → delete →
upsert keeps original `created_at`, clears `revoked_at`) with a three-line
extension of `upsertStampsCreatedAtOnceAndRefreshesVerifier` — feed as
candidate input to the next persistence-suite-touching ticket. Implementation
set: 11 counted files (§Analysis) + specs/ regen; tests-first honored (suites
RED on the five absent classes, driven green in-ticket); `verify.sh` GREEN
(PASS=20) at commit.
