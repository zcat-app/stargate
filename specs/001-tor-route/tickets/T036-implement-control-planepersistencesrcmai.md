---
id: T036
title: 'Implement `control-plane/persistence/src/main/java/.../entity/AuditLog'
status: done
created: 2026-07-04
last_updated: 2026-09-05
source: tasks.md#T036
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T100]
parallel: false
files_budget: 6   # pom edit + entity + service + test config + test class + this ticket
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/data-model.md §4        # audit rows: five actions, actor constants, fixed-vocabulary detail
  - specs/001-tor-route/data-model.md §1.6      # no token bytes / pepper material in audit or log surfaces
  - specs/001-tor-route/spec.md#FR-018          # audit entries per the tokens.yaml load diff
  - specs/000-architecture/spec.md §6.5         # audit_log append-only by mechanism
decision_refs: []
reviews: { round: 1, date: 2026-09-05, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T036: Implement `control-plane/persistence/src/main/java/.../entity/AuditLog

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/persistence/src/main/java/.../entity/AuditLog.java` (Panache entity matching V001 schema) and `AuditLogService.java` exposing one `write(action, target, detailJson)` method that emits any of the five fixed-vocabulary actions enumerated in data-model.md §4: `enrolled`, `revoked`, `config_error`, `sidecar_healthy`, `sidecar_unhealthy`. `actor` is set to `tokens.yaml` for the three token actions and to `system` for the two sidecar transitions, per §4. The callers wired by this feature are T035 (`enrolled`, `revoked`, `config_error`), T039 (`sidecar_healthy`), and T074 (`sidecar_unhealthy`).

## Analysis

Required (`privacy_critical: true`) — full property map. Grounded
2026-09-05 against data-model.md §4/§1.6, spec.md FR-018, arch §6.5,
`V001__init.sql` (incl. the T100 append-only triggers), and the landed
seams: `TokenLoaderContract.AuditSink` (T035a, core) pins the
`write(action, target, detailJson)` shape and states the sink derives
`actor` from the action; `AuditLogService` is the production adapter for
that port (T035a Javadoc names it). Grounding findings: (a) the
persistence module has **no `src/main/java` yet** — this ticket creates
it; the four T100 suites pin the schema/DML layer but reference no Java
API, so T036's tests are new (tests-first per Principle VII); (b)
persistence→core is a **new module dependency** (core has no reverse
dep — no cycle) so the service can implement the port; (c)
`PanacheEntity`'s inherited `id` is a strategy-less `@GeneratedValue`
(Hibernate AUTO → sequence/table fallback — wrong for SQLite) so the
entity declares an explicit `GenerationType.IDENTITY` mapping instead of
extending `PanacheEntity` (SQLite rowid alias = V001's `INTEGER PRIMARY
KEY`); (d) testing runs `@QuarkusTest` against the real stack (Agroal
SQLite + Panache + Flyway `migrate-at-start`) — the same wiring T041's
runtime boot will rely on.

- **Must hold (property map)**
  - Fixed five-action vocabulary (data-model.md §4; arch §5.2 "detail is
    a fixed-vocabulary token"): `write` accepts exactly `enrolled`,
    `revoked`, `config_error`, `sidecar_healthy`, `sidecar_unhealthy`;
    anything else throws before any row is written. Later actions
    (`bridge_toggle`, `export`, `import`, `wipe`) land via lock-step
    amendments per the V001 §6.5 comment.
  - Actor constants, no user identity (data-model.md §4: "No user
    identity is captured because there is no admin UI in this
    feature"): the three token actions → `"tokens.yaml"`, the two
    sidecar transitions → `"system"`, derived inside the sink.
  - Row shape matches V001 §6.5 exactly: `(id, ts, actor, action,
    target, detail_json)`; `ts` is write-time unix seconds — second
    resolution is spec'd for admin-action rows (V001 §6.5 comment: "not
    user request time"; Principle III's ≥1h bucketing governs
    per-request surfaces, not this table).
  - `detail_json` stored verbatim — never parsed, re-serialized, or
    enriched; never token bytes or pepper material (data-model.md §1.6;
    arch §5.2). `target` carries the label or `tor`/`tokens.yaml`, per
    the §4 table — never request data (Principle III).
  - Append-only preserved through the ORM path (arch §6.5; Principle III
    by construction): the service only INSERTs; the V001 triggers reject
    UPDATE/DELETE/REPLACE-overwrite by mechanism — including any
    accidental Panache `merge()`/`delete()` on the entity.
  - Seam conformance: `AuditLogService implements
    TokenLoaderContract.AuditSink` — the pinned shape, so T035 binds the
    production adapter without a shim.
  - Principle VII: every must-hold above has a named test in
    `AuditLogServiceTest`.
  - NullAway/Error Prone clean on main sources (module gate): entity
    fields are framework-initialized → `@SuppressWarnings("NullAway.Init")`
    at the declaration per the parent pom's documented suppression
    pattern.
- **Gated**
  - Vocabulary + actor constants: `writePersistsEachOfTheFiveVocabularyActionsWithTheSectionFourActor`
    (parametrized over the §4 table) and
    `writeRejectsActionOutsideTheFixedVocabularyWithoutWritingARow` —
    this ticket promotes both into the gated set.
  - Entity↔V001 mapping: the same round-trip test reads back via **raw
    JDBC with literal column names** (not through the entity), alongside
    the existing `V001SchemaContractTest` / `V001MigrationTest` (T100).
  - Append-only at the SQL layer: `AuditLogAppendOnlyTest` (T100); at
    the ORM layer: `panacheMergeAndDeleteAreRejectedByTheAppendOnlyTriggers`
    (new — closes the Panache-default-methods gap).
  - Port shape: `serviceSatisfiesTheTokenLoaderAuditSinkPort`
    (assignability + a call through the port reference).
  - NullAway + Error Prone ERROR-severity checks and the SPDX license
    header: `cd control-plane && ./mvnw -B -q verify` via
    `scripts/verify.sh`.
- **Residue**
  - The per-action *inner* `detail_json` vocabulary
    (`{"kind":…|…}`, `{"source":…,"generation":…}`, `{"generation":…}`)
    is caller-supplied; `write` stores verbatim and cannot catch a
    caller passing free text (a per-action JSON-shape lint is new
    schema, deferred). Redteam/review focus: the T035/T039/T074 call
    sites.
  - "No token bytes in `detail_json`" is unenforceable in the service
    (it never sees plaintext); rests on T035's tests and review.

**Implementation finding (2026-09-05) — forced lift, T104a debt.** The
first post-T104a recompile of this module's test sources surfaced 74
latent NullAway violations in T100's `V001SchemaContractTest` (72) and
`RepositoryShapeContractTest` (2): T104a removed the
`default-testCompile` exemption stanza and recorded a green verify, but
the module's stale `target/test-classes` made maven-compiler skip
recompiling those files entirely — the exact "green-but-not-enforced"
failure mode T104's pom notes warn about. Falsified at HEAD: stash +
`test-compile` reproduces all 74 without any T036 change. Lifted
mechanically within T104a's own landed doctrine (test sources are
NullAway-gated; fix by making the nullness contract explicit): a
`col(cols, name)` `Objects.requireNonNull` helper for the PRAGMA map
accesses, and `assertNotNull` refinement for `getMessage()` derefs —
zero behavioral change; all four T100 suites re-ran green on the same
assertions. Budget disposition (9 files vs 6, incl. driver-regenerated
STATUS.md): entity, service, pom edit, test config, test class, ticket
= acceptance; the two T100 test files = this documented forced lift
(T050 precedent). T104a's acceptance-#2/4 evidence should be
re-verified by its owner; flagged in the session report.

## Acceptance

All tests live in `control-plane/persistence/src/test/java/app/zcat/stargate/persistence/AuditLogServiceTest.java`
(`@QuarkusTest` on a Flyway-migrated SQLite DB under `target/`; row-count
assertions are deltas — the append-only triggers forbid cleanup deletes):

1. `writePersistsEachOfTheFiveVocabularyActionsWithTheSectionFourActor`
   — parametrized over the data-model.md §4 table: each action
   round-trips a §4-shaped row through the real stack; raw-JDBC
   read-back asserts the actor mapping (3× `tokens.yaml`, 2×
   `system`), verbatim `detail_json`, a fresh unix-seconds `ts`
   (tolerance ±5 s of now), and a generated distinct `id`.
2. `writeRejectsActionOutsideTheFixedVocabularyWithoutWritingARow` —
   an action outside the five throws `IllegalArgumentException` and the
   audit row count is unchanged.
3. `panacheMergeAndDeleteAreRejectedByTheAppendOnlyTriggers` — on a
   persisted row, Panache `merge()` and `delete()` fail with an
   exception whose cause chain carries the trigger's "append-only"
   diagnostic (ORM-layer complement to T100's `AuditLogAppendOnlyTest`).
4. `serviceSatisfiesTheTokenLoaderAuditSinkPort` — the service is
   assignable to `TokenLoaderContract.AuditSink` and a call through the
   port reference writes the `enrolled` row.
5. `cd control-plane && ./mvnw -B -q -pl persistence -am test` green
   (includes the four T100 suites); `scripts/verify.sh` green from the
   repo root.

## Out-of-scope

- Production datasource/Flyway config for the runtime module (T041 wires
  the CP boot); this ticket adds only the test-profile
  `application.properties` under `persistence/src/test/resources`.
- The `ConfiguredTokenStore` / `GenerationStore` Panache adapters
  (T035's store wiring).
- Caller wiring: T035 (`enrolled`, `revoked`, `config_error`), T039
  (`sidecar_healthy`), T074 (`sidecar_unhealthy`) own their emission
  rules; this ticket provides the sink only.
- The later vocabulary actions (`bridge_toggle`, `export`, `import`,
  `wipe`) — V001 §6.5 comment: land via lock-step amendments.
- No schema changes: V001 is frozen by T100's suites; this ticket writes
  main code only.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
