---
id: T012
title: 'Author `control-plane/persistence/src/main/resources/db/migration/V001'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T012
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: false
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: ['architecture/spec.md#6', 'data-model.md#4']   # filled at /start
decision_refs: []
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T012: Author `control-plane/persistence/src/main/resources/db/migration/V001

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `control-plane/persistence/src/main/resources/db/migration/V001__init.sql` with the full schema from architecture spec §6 (so later features add data without schema churn); this feature writes only `audit_log` and `enrolled_devices` per data-model.md §4.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

**Named test** (`control-plane/persistence/src/test/java/app/zcat/stargate/persistence/V001MigrationTest.java`):

- `v001AppliesCleanlyAndCreatesAllFiveTables` — Flyway applies
  `V001__init.sql` to a fresh SQLite file DB; `sqlite_master` then
  contains exactly the five arch-§6 tables (`enrolled_devices`,
  `admin_credentials`, `tor_bridges`, `aggregate_counters`, `audit_log`),
  no more, no less.
- `flywayHistoryRecordsV001` — `flyway_schema_history` records version
  `"001"` (Flyway derives it verbatim from the filename `V001__init.sql`)
  at `success=1`; a regression that disabled Flyway or applied the SQL
  out-of-band would surface here.

**Runnable command:** `bash scripts/verify.sh` GREEN (mvnw-verify gate
runs the persistence module's tests; provider must be `JUnitPlatformProvider`
and `Tests run: 2`, not 0 — the Surefire green-by-vacuity trap).

**Spec fidelity floor:** the five `CREATE TABLE` statements are byte-
faithful to arch §6.1–§6.5 including the `CHECK` constraints on
`admin_credentials.kind` and `aggregate_counters.route`, and the
`UNIQUE` constraints on `enrolled_devices.name`,
`admin_credentials.credential_id`, and `tor_bridges.bridge_line`.

## Out-of-scope

- WAL mode (`PRAGMA journal_mode=WAL`) — arch §6 prose names WAL as a
  runtime property of the control.db file; it is a DataSource /
  Quarkus-config concern, not a Flyway migration concern (PRAGMAs that
  affect persistence run outside migrations). Lands with the Quarkus
  datasource wiring task.
- Panache `@Entity` classes for `audit_log` and `enrolled_devices` —
  later task (T012 only ships DDL; the Hibernate mapping lands when the
  code that writes the rows lands).
- A `CHECK` constraint on `audit_log.action` — deliberately omitted per
  arch §6.5 (the action vocabulary is extensible across features via
  lock-step amendment; a CHECK would force a migration per feature).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
