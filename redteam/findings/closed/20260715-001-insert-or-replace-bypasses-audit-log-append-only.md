---
id: 20260715-001-insert-or-replace-bypasses-audit-log-append-only
status: closed
severity: major
principle: [III]
threat-model: 8.3
location: control-plane/persistence/src/main/resources/db/migration/V001__init.sql (audit_log triggers)
first-seen-run: 20260715-T100
first-seen-date: 2026-07-15
fix-commit: pending (lands in the T100 implement commit on 001-tor-route)
decision-ref: null
closed-date: 2026-07-15
closed-by: stargate-redteam re-review (2026-07-15) — M1 RESOLVED
---

# `INSERT OR REPLACE` bypassed the audit_log append-only triggers

## What the code does (at first-seen)

T100's first pass added `BEFORE UPDATE` and `BEFORE DELETE` `RAISE(ABORT)`
triggers on `audit_log` and claimed the log was append-only "BY MECHANISM … so
the admin-action log's integrity does not depend on caller discipline." That
claim was **falsified** for `INSERT OR REPLACE`: under the default
`PRAGMA recursive_triggers=OFF`, SQLite's REPLACE conflict resolution deletes
the conflicting PK row **without** firing `BEFORE DELETE`, then the INSERT
lands — silently rewriting `actor`/`action`/`ts`/`target`/`detail_json` of any
existing audit row. Neither the migration nor any control-plane config set
`recursive_triggers`, so the bypass was live by default. Verified empirically
against the exact DDL (sqlite-jdbc 3.46.1.3 / SQLite 3.46): the seeded row
`original → REPLACED`. Plain `UPDATE`, plain `DELETE`, and
`ON CONFLICT(id) DO UPDATE` were correctly blocked.

Not a Blocker because (a) no shipped v1 code path used `INSERT OR REPLACE` on
`audit_log` (schema+tests only), (b) THREAT-MODEL §8.3 already concedes a
host/admin-compromise attacker can wipe the log, and (c) the legitimate insert
path (no explicit id) was unaffected.

## Resolution (lands in the T100 implement commit)

A third trigger closes the bypass at INSERT time, connection-config-independent
(it does NOT rely on the per-connection `PRAGMA recursive_triggers`, which would
silently reopen on any connection that omits it):

```sql
CREATE TRIGGER audit_log_no_replace BEFORE INSERT ON audit_log
WHEN EXISTS (SELECT 1 FROM audit_log WHERE id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: row overwrite rejected');
END;
```

This detects a row overwrite by checking the already-existing id at BEFORE
INSERT (legitimate appends never collide — `id` is the autoincrement rowid and
callers do not supply it). Regression coverage:
`AuditLogAppendOnlyTest#insertOrReplaceOverwriteIsRejectedAndLeavesRowUntouched`
runs under the production default (no `PRAGMA recursive_triggers`) so it stays a
live guard, and `#appendOnlyTriggersAreInstalled` now asserts all three triggers.

## Documented residue (not closed by T100)

DDL/admin access — `DROP TRIGGER` then `UPDATE`; `PRAGMA writable_schema=ON`
mutating `sqlite_master` — remain and are the documented THREAT-MODEL §8.3
residue ("the log lives in the same DB a host/admin-compromise attacker can read
or wipe"). T100 does not claim to close these.
