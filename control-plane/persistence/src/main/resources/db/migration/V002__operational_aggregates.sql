-- Copyright 2026 The Stargate Authors
-- SPDX-License-Identifier: Apache-2.0
-- T152 / Constitution III. Forward migration preserves V001's applied checksum.
-- secure_delete scrubs SQLite's freed ordinary-table pages; WAL/backups still
-- require the operator cleanup procedure in THREAT-MODEL.md. No forensic claim.
PRAGMA secure_delete = ON;
DROP TABLE audit_log;
CREATE TABLE operational_aggregates (
  hour_bucket INTEGER NOT NULL CHECK (typeof(hour_bucket) = 'integer' AND hour_bucket >= 0 AND hour_bucket % 3600 = 0),
  category TEXT NOT NULL CHECK (category IN ('enrolled','revoked','config_error','sidecar_healthy','sidecar_unhealthy')),
  count INTEGER NOT NULL CHECK (typeof(count) = 'integer' AND count >= 0),
  PRIMARY KEY (hour_bucket, category)
) WITHOUT ROWID;
CREATE TRIGGER operational_aggregates_no_update BEFORE UPDATE ON operational_aggregates
BEGIN
  SELECT RAISE(ABORT, 'completed operational aggregates are immutable');
END;
CREATE TRIGGER operational_aggregates_no_replace BEFORE INSERT ON operational_aggregates
WHEN EXISTS (SELECT 1 FROM operational_aggregates WHERE hour_bucket = NEW.hour_bucket AND category = NEW.category)
BEGIN
  SELECT RAISE(IGNORE);
END;
-- Only current manual credentials are auth state. Revocation history, creation
-- times and per-device last-seen columns are not needed to authorize a request.
CREATE TABLE configured_tokens_current (
  label TEXT NOT NULL PRIMARY KEY,
  verifier BLOB NOT NULL
);
INSERT INTO configured_tokens_current(label, verifier)
  SELECT label, verifier FROM configured_tokens WHERE revoked_at IS NULL;
DROP TABLE configured_tokens;
ALTER TABLE configured_tokens_current RENAME TO configured_tokens;
-- Migration versions/checksums are current schema identity, not an installation
-- event journal. Neutralize Flyway's unused actor/time/duration fields, including
-- the V002 history row which Flyway inserts after this script completes.
UPDATE flyway_schema_history SET installed_by = 'stargate',
  installed_on = '1970-01-01 00:00:00', execution_time = 0;
CREATE TRIGGER flyway_schema_identity_only AFTER INSERT ON flyway_schema_history
BEGIN
  UPDATE flyway_schema_history SET installed_by = 'stargate',
    installed_on = '1970-01-01 00:00:00', execution_time = 0
    WHERE installed_rank = NEW.installed_rank;
END;
