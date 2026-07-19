-- Copyright 2026 The Stargate Authors
-- SPDX-License-Identifier: Apache-2.0

-- V001__init.sql — initial SQLite schema for the Stargate control plane.
--
-- Source of truth: specs/000-architecture/spec.md §6 (SQLite Schema Sketch).
-- This migration lands the FULL v1 schema up-front so later features add
-- data without schema churn (T012 rationale: this feature writes only
-- audit_log and enrolled_devices per data-model.md §4, but the other
-- tables are created here to keep the migration set stable).
--
-- Privacy note (arch §6 "What is deliberately NOT in this schema",
-- Constitution Principle III): the schema holds NO per-request URL,
-- hostname, IP, or sub-hour timestamp. audit_log and aggregate_counters
-- are bucketed to ≥1h resolution. The `audit_log.detail_json` column is
-- a fixed-vocabulary token (data-model.md §4), never free-text request
-- data.

-- 6.1 enrolled_devices — devices enrolled via the dashboard (future).
-- (T092 / sol-review M1) reserved for the future dashboard-enrollment
-- feature, the only path that has a device public key. The manual
-- tokens.yaml path persists to configured_tokens (§6.6 below), NOT here.
CREATE TABLE enrolled_devices (
  id              INTEGER PRIMARY KEY,
  name            TEXT    NOT NULL UNIQUE,
  pubkey          BLOB    NOT NULL,             -- ed25519 device key
  token_hash      BLOB    NOT NULL,             -- HMAC-SHA-256 verifier under the pepper (T092; was argon2id)
  created_at      INTEGER NOT NULL,             -- unix seconds
  last_seen_hour  INTEGER,                      -- rounded to hour-bucket
  revoked_at      INTEGER                       -- nullable
);
-- last_seen_hour is bucketed to satisfy Principle III (>=1h log resolution).

-- 6.2 admin_credentials — admin login credentials (WebAuthn + ed25519 fallback).
CREATE TABLE admin_credentials (
  id                INTEGER PRIMARY KEY,
  kind              TEXT    NOT NULL CHECK (kind IN ('webauthn','ed25519')),
  credential_id     BLOB    NOT NULL UNIQUE,    -- WebAuthn credId or ssh-key fingerprint
  public_key_cose   BLOB,                       -- WebAuthn only
  ssh_pubkey_line   TEXT,                       -- ed25519 fallback only
  label             TEXT,
  created_at        INTEGER NOT NULL,
  revoked_at        INTEGER
);

-- 6.3 tor_bridges — toggleable per Constitution v1 Scope.
CREATE TABLE tor_bridges (
  id          INTEGER PRIMARY KEY,
  bridge_line TEXT    NOT NULL UNIQUE,          -- full "Bridge ..." torrc line
  transport   TEXT    NOT NULL,                 -- obfs4 | snowflake | webtunnel | direct
  enabled     INTEGER NOT NULL DEFAULT 0,
  added_at    INTEGER NOT NULL
);

-- 6.4 aggregate_counters — routing counters at hour resolution.
CREATE TABLE aggregate_counters (
  route         TEXT    NOT NULL CHECK (route IN ('TOR','I2P','NYM','DIRECT')),
  hour_bucket   INTEGER NOT NULL,                -- unix-hour
  request_count INTEGER NOT NULL DEFAULT 0,
  byte_count    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (route, hour_bucket)
);
-- No destination, no token id, no sub-hour granularity (Principle III).

-- 6.5 audit_log — append-only admin action log.
CREATE TABLE audit_log (
  id           INTEGER PRIMARY KEY,
  ts           INTEGER NOT NULL,                -- unix seconds (admin action time, not user request time)
  actor        TEXT    NOT NULL,                -- admin credential label
  action       TEXT    NOT NULL,                -- enum (v1 baseline; per-feature extensions land via lock-step amendments — see e.g. specs/001-tor-route/data-model.md §4): enrolled, revoked, config_error, sidecar_healthy, sidecar_unhealthy, sidecar_restart, bridge_toggle, export, import, wipe
  target       TEXT,                            -- entity affected (e.g. device name)
  detail_json  TEXT                             -- fixed-schema metadata; never request data
);
-- Inserts only; no UPDATE/DELETE in code paths. Verified by stargate-redteam.
--
-- Append-only BY MECHANISM (arch §6.5; Constitution Principle III —
-- "by construction"): triggers reject every mutation that could change or
-- remove an existing audit row, so the admin-action log's integrity does not
-- depend on caller discipline. The diagnostic surfaces verbatim in any stack
-- trace that trips it. Added by T100 (sol-review A1) within the pre-release
-- "schema lands once" window.
--
-- Three DML paths are guarded, each connection-config-independent (the fix does
-- NOT rely on PRAGMA recursive_triggers, which is per-connection and would
-- silently reopen on any connection that omits it):
--   * UPDATE                       -> audit_log_no_update
--   * DELETE                       -> audit_log_no_delete
--   * row overwrite via INSERT OR  -> audit_log_no_replace (stargate-redteam
--     REPLACE / REPLACE conflict     M1: REPLACE's internal delete of a
--     resolution                     conflicting PK row does NOT fire
--                                     BEFORE DELETE under the default
--                                     recursive_triggers=OFF, so the
--                                     overwrite is caught here, at INSERT,
--                                     by detecting the already-existing id.)
-- DDL/admin access (DROP TRIGGER, PRAGMA writable_schema) can still defeat
-- these — that is the documented THREAT-MODEL §8.3 residue (the log lives in
-- the same DB a host/admin-compromise attacker can read or wipe), not a gap
-- this ticket claims to close.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected');
END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE rejected');
END;
CREATE TRIGGER audit_log_no_replace BEFORE INSERT ON audit_log
WHEN EXISTS (SELECT 1 FROM audit_log WHERE id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: row overwrite rejected');
END;

-- 6.6 configured_tokens — manual tokens.yaml token records (T092 / sol-review M1).
-- Manual tokens carry (label, verifier) only — no device public key — so they
-- live here, not in enrolled_devices (whose pubkey/token_hash are both NOT NULL).
-- Full contract: specs/001-tor-route/data-model.md §1.9.
CREATE TABLE configured_tokens (
  label          TEXT    NOT NULL PRIMARY KEY,    -- from tokens.yaml (non-empty, §1.1); NOT NULL closes SQLite's TEXT-PK NULL quirk (T100)
  verifier       BLOB    NOT NULL,                -- 32-byte HMAC-SHA-256 tag under the pepper
  created_at     INTEGER NOT NULL,                -- unix seconds (audit 'enrolled')
  last_seen_hour INTEGER,                         -- hour-bucket of last auth pass (Principle III; nullable)
  revoked_at     INTEGER                          -- nullable; set when label disappears from tokens.yaml
);

-- 6.7 token_generation — persisted monotonic generation counter (T092 / sol-review M1).
-- Source of truth for the ReloadTokens generation; lets a CP restart propose
-- last+1 instead of restarting at 1 and silently revoking every client.
-- Full semantics: specs/001-tor-route/data-model.md §1.8.
CREATE TABLE token_generation (
  generation  INTEGER PRIMARY KEY   -- singleton row; the last-assigned generation
);
