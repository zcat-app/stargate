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

-- 6.1 enrolled_devices — devices that may use the proxy.
CREATE TABLE enrolled_devices (
  id              INTEGER PRIMARY KEY,
  name            TEXT    NOT NULL UNIQUE,
  pubkey          BLOB    NOT NULL,             -- ed25519 device key
  token_hash      BLOB    NOT NULL,             -- argon2id of bearer token
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
