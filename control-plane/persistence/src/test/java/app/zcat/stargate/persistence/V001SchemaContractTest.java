// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Introspects every v1 table via SQLite {@code PRAGMA} and asserts the
 * installed schema matches the amended data model exactly: columns, declared
 * types, NOT NULL, column defaults, PRIMARY KEY membership, UNIQUE indexes, and
 * CHECK constraints. This is the column-level strengthening of
 * {@link V001MigrationTest} (which proved only that the table names exist);
 * T100 acceptance #1.
 *
 * <p>Authorities: architecture spec §6.1–§6.7 (the canonical DDL), and the
 * bearer-token amendments in {@code specs/001-tor-route/data-model.md} §1.8
 * ({@code token_generation}) and §1.9 ({@code configured_tokens}). A green
 * test here is the regression line against silent column/nullability drift —
 * the class of bug that let the {@code enrolled_devices} NOT-NULL
 * {@code pubkey} contradiction ship undetected (T100 Context).
 *
 * <p>The asserted set is exactly what {@code V001__init.sql} defines today
 * (the schema lands once, pre-release). Where the data model leaves a column
 * intentionally free-text with no DB CHECK (e.g. {@code audit_log.action},
 * which is a fixed-vocabulary application-layer enum that grows by lock-step
 * amendment per feature — data-model.md §4), the test asserts the column has
 * NO check rather than inventing one.
 */
class V001SchemaContractTest {

    @TempDir
    Path tempDir;

    private String url;

    @BeforeEach
    void migrate() {
        Path dbFile = tempDir.resolve("stargate-control.db");
        url = "jdbc:sqlite:" + dbFile.toAbsolutePath();
        Flyway flyway = Flyway.configure().dataSource(url, "", "").load();
        flyway.migrate();
    }

    // --- enrolled_devices (arch §6.1) -------------------------------------

    @Test
    void enrolledDevicesContract() throws SQLException {
        Map<String, Col> cols = columns("enrolled_devices");
        assertColumns(cols, "id", "name", "pubkey", "token_hash",
                      "created_at", "last_seen_hour", "revoked_at");
        assertEquals("INTEGER", cols.get("id").type);
        assertTrue(cols.get("id").pk, "id is PRIMARY KEY");
        assertEquals("TEXT", cols.get("name").type);
        assertTrue(cols.get("name").notNull);
        assertEquals("BLOB", cols.get("pubkey").type);
        assertTrue(cols.get("pubkey").notNull, "pubkey NOT NULL (device key)");
        assertEquals("BLOB", cols.get("token_hash").type);
        assertTrue(cols.get("token_hash").notNull, "token_hash NOT NULL (HMAC verifier)");
        assertEquals("INTEGER", cols.get("created_at").type);
        assertTrue(cols.get("created_at").notNull);
        assertEquals("INTEGER", cols.get("last_seen_hour").type);
        assertFalse(cols.get("last_seen_hour").notNull, "last_seen_hour nullable (Principle III)");
        assertEquals("INTEGER", cols.get("revoked_at").type);
        assertFalse(cols.get("revoked_at").notNull, "revoked_at nullable");
        // name is UNIQUE (unique device name).
        assertTrue(uniqueColumns("enrolled_devices").contains("name"),
                   "enrolled_devices.name UNIQUE");
    }

    // --- admin_credentials (arch §6.2) ------------------------------------

    @Test
    void adminCredentialsContract() throws SQLException {
        Map<String, Col> cols = columns("admin_credentials");
        assertColumns(cols, "id", "kind", "credential_id", "public_key_cose",
                      "ssh_pubkey_line", "label", "created_at", "revoked_at");
        assertTrue(cols.get("id").pk);
        assertEquals("TEXT", cols.get("kind").type);
        assertTrue(cols.get("kind").notNull);
        assertEquals("BLOB", cols.get("credential_id").type);
        assertTrue(cols.get("credential_id").notNull);
        assertTrue(uniqueColumns("admin_credentials").contains("credential_id"),
                   "admin_credentials.credential_id UNIQUE");
        assertFalse(cols.get("public_key_cose").notNull, "public_key_cose WebAuthn-only");
        assertFalse(cols.get("ssh_pubkey_line").notNull, "ssh_pubkey_line ed25519-only");
        assertFalse(cols.get("label").notNull);
        assertTrue(cols.get("created_at").notNull);
        assertFalse(cols.get("revoked_at").notNull);
        // CHECK (kind IN ('webauthn','ed25519')) — declared in the table DDL.
        assertTrue(ddl("admin_credentials").contains("CHECK") && ddl("admin_credentials").contains("webauthn"),
                   "kind CHECK constraint missing");
    }

    // --- tor_bridges (arch §6.3) ------------------------------------------

    @Test
    void torBridgesContract() throws SQLException {
        Map<String, Col> cols = columns("tor_bridges");
        assertColumns(cols, "id", "bridge_line", "transport", "enabled", "added_at");
        assertTrue(cols.get("id").pk);
        assertEquals("TEXT", cols.get("bridge_line").type);
        assertTrue(cols.get("bridge_line").notNull);
        assertTrue(uniqueColumns("tor_bridges").contains("bridge_line"),
                   "tor_bridges.bridge_line UNIQUE");
        assertEquals("TEXT", cols.get("transport").type);
        assertTrue(cols.get("transport").notNull);
        assertEquals("INTEGER", cols.get("enabled").type);
        assertTrue(cols.get("enabled").notNull);
        assertEquals("0", cols.get("enabled").dflt, "enabled DEFAULT 0");
        assertEquals("INTEGER", cols.get("added_at").type);
        assertTrue(cols.get("added_at").notNull);
    }

    // --- aggregate_counters (arch §6.4) -----------------------------------

    @Test
    void aggregateCountersContract() throws SQLException {
        Map<String, Col> cols = columns("aggregate_counters");
        // Privacy invariant (Principle III): NO destination / token / url column.
        assertColumns(cols, "route", "hour_bucket", "request_count", "byte_count");
        assertEquals("TEXT", cols.get("route").type);
        assertTrue(cols.get("route").pk, "route part of composite PK");
        assertTrue(cols.get("route").notNull);
        assertEquals("INTEGER", cols.get("hour_bucket").type);
        assertTrue(cols.get("hour_bucket").pk, "hour_bucket part of composite PK");
        assertTrue(cols.get("hour_bucket").notNull);
        assertEquals("INTEGER", cols.get("request_count").type);
        assertTrue(cols.get("request_count").notNull);
        assertEquals("0", cols.get("request_count").dflt, "request_count DEFAULT 0");
        assertEquals("INTEGER", cols.get("byte_count").type);
        assertTrue(cols.get("byte_count").notNull);
        assertEquals("0", cols.get("byte_count").dflt, "byte_count DEFAULT 0");
        // CHECK (route IN ('TOR','I2P','NYM','DIRECT')) — declared in DDL.
        String ddl = ddl("aggregate_counters");
        assertTrue(ddl.contains("CHECK") && ddl.contains("'TOR'") && ddl.contains("'DIRECT'"),
                   "route CHECK constraint missing");
    }

    // --- audit_log (arch §6.5) --------------------------------------------

    @Test
    void auditLogContract() throws SQLException {
        Map<String, Col> cols = columns("audit_log");
        assertColumns(cols, "id", "ts", "actor", "action", "target", "detail_json");
        assertTrue(cols.get("id").pk);
        assertEquals("INTEGER", cols.get("ts").type);
        assertTrue(cols.get("ts").notNull);
        assertEquals("TEXT", cols.get("actor").type);
        assertTrue(cols.get("actor").notNull);
        assertEquals("TEXT", cols.get("action").type);
        assertTrue(cols.get("action").notNull);
        // action is intentionally a free TEXT column with NO DB CHECK: it is a
        // fixed-vocabulary APPLICATION-layer enum that grows by lock-step
        // amendment per feature (data-model.md §4). Asserting "no check" pins
        // that decision so a future CHECK is a deliberate review event.
        assertFalse(ddl("audit_log").toLowerCase().contains("action") && ddl("audit_log").contains("CHECK"),
                    "action has no DB CHECK (intentionally application-enforced)");
        assertEquals("TEXT", cols.get("target").type);
        assertFalse(cols.get("target").notNull, "target nullable");
        assertEquals("TEXT", cols.get("detail_json").type);
        assertFalse(cols.get("detail_json").notNull, "detail_json nullable");
    }

    // --- configured_tokens (§6.6 / data-model.md §1.9) -------------------

    @Test
    void configuredTokensContract() throws SQLException {
        Map<String, Col> cols = columns("configured_tokens");
        assertColumns(cols, "label", "verifier", "created_at", "last_seen_hour", "revoked_at");
        // label is the PRIMARY KEY (audit-log key); it is NOT an autoincrement id.
        assertTrue(cols.get("label").pk, "configured_tokens.label PRIMARY KEY");
        assertEquals("TEXT", cols.get("label").type);
        assertTrue(cols.get("label").notNull);
        assertEquals("BLOB", cols.get("verifier").type);
        assertTrue(cols.get("verifier").notNull, "verifier (HMAC tag) NOT NULL");
        assertEquals("INTEGER", cols.get("created_at").type);
        assertTrue(cols.get("created_at").notNull);
        assertEquals("INTEGER", cols.get("last_seen_hour").type);
        assertFalse(cols.get("last_seen_hour").notNull);
        assertEquals("INTEGER", cols.get("revoked_at").type);
        assertFalse(cols.get("revoked_at").notNull);
    }

    // --- token_generation (§6.7 / data-model.md §1.8) --------------------

    @Test
    void tokenGenerationContract() throws SQLException {
        Map<String, Col> cols = columns("token_generation");
        assertColumns(cols, "generation");
        assertTrue(cols.get("generation").pk, "token_generation.generation PRIMARY KEY");
        assertEquals("INTEGER", cols.get("generation").type);
        // NOTE: SQLite's PRAGMA reports notnull=0 for `INTEGER PRIMARY KEY` (a
        // long-standing quirk) even though it is the rowid alias and is
        // behaviorally non-null. We assert pk membership, not the pragma's
        // notnull flag, for this column; a rowid alias cannot hold NULL.
    }

    // --- helpers ----------------------------------------------------------

    private record Col(String name, String type, boolean notNull, String dflt, boolean pk) {}

    private Map<String, Col> columns(String table) throws SQLException {
        Map<String, Col> out = new LinkedHashMap<>();
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement("PRAGMA table_info(" + table + ")");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                out.put(rs.getString("name"), new Col(
                    rs.getString("name"),
                    rs.getString("type"),
                    rs.getInt("notnull") == 1,
                    rs.getString("dflt_value"),
                    rs.getInt("pk") > 0));
            }
        }
        assertFalse(out.isEmpty(), "no columns introspected for " + table);
        return out;
    }

    private Set<String> uniqueColumns(String table) throws SQLException {
        // Union of columns covered by any unique index (UNIQUE constraints and
        // PRIMARY KEY both surface here with unique=1).
        Set<String> out = new LinkedHashSet<>();
        try (Connection c = DriverManager.getConnection(url, "", "")) {
            try (PreparedStatement pl = c.prepareStatement("PRAGMA index_list(" + table + ")");
                 ResultSet irl = pl.executeQuery()) {
                while (irl.next()) {
                    if (irl.getInt("unique") == 1) {
                        String idx = irl.getString("name");
                        try (PreparedStatement pi = c.prepareStatement("PRAGMA index_info(" + idx + ")");
                             ResultSet iri = pi.executeQuery()) {
                            while (iri.next()) {
                                out.add(iri.getString("name"));
                            }
                        }
                    }
                }
            }
        }
        return out;
    }

    private String ddl(String table) throws SQLException {
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT sql FROM sqlite_master WHERE type='table' AND name=?")) {
            ps.setString(1, table);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "no DDL row for " + table);
                return rs.getString("sql");
            }
        }
    }

    /** Asserts the column set matches exactly (catches both missing AND added columns). */
    private static void assertColumns(Map<String, Col> cols, String... expected) {
        Set<String> want = new LinkedHashSet<>(Set.of(expected));
        assertEquals(want, cols.keySet(),
            "column set drift; expected " + want + " but got " + cols.keySet());
    }
}
