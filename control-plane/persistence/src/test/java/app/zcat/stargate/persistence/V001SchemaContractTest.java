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
import java.util.Objects;
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
        assertEquals("INTEGER", col(cols, "id").type);
        assertTrue(col(cols, "id").pk, "id is PRIMARY KEY");
        assertEquals("TEXT", col(cols, "name").type);
        assertTrue(col(cols, "name").notNull);
        assertEquals("BLOB", col(cols, "pubkey").type);
        assertTrue(col(cols, "pubkey").notNull, "pubkey NOT NULL (device key)");
        assertEquals("BLOB", col(cols, "token_hash").type);
        assertTrue(col(cols, "token_hash").notNull, "token_hash NOT NULL (HMAC verifier)");
        assertEquals("INTEGER", col(cols, "created_at").type);
        assertTrue(col(cols, "created_at").notNull);
        assertEquals("INTEGER", col(cols, "last_seen_hour").type);
        assertFalse(col(cols, "last_seen_hour").notNull, "last_seen_hour nullable (Principle III)");
        assertEquals("INTEGER", col(cols, "revoked_at").type);
        assertFalse(col(cols, "revoked_at").notNull, "revoked_at nullable");
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
        assertTrue(col(cols, "id").pk);
        assertEquals("TEXT", col(cols, "kind").type);
        assertTrue(col(cols, "kind").notNull);
        assertEquals("BLOB", col(cols, "credential_id").type);
        assertTrue(col(cols, "credential_id").notNull);
        assertTrue(uniqueColumns("admin_credentials").contains("credential_id"),
                   "admin_credentials.credential_id UNIQUE");
        assertFalse(col(cols, "public_key_cose").notNull, "public_key_cose WebAuthn-only");
        assertFalse(col(cols, "ssh_pubkey_line").notNull, "ssh_pubkey_line ed25519-only");
        assertFalse(col(cols, "label").notNull);
        assertTrue(col(cols, "created_at").notNull);
        assertFalse(col(cols, "revoked_at").notNull);
        // CHECK (kind IN ('webauthn','ed25519')) — declared in the table DDL.
        assertTrue(ddl("admin_credentials").contains("CHECK") && ddl("admin_credentials").contains("webauthn"),
                   "kind CHECK constraint missing");
    }

    // --- tor_bridges (arch §6.3) ------------------------------------------

    @Test
    void torBridgesContract() throws SQLException {
        Map<String, Col> cols = columns("tor_bridges");
        assertColumns(cols, "id", "bridge_line", "transport", "enabled", "added_at");
        assertTrue(col(cols, "id").pk);
        assertEquals("TEXT", col(cols, "bridge_line").type);
        assertTrue(col(cols, "bridge_line").notNull);
        assertTrue(uniqueColumns("tor_bridges").contains("bridge_line"),
                   "tor_bridges.bridge_line UNIQUE");
        assertEquals("TEXT", col(cols, "transport").type);
        assertTrue(col(cols, "transport").notNull);
        assertEquals("INTEGER", col(cols, "enabled").type);
        assertTrue(col(cols, "enabled").notNull);
        assertEquals("0", col(cols, "enabled").dflt, "enabled DEFAULT 0");
        assertEquals("INTEGER", col(cols, "added_at").type);
        assertTrue(col(cols, "added_at").notNull);
    }

    // --- aggregate_counters (arch §6.4) -----------------------------------

    @Test
    void aggregateCountersContract() throws SQLException {
        Map<String, Col> cols = columns("aggregate_counters");
        // Privacy invariant (Principle III): NO destination / token / url column.
        assertColumns(cols, "route", "hour_bucket", "request_count", "byte_count");
        assertEquals("TEXT", col(cols, "route").type);
        assertTrue(col(cols, "route").pk, "route part of composite PK");
        assertTrue(col(cols, "route").notNull);
        assertEquals("INTEGER", col(cols, "hour_bucket").type);
        assertTrue(col(cols, "hour_bucket").pk, "hour_bucket part of composite PK");
        assertTrue(col(cols, "hour_bucket").notNull);
        assertEquals("INTEGER", col(cols, "request_count").type);
        assertTrue(col(cols, "request_count").notNull);
        assertEquals("0", col(cols, "request_count").dflt, "request_count DEFAULT 0");
        assertEquals("INTEGER", col(cols, "byte_count").type);
        assertTrue(col(cols, "byte_count").notNull);
        assertEquals("0", col(cols, "byte_count").dflt, "byte_count DEFAULT 0");
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
        assertTrue(col(cols, "id").pk);
        assertEquals("INTEGER", col(cols, "ts").type);
        assertTrue(col(cols, "ts").notNull);
        assertEquals("TEXT", col(cols, "actor").type);
        assertTrue(col(cols, "actor").notNull);
        assertEquals("TEXT", col(cols, "action").type);
        assertTrue(col(cols, "action").notNull);
        // action is intentionally a free TEXT column with NO DB CHECK: it is a
        // fixed-vocabulary APPLICATION-layer enum that grows by lock-step
        // amendment per feature (data-model.md §4). Asserting "no check" pins
        // that decision so a future CHECK is a deliberate review event.
        assertFalse(ddl("audit_log").toLowerCase().contains("action") && ddl("audit_log").contains("CHECK"),
                    "action has no DB CHECK (intentionally application-enforced)");
        assertEquals("TEXT", col(cols, "target").type);
        assertFalse(col(cols, "target").notNull, "target nullable");
        assertEquals("TEXT", col(cols, "detail_json").type);
        assertFalse(col(cols, "detail_json").notNull, "detail_json nullable");
    }

    // --- configured_tokens (§6.6 / data-model.md §1.9) -------------------

    @Test
    void configuredTokensContract() throws SQLException {
        Map<String, Col> cols = columns("configured_tokens");
        assertColumns(cols, "label", "verifier", "created_at", "last_seen_hour", "revoked_at");
        // label is the PRIMARY KEY (audit-log key); it is NOT an autoincrement id.
        assertTrue(col(cols, "label").pk, "configured_tokens.label PRIMARY KEY");
        assertEquals("TEXT", col(cols, "label").type);
        assertTrue(col(cols, "label").notNull);
        assertEquals("BLOB", col(cols, "verifier").type);
        assertTrue(col(cols, "verifier").notNull, "verifier (HMAC tag) NOT NULL");
        assertEquals("INTEGER", col(cols, "created_at").type);
        assertTrue(col(cols, "created_at").notNull);
        assertEquals("INTEGER", col(cols, "last_seen_hour").type);
        assertFalse(col(cols, "last_seen_hour").notNull);
        assertEquals("INTEGER", col(cols, "revoked_at").type);
        assertFalse(col(cols, "revoked_at").notNull);
    }

    // --- token_generation (§6.7 / data-model.md §1.8) --------------------

    @Test
    void tokenGenerationContract() throws SQLException {
        Map<String, Col> cols = columns("token_generation");
        assertColumns(cols, "generation");
        assertTrue(col(cols, "generation").pk, "token_generation.generation PRIMARY KEY");
        assertEquals("INTEGER", col(cols, "generation").type);
        // NOTE: SQLite's PRAGMA reports notnull=0 for `INTEGER PRIMARY KEY` (a
        // long-standing quirk) even though it is the rowid alias and is
        // behaviorally non-null. We assert pk membership, not the pragma's
        // notnull flag, for this column; a rowid alias cannot hold NULL.
    }

    // --- helpers ----------------------------------------------------------

    /**
     * {@code cols.get(name)} with an explicit non-null contract. Test sources
     * are NullAway-gated since T104a; these call sites predate that gate and
     * only surfaced when T036's new test forced the module's first
     * post-T104a recompile (the stale {@code target/test-classes} had been
     * masking them). {@code requireNonNull} names the missing column instead
     * of failing with an anonymous NPE at the deref site.
     */
    private static Col col(Map<String, Col> cols, String name) {
        return Objects.requireNonNull(cols.get(name), "column missing: " + name);
    }

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
