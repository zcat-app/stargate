// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Applies {@code V001__init.sql} via Flyway against a fresh SQLite database
 * and asserts the schema matches arch §6: exactly the seven tables the
 * architecture spec mandates, no more, no less. The migration is a
 * contract-defining artefact (every future feature inherits this schema),
 * so a green test here is the regression line against silent schema drift.
 *
 * <p>Not privacy-critical (Constitution Principle VII test-order mandate
 * does not apply), but the schema encodes Principle III invariants
 * (bucketed counters, no per-request data) that later tests build on, so
 * validating it applies cleanly is worth a standing test.
 *
 * <p>T092 (sol-review M1) added {@code configured_tokens} (§6.6) and
 * {@code token_generation} (§6.7) within V001: the manual-token path needs
 * its own home separate from {@code enrolled_devices} (device pubkey NOT
 * NULL), and the monotonic ReloadTokens generation needs a persisted
 * source of truth. Pre-release, nothing has shipped, so the "schema lands
 * once" window (T012) is the intended time to amend V001 in lock-step
 * rather than ship a corrective V002. The count moved 5 → 7 deliberately.
 */
class V001MigrationTest {

    @TempDir
    Path tempDir;

    @Test
    void v001AppliesCleanlyAndCreatesAllSevenTables() throws SQLException {
        Path dbFile = tempDir.resolve("stargate-control.db");
        String url = "jdbc:sqlite:" + dbFile.toAbsolutePath();

        // Flyway applies the migration located under
        // src/main/resources/db/migration/ on the classpath.
        Flyway flyway = Flyway.configure().dataSource(url, "", "").target("001").load();
        flyway.migrate();

        Set<String> tables = userTables(url);
        // arch §6.1 — §6.7, in declaration order.
        assertTrue(tables.contains("enrolled_devices"), "arch §6.1 enrolled_devices missing");
        assertTrue(tables.contains("admin_credentials"), "arch §6.2 admin_credentials missing");
        assertTrue(tables.contains("tor_bridges"), "arch §6.3 tor_bridges missing");
        assertTrue(tables.contains("aggregate_counters"), "arch §6.4 aggregate_counters missing");
        assertTrue(tables.contains("audit_log"), "arch §6.5 audit_log missing");
        assertTrue(tables.contains("configured_tokens"), "arch §6.6 configured_tokens missing (T092)");
        assertTrue(tables.contains("token_generation"), "arch §6.7 token_generation missing (T092)");
        assertEquals(7, tables.size(),
            "exactly seven user tables expected (no churn within V001 beyond the T092 amendment); got " + tables);
    }

    @Test
    void flywayHistoryRecordsV001() throws SQLException {
        Path dbFile = tempDir.resolve("stargate-control.db");
        String url = "jdbc:sqlite:" + dbFile.toAbsolutePath();

        Flyway flyway = Flyway.configure().dataSource(url, "", "").target("001").load();
        flyway.migrate();

        // Flyway's own schema-history table must record exactly V001 at
        // success — a regression that disables Flyway or applies the SQL
        // out-of-band would surface here.
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT version, success FROM flyway_schema_history WHERE installed_rank >= 1");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next(), "flyway_schema_history empty after migrate()");
            // Flyway derives the version string from the filename V001__init.sql
            // verbatim ("001"), not as a normalised integer ("1").
            assertEquals("001", rs.getString("version"), "first installed version");
            assertEquals(1, rs.getInt("success"), "first migration recorded as success");
        }
    }

    @Test
    void legacyMigrationRemovesOperationalHistoryButPreservesCurrentAuth() throws Exception {
        String url = "jdbc:sqlite:" + tempDir.resolve("legacy.db");
        Flyway.configure().dataSource(url, "", "").target("001").load().migrate();
        try (Connection c = DriverManager.getConnection(url); var st = c.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("INSERT INTO audit_log(ts, actor, action, target, detail_json) "
                    + "VALUES(123, 'legacy-actor', 'enrolled', 'legacy-label', 'legacy-private-detail')");
            st.execute("INSERT INTO configured_tokens(label,verifier,created_at) VALUES('active', zeroblob(32),123)");
            st.execute("INSERT INTO configured_tokens(label,verifier,created_at,revoked_at) VALUES('revoked',zeroblob(32),123,456)");
            st.execute("INSERT INTO token_generation(generation) VALUES(42)");
        }
        Path backup = tempDir.resolve("retired-backup.db");
        Files.copy(tempDir.resolve("legacy.db"), backup);
        try (Connection walKeeper = DriverManager.getConnection(url)) {
        // Keep one connection open so WAL cleanup is an explicit operation, not
        // merely SQLite's automatic checkpoint when its last connection closes.
        assertTrue(!walKeeper.isClosed());
        Flyway.configure().dataSource(url, "", "").load().migrate();
        assertTrue(!userTables(url).contains("audit_log"), "legacy per-event journal must be removed");
        try (Connection c = DriverManager.getConnection(url); var st = c.createStatement()) {
            try (var rs = st.executeQuery("SELECT label FROM configured_tokens")) {
                assertTrue(rs.next());
                assertEquals("active", rs.getString(1));
                assertTrue(!rs.next(), "revoked token history must not survive migration");
            }
            try (var rs = st.executeQuery("SELECT generation FROM token_generation")) {
                assertTrue(rs.next());
                assertEquals(42, rs.getLong(1), "migration preserves auth authority");
            }
            try (var rs = st.executeQuery("PRAGMA table_info(configured_tokens)")) {
                Set<String> columns = new HashSet<>();
                while (rs.next()) columns.add(rs.getString("name"));
                assertEquals(Set.of("label", "verifier"), columns);
            }
            try (var checkpoint = st.executeQuery("PRAGMA wal_checkpoint(TRUNCATE)")) {
                assertTrue(checkpoint.next());
                assertEquals(0, checkpoint.getInt(1), "no reader may block cleanup");
            }
            st.execute("VACUUM");
            try (var checkpoint = st.executeQuery("PRAGMA wal_checkpoint(TRUNCATE)")) {
                assertTrue(checkpoint.next()); assertEquals(0, checkpoint.getInt(1));
            }
        }
        }
        String live = new String(Files.readAllBytes(tempDir.resolve("legacy.db")),
                java.nio.charset.StandardCharsets.ISO_8859_1);
        String retired = new String(Files.readAllBytes(backup), java.nio.charset.StandardCharsets.ISO_8859_1);
        assertTrue(!live.contains("legacy-private-detail"), "live SQLite pages cleaned, not forensic host erasure");
        assertTrue(retired.contains("legacy-private-detail"), "backups remain explicit operator cleanup work");
    }

    @Test
    void migrationBookkeepingRetainsSchemaIdentityWithoutInstallHistory() throws Exception {
        String url = "jdbc:sqlite:" + tempDir.resolve("schema-identity.db");
        Flyway flyway = Flyway.configure().dataSource(url, "", "").load();
        flyway.migrate();
        flyway.validate();
        try (Connection c = DriverManager.getConnection(url); var st = c.createStatement();
                var rows = st.executeQuery("SELECT installed_by, installed_on, execution_time "
                        + "FROM flyway_schema_history")) {
            while (rows.next()) {
                assertEquals("1970-01-01 00:00:00", rows.getString(2),
                        "schema checksums do not authorize an installation event journal");
                assertEquals("stargate", rows.getString(1));
                assertEquals(0, rows.getInt(3));
            }
        }
    }

    /** Returns the set of user-created tables (type='table', not sqlite_ internal). */
    private Set<String> userTables(String url) throws SQLException {
        Set<String> tables = new HashSet<>();
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'flyway_%'");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                tables.add(rs.getString("name"));
            }
        }
        return tables;
    }
}
