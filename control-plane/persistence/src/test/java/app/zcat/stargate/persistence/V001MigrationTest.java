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
 * and asserts the schema matches arch §6: exactly the five tables the
 * architecture spec mandates, no more, no less. The migration is a
 * contract-defining artefact (every future feature inherits this schema),
 * so a green test here is the regression line against silent schema drift.
 *
 * <p>Not privacy-critical (Constitution Principle VII test-order mandate
 * does not apply), but the schema encodes Principle III invariants
 * (bucketed counters, no per-request data) that later tests build on, so
 * validating it applies cleanly is worth a standing test.
 */
class V001MigrationTest {

    @TempDir
    Path tempDir;

    @Test
    void v001AppliesCleanlyAndCreatesAllFiveTables() throws SQLException {
        Path dbFile = tempDir.resolve("stargate-control.db");
        String url = "jdbc:sqlite:" + dbFile.toAbsolutePath();

        // Flyway applies the migration located under
        // src/main/resources/db/migration/ on the classpath.
        Flyway flyway = Flyway.configure().dataSource(url, "", "").load();
        flyway.migrate();

        Set<String> tables = userTables(url);
        // arch §6.1 — §6.5, in declaration order.
        assertTrue(tables.contains("enrolled_devices"), "arch §6.1 enrolled_devices missing");
        assertTrue(tables.contains("admin_credentials"), "arch §6.2 admin_credentials missing");
        assertTrue(tables.contains("tor_bridges"), "arch §6.3 tor_bridges missing");
        assertTrue(tables.contains("aggregate_counters"), "arch §6.4 aggregate_counters missing");
        assertTrue(tables.contains("audit_log"), "arch §6.5 audit_log missing");
        assertEquals(5, tables.size(),
            "exactly five user tables expected (no churn within V001); got " + tables);
    }

    @Test
    void flywayHistoryRecordsV001() throws SQLException {
        Path dbFile = tempDir.resolve("stargate-control.db");
        String url = "jdbc:sqlite:" + dbFile.toAbsolutePath();

        Flyway flyway = Flyway.configure().dataSource(url, "", "").load();
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
