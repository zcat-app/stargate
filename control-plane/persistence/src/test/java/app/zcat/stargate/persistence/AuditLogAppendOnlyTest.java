// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Historical V001 baseline only. T152 migration and AuditLogServiceTest cover the active V002 schema.
 * Append-only enforcement for {@code audit_log} (arch §6.5 "Inserts only; no
 * UPDATE/DELETE in code paths"; Constitution Principle III — privacy-preserving
 * <em>by construction</em>). The schema MUST reject {@code UPDATE} and
 * {@code DELETE} on {@code audit_log} by mechanism (SQLite triggers), not by
 * caller discipline: the audit log is the tamper-evidence surface for admin
 * actions, so its append-only nature may not depend on every code path
 * remembering not to mutate it.
 *
 * <p>T100 acceptance #3. Privacy-critical (Constitution Principle VII): this is
 * the regression line for the {@code audit_log} integrity invariant. The test
 * is authored before the triggers and driven green by amending
 * {@code V001__init.sql} — the sanctioned pre-release "schema lands once"
 * window (see {@link V001MigrationTest}'s class Javadoc).
 */
class AuditLogAppendOnlyTest {

    @TempDir
    Path tempDir;

    private String url;

    @BeforeEach
    void migrateAndSeed() throws SQLException {
        Path dbFile = tempDir.resolve("stargate-control.db");
        url = "jdbc:sqlite:" + dbFile.toAbsolutePath();
        Flyway flyway = Flyway.configure().dataSource(url, "", "").target("001").load();
        flyway.migrate();
        // Seed one row so UPDATE/DELETE have a concrete target. This is the
        // documented enrolled-action shape (data-model.md §4).
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "INSERT INTO audit_log (ts, actor, action, target, detail_json) "
                 + "VALUES (?,?,?,?,?)")) {
            ps.setLong(1, 1_700_000_000L);
            ps.setString(2, "tokens.yaml");
            ps.setString(3, "enrolled");
            ps.setString(4, "alice-laptop");
            ps.setString(5, "{\"source\":\"tokens.yaml\",\"generation\":1}");
            ps.executeUpdate();
        }
    }

    @Test
    void updateOnAuditLogIsRejectedAndLeavesRowUntouched() throws SQLException {
        SQLException ex = assertThrows(SQLException.class, () -> {
            try (Connection c = DriverManager.getConnection(url, "", "");
                 PreparedStatement ps = c.prepareStatement(
                     "UPDATE audit_log SET actor = 'forged' WHERE id = 1")) {
                ps.executeUpdate();
            }
        });
        // The trigger's diagnostic must surface so a stack trace is unambiguous
        // about WHICH invariant fired (not, e.g., a stray FK constraint).
        assertNotNull(ex.getMessage(), "UPDATE on audit_log must raise");
        assertTrue(
            ex.getMessage().toLowerCase(Locale.ROOT).contains("append-only"),
            "UPDATE must be rejected by the append-only trigger; got: " + ex.getMessage());

        // Semantic certainty independent of driver error-code mapping: the row
        // is unchanged after the aborted mutation (RAISE(ABORT) rolls back the
        // statement).
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT actor FROM audit_log WHERE id = 1");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals("tokens.yaml", rs.getString("actor"),
                "append-only trigger must not let the UPDATE take effect");
        }
    }

    @Test
    void deleteOnAuditLogIsRejectedAndKeepsAllRows() throws SQLException {
        SQLException ex = assertThrows(SQLException.class, () -> {
            try (Connection c = DriverManager.getConnection(url, "", "");
                 PreparedStatement ps = c.prepareStatement(
                     "DELETE FROM audit_log WHERE id = 1")) {
                ps.executeUpdate();
            }
        });
        assertNotNull(ex.getMessage(), "DELETE on audit_log must raise");
        assertTrue(
            ex.getMessage().toLowerCase(Locale.ROOT).contains("append-only"),
            "DELETE must be rejected by the append-only trigger; got: " + ex.getMessage());

        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT COUNT(*) FROM audit_log");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(1, rs.getInt(1),
                "append-only trigger must not let the DELETE take effect");
        }
    }

    @Test
    void insertOnAuditLogIsPermitted() throws SQLException {
        // Sanity: append-only must NOT block the one legitimate operation.
        // If this fails, the trigger is over-broad (e.g. fired BEFORE INSERT
        // unconditionally, or the EXISTS guard matched a non-colliding row).
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "INSERT INTO audit_log (ts, actor, action, target, detail_json) "
                 + "VALUES (?,?,?,?,?)")) {
            ps.setLong(1, 1_700_000_001L);
            ps.setString(2, "system");
            ps.setString(3, "sidecar_healthy");
            ps.setString(4, "tor");
            ps.setString(5, "{\"generation\":1}");
            ps.executeUpdate();
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT COUNT(*) FROM audit_log");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(2, rs.getInt(1), "INSERT must still succeed on audit_log");
        }
    }

    @Test
    void insertOrReplaceOverwriteIsRejectedAndLeavesRowUntouched() throws SQLException {
        // stargate-redteam M1: under the default recursive_triggers=OFF, SQLite's
        // REPLACE conflict resolution deletes the conflicting PK row WITHOUT
        // firing BEFORE DELETE, so the no_delete trigger alone does not stop an
        // INSERT OR REPLACE from silently rewriting an existing audit row. The
        // audit_log_no_replace BEFORE-INSERT trigger closes this at INSERT time
        // by detecting the already-existing id — connection-config-independent.
        // This test must not set PRAGMA recursive_triggers (it mirrors the
        // production default) so it stays a live regression line for the bypass.
        SQLException ex = assertThrows(SQLException.class, () -> {
            try (Connection c = DriverManager.getConnection(url, "", "");
                 PreparedStatement ps = c.prepareStatement(
                     "INSERT OR REPLACE INTO audit_log (id, ts, actor, action, target, detail_json) "
                     + "VALUES (1, 1700000099, 'forged', 'wipe', null, null)")) {
                ps.executeUpdate();
            }
        });
        assertNotNull(ex.getMessage(), "INSERT OR REPLACE overwrite must raise");
        assertTrue(
            ex.getMessage().toLowerCase(Locale.ROOT).contains("append-only"),
            "overwrite must be rejected by the append-only trigger; got: " + ex.getMessage());

        // The seeded row (id=1, actor='tokens.yaml') is untouched.
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT actor, action FROM audit_log WHERE id = 1");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals("tokens.yaml", rs.getString("actor"));
            assertEquals("enrolled", rs.getString("action"));
        }
    }

    @Test
    void appendOnlyTriggersAreInstalled() throws SQLException {
        // Guards against a future migration dropping a trigger. All three must
        // be present so no mutation path (UPDATE / DELETE / REPLACE-overwrite)
        // is left unenforced.
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'audit_log_%'");
             ResultSet rs = ps.executeQuery()) {
            boolean hasNoUpdate = false;
            boolean hasNoDelete = false;
            boolean hasNoReplace = false;
            while (rs.next()) {
                String name = rs.getString("name");
                hasNoUpdate |= "audit_log_no_update".equals(name);
                hasNoDelete |= "audit_log_no_delete".equals(name);
                hasNoReplace |= "audit_log_no_replace".equals(name);
            }
            assertTrue(hasNoUpdate, "audit_log_no_update trigger missing");
            assertTrue(hasNoDelete, "audit_log_no_delete trigger missing");
            assertTrue(hasNoReplace, "audit_log_no_replace trigger missing (redteam M1)");
        }
    }
}
