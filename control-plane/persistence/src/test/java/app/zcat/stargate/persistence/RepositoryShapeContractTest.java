// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the exact insert/update/delete DML shapes the repositories will
 * consume, against a fresh Flyway-migrated SQLite database. This pins that the
 * schema actually accepts the field sets the data model documents — not just
 * that the right columns exist (that is {@link V001SchemaContractTest}'s job)
 * but that the real statements round-trip. T100 acceptance #2.
 *
 * <p>The load-bearing case is the {@code configured_tokens} vs
 * {@code enrolled_devices} split (data-model.md §1.9): a manual
 * {@code tokens.yaml} record carries {@code (label, verifier)} only — no device
 * public key — so it MUST be insertable into the dedicated table and MUST NOT
 * be insertable into {@code enrolled_devices} (whose {@code pubkey} and
 * {@code token_hash} are both NOT NULL). That is the contradiction T100 was
 * opened to catch (T100 Context; remediates T012).
 *
 * <p>Tables exercised, mapped to the data-model consumers named in acceptance
 * #2: {@code configured_tokens} (configured tokens), {@code audit_log} (audit
 * logging + sidecar-event state — there is no dedicated sidecar_state table;
 * sidecar transitions are audit rows per §4), {@code aggregate_counters}
 * (counters), and {@code tor_bridges} (toggleable sidecar-adjacent config
 * state). {@code audit_log} mutation is covered by {@link AuditLogAppendOnlyTest};
 * here we only INSERT audit rows.
 */
class RepositoryShapeContractTest {

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

    // --- configured tokens (data-model.md §1.9) --------------------------

    @Test
    void configuredTokenInsertsVerifierWithoutAnyEnrollmentPubkey() throws SQLException {
        // The must-hold (T100 Analysis): a manual token record is insertable
        // with (label, verifier, created_at) and NO device key / fake fields.
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "INSERT INTO configured_tokens (label, verifier, created_at) VALUES (?,?,?)")) {
            ps.setString(1, "alice-laptop");
            ps.setBytes(2, new byte[32]);   // 32-byte HMAC tag placeholder
            ps.setLong(3, 1_700_000_000L);
            ps.executeUpdate();
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT label, last_seen_hour, revoked_at FROM configured_tokens WHERE label='alice-laptop'");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(null, rs.getObject("last_seen_hour"), "last_seen_hour starts NULL");
            assertEquals(null, rs.getObject("revoked_at"), "revoked_at starts NULL");
        }
    }

    @Test
    void configuredTokenRevocationMarksRevokedAt() throws SQLException {
        // data-model.md §1.9: when a label disappears from tokens.yaml its
        // row is UPDATEd with revoked_at (NOT deleted — audit linkage persists).
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ins = c.prepareStatement(
                 "INSERT INTO configured_tokens (label, verifier, created_at) VALUES (?,?,?)")) {
            ins.setString(1, "alice-desktop");
            ins.setBytes(2, new byte[32]);
            ins.setLong(3, 1_700_000_000L);
            ins.executeUpdate();
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement upd = c.prepareStatement(
                 "UPDATE configured_tokens SET revoked_at=? WHERE label=?")) {
            upd.setLong(1, 1_700_000_100L);
            upd.setString(2, "alice-desktop");
            assertEquals(1, upd.executeUpdate());
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "SELECT revoked_at FROM configured_tokens WHERE label='alice-desktop'");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(1_700_000_100L, rs.getLong("revoked_at"));
        }
    }

    @Test
    void manualTokenCannotBeInsertedIntoEnrolledDevicesWithoutPubkey() {
        // Proves WHY configured_tokens exists: enrolled_devices.pubkey and
        // token_hash are both NOT NULL (arch §6.1), so a manual token — which
        // has no device key — cannot live there. Inserting without pubkey MUST
        // fail; that failure is the contradiction the dedicated table resolves.
        SQLException ex = assertThrows(SQLException.class, () -> {
            try (Connection c = DriverManager.getConnection(url, "", "");
                 PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO enrolled_devices (name, created_at) VALUES (?,?)")) {
                ps.setString(1, "should-not-fit");
                ps.setLong(2, 1_700_000_000L);
                ps.executeUpdate();
            }
        });
        // getMessage() is @Nullable (NullAway, T104a-gated test source);
        // assertNotNull both fails fast on a message-less exception and
        // refines the contract for the deref below (same pattern as
        // AuditLogAppendOnlyTest).
        assertNotNull(ex.getMessage(), "enrolled_devices insert must raise with a message");
        assertTrue(ex.getMessage().toLowerCase().contains("not null"),
                   "enrolled_devices insert without pubkey must fail NOT NULL; got: " + ex.getMessage());
    }

    // --- audit logging + sidecar-event state (data-model.md §4) ----------

    @Test
    void documentedAuditActionsInsertCleanly() throws SQLException {
        // Every action value the v1 data model emits (§4) must round-trip. The
        // fixed vocabulary is application-enforced; here we only confirm the
        // audit_log row accepts each documented shape.
        String[][] rows = {
            {1_700_000_000L + "", "tokens.yaml", "enrolled",       "alice",   "{\"source\":\"tokens.yaml\",\"generation\":1}"},
            {1_700_000_001L + "", "tokens.yaml", "revoked",        "bob",     "{\"source\":\"tokens.yaml\",\"generation\":2}"},
            {1_700_000_002L + "", "tokens.yaml", "config_error",   "tokens.yaml", "{\"kind\":\"parse\",\"line\":3}"},
            {1_700_000_003L + "", "system",      "sidecar_healthy",  "tor",   "{\"generation\":2}"},
            {1_700_000_004L + "", "system",      "sidecar_unhealthy", "tor",  "{\"kind\":\"STOPPED\"}"},
        };
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "INSERT INTO audit_log (ts, actor, action, target, detail_json) VALUES (?,?,?,?,?)")) {
            for (String[] r : rows) {
                ps.setLong(1, Long.parseLong(r[0]));
                ps.setString(2, r[1]);
                ps.setString(3, r[2]);
                ps.setString(4, r[3]);
                ps.setString(5, r[4]);
                ps.addBatch();
            }
            int[] n = ps.executeBatch();
            assertEquals(rows.length, n.length);
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM audit_log")) {
            assertTrue(rs.next());
            assertEquals(rows.length, rs.getInt(1));
        }
    }

    // --- counters (data-model.md §3 / arch §6.4) ------------------------

    @Test
    void counterUpsertIncrementsAndRejectsBadRoute() throws SQLException {
        // The CP-side increment shape: INSERT ... ON CONFLICT DO UPDATE.
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ps = c.prepareStatement(
                 "INSERT INTO aggregate_counters (route, hour_bucket, request_count, byte_count) "
                 + "VALUES (?,?,1,128) "
                 + "ON CONFLICT(route, hour_bucket) DO UPDATE SET "
                 + "request_count=request_count+excluded.request_count, "
                 + "byte_count=byte_count+excluded.byte_count")) {
            ps.setString(1, "TOR");
            ps.setLong(2, 1_700_000_000L / 3600);
            ps.executeUpdate();
            // Second increment on the same bucket exercises the conflict branch.
            ps.executeUpdate();
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                 "SELECT request_count, byte_count FROM aggregate_counters WHERE route='TOR'")) {
            assertTrue(rs.next());
            assertEquals(2, rs.getInt("request_count"), "two increments");
            assertEquals(256, rs.getInt("byte_count"), "bytes summed");
        }
        // CHECK (route IN (...)) rejects an out-of-vocabulary route.
        assertThrows(SQLException.class, () -> {
            try (Connection c = DriverManager.getConnection(url, "", "");
                 PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO aggregate_counters (route, hour_bucket) VALUES (?,?)")) {
                ps.setString(1, "VPN");   // not a v1 route
                ps.setLong(2, 1_700_000_000L / 3600);
                ps.executeUpdate();
            }
        });
    }

    // --- tor_bridges: toggleable sidecar-adjacent config (arch §6.3) -----

    @Test
    void torBridgeInsertAndToggleShape() throws SQLException {
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement ins = c.prepareStatement(
                 "INSERT INTO tor_bridges (bridge_line, transport, enabled, added_at) VALUES (?,?,?,?)")) {
            ins.setString(1, "Bridge 192.0.2.1:9001 ABCDEF");
            ins.setString(2, "obfs4");
            ins.setInt(3, 0);   // default off (Constitution v1 Scope)
            ins.setLong(4, 1_700_000_000L);
            ins.executeUpdate();
        }
        // The toggle: UPDATE enabled. (admin-UI bridge_toggle path.)
        try (Connection c = DriverManager.getConnection(url, "", "");
             PreparedStatement upd = c.prepareStatement(
                 "UPDATE tor_bridges SET enabled=1 WHERE bridge_line=?")) {
            upd.setString(1, "Bridge 192.0.2.1:9001 ABCDEF");
            assertEquals(1, upd.executeUpdate());
        }
        try (Connection c = DriverManager.getConnection(url, "", "");
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT enabled FROM tor_bridges")) {
            assertTrue(rs.next());
            assertEquals(1, rs.getInt("enabled"));
        }
    }
}
