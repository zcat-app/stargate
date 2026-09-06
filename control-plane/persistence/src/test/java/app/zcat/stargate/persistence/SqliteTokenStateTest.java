// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import app.zcat.stargate.auth.TokenLoaderContract;
import io.agroal.api.AgroalDataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.UserTransaction;
import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.Test;

/**
 * Behavioural contract for {@link SqliteTokenState} (T041; Principle VII
 * tests-first — the token push path is authentication surface) against the
 * REAL stack — Agroal-pooled SQLite, Hibernate ORM, Flyway-migrated
 * {@code V001__init.sql} — the same wiring the runtime boot relies on (the
 * T036 test shape, promoted). Ports: data-model.md §1.8
 * ({@code token_generation} singleton) and §1.9 ({@code configured_tokens});
 * the transactional interplay with the §4 audit sink is the property the
 * loader's write order (§1.7: store → generation → push, diff rows inside
 * the store transaction) depends on.
 *
 * <p>The append-only triggers forbid cleanup deletes, so row assertions are
 * DELTAS around each write and every probe uses labels unique to itself —
 * the established AuditLogServiceTest discipline.
 */
@QuarkusTest
class SqliteTokenStateTest {

    private static final byte[] VERIFIER_A = fill((byte) 0xa1);
    private static final byte[] VERIFIER_B = fill((byte) 0xb2);

    @Inject
    SqliteTokenState state;

    @Inject
    AuditLogService audit;

    @Inject
    AgroalDataSource dataSource;

    @Inject
    EntityManager em;

    @Inject
    UserTransaction utx;

    private static byte[] fill(byte b) {
        byte[] out = new byte[32];
        java.util.Arrays.fill(out, b);
        return out;
    }

    private int countAuditRows() {
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM audit_log")) {
            rs.next();
            return rs.getInt(1);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private @Nullable Row readTokenRow(String label) {
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT label, verifier, created_at, revoked_at "
                        + "FROM configured_tokens WHERE label = '" + label + "'")) {
            if (!rs.next()) {
                return null;
            }
            return new Row(rs.getString(1), rs.getBytes(2), rs.getLong(3),
                    rs.getObject(4) == null ? null : rs.getLong(4));
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private long readGenerationRowValue() {
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT generation FROM token_generation")) {
            if (!rs.next()) {
                return 0L;
            }
            return rs.getLong(1);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private int countGenerationRows() {
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM token_generation")) {
            rs.next();
            return rs.getInt(1);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Row(String label, byte[] verifier, long createdAt, @Nullable Long revokedAt) {
    }

    // --- port conformance --------------------------------------------------------

    @Test
    void satisfiesBothTokenLoaderContractPorts() {
        assertTrue(state instanceof TokenLoaderContract.ConfiguredTokenStore,
                "SqliteTokenState is the production ConfiguredTokenStore adapter (§1.9)");
        assertTrue(state instanceof TokenLoaderContract.GenerationStore,
                "SqliteTokenState is the production GenerationStore adapter (§1.8)");
        // a call through each port reference — the shape the loader (T035) binds
        TokenLoaderContract.GenerationStore generations = state;
        TokenLoaderContract.ConfiguredTokenStore store = state;
        assertEquals(state.lastGeneration(), generations.lastGeneration());
        assertTrue(store.storedTokens() instanceof Collection<?>);
    }

    // --- §1.8 generation singleton ------------------------------------------------

    @Test
    void generationProposesZeroOnFreshStateAndRecordUpsertsSingleton() {
        long before = state.lastGeneration();
        assertTrue(before >= 0, "lastGeneration is defined whether or not the row exists");
        long next = before + 3;

        state.record(next);

        assertEquals(next, state.lastGeneration(), "the proposal base follows the record (§1.8)");
        assertEquals(next, readGenerationRowValue(), "the singleton row carries the generation");
        assertEquals(1, countGenerationRows(), "record() upserts — the singleton stays one row");

        state.record(next);
        assertEquals(1, countGenerationRows(), "re-recording the same value adds no row");
        assertEquals(next, state.lastGeneration());
    }

    @Test
    void generationReadsBackThroughAFreshInstance() {
        // restart-safety at the DB layer: a NEW adapter over the same store
        // reads the persisted value — the restarted CP proposes last+1, not 1
        // (§1.8; sol-review M1; TokenLifecycleContractTest#restartProposesLastPlusOneNotOne
        // pins the arithmetic, this pins the persistence).
        long before = state.lastGeneration();
        state.record(before + 5);

        SqliteTokenState fresh = new SqliteTokenState(em, utx);
        assertEquals(before + 5, fresh.lastGeneration(),
                "a fresh adapter reads the persisted singleton (restart-safety, §1.8)");
    }

    @Test
    void absentGenerationRowReadsAsZeroDeterministically() throws SQLException {
        // §1.8 DB-wipe row, made deterministic (round-1 review F3: the
        // shared-DB delta style left the absent-row branch order-dependent).
        // Wiping the singleton simulates the CP-DB-wipe scenario exactly —
        // token_generation carries no append-only guard (CP-owned state,
        // unlike audit_log) and no adapter delete exists, because the wipe is
        // itself the scenario under test. The proposal base must read 0 so
        // the wiped CP proposes generation 1 and the DP-side reconciliation
        // absorbs the restore.
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement()) {
            s.executeUpdate("DELETE FROM token_generation");
        }
        assertEquals(0L, state.lastGeneration(),
                "no token_generation row ⇒ 0 (§1.8 DB-wipe row); the proposal is 1");
    }

    // --- §1.9 configured_tokens ----------------------------------------------------

    @Test
    void upsertStampsCreatedAtOnceAndRefreshesVerifier() {
        String label = "created-at-probe-" + System.nanoTime();
        // upsert/delete are the loader's in-window writes (§1.7): each probe
        // drives them through the same begin/commit shape the loader uses.
        state.begin();
        state.upsert(label, VERIFIER_A);
        state.commit();
        Row first = readTokenRow(label);
        assertNotNull(first, "the row persists");
        assertTrue(first.createdAt() > 0, "created_at stamped at first sight (§1.9)");
        assertTrue(java.util.Arrays.equals(VERIFIER_A, first.verifier()), "verifier persisted");
        assertNull(first.revokedAt(), "a live record has no revoked_at");

        state.begin();
        state.upsert(label, VERIFIER_B);
        state.commit();
        Row second = readTokenRow(label);
        assertNotNull(second, "the re-upserted row persists");
        assertEquals(first.createdAt(), second.createdAt(),
                "re-upserting the same label keeps created_at (§1.9: stamped once)");
        assertTrue(java.util.Arrays.equals(VERIFIER_B, second.verifier()),
                "the fresh verifier overwrites (§1.7 full-set rewrite — the pepper-rotation property)");
        assertNull(second.revokedAt());

        List<String> labels = state.storedTokens().stream()
                .map(TokenLoaderContract.StoredToken::label)
                .collect(Collectors.toList());
        assertTrue(labels.contains(label), "the label feeds the diff (storedLabels)");
    }

    @Test
    void deleteStampsRevokedAtAndRemovesFromStoredLabels() {
        String label = "revoke-probe-" + System.nanoTime();
        state.begin();
        state.upsert(label, VERIFIER_A);
        state.delete(label);
        state.commit();

        Row row = readTokenRow(label);
        assertNotNull(row, "delete is a soft delete — the row remains (§1.9 revoked_at)");
        assertNotNull(row.revokedAt(), "revoked_at stamped on removal (§1.9)");
        assertTrue(state.storedTokens().stream().noneMatch(t -> t.label().equals(label)),
                "a deleted label leaves the diff view (§1.4/§1.9)");
    }

    // --- the §1.7 transactional window: audit rows join the store transaction ------

    @Test
    void auditRowsInsideTheStoreWindowCommit() {
        int before = countAuditRows();
        String label = "audit-commit-probe-" + System.nanoTime();

        state.begin();
        audit.write("enrolled", label, "{\"source\":\"tokens.yaml\",\"generation\":42}");
        state.commit();

        assertEquals(before + 1, countAuditRows(),
                "the diff row written inside begin/commit persists (§1.7 — the loader's window)");
    }

    @Test
    void rollbackDiscardsBothStoreWritesAndAuditRows() {
        int before = countAuditRows();
        String label = "audit-rollback-probe-" + System.nanoTime();

        state.begin();
        audit.write("enrolled", label, "{\"source\":\"tokens.yaml\",\"generation\":43}");
        state.upsert(label, VERIFIER_A);
        state.rollback();

        assertEquals(before, countAuditRows(),
                "a rollback discards the diff rows with the store writes (§4 atomicity)");
        assertNull(readTokenRow(label), "the upsert is discarded too");
        assertTrue(state.storedTokens().stream().noneMatch(t -> t.label().equals(label)));
    }
}
