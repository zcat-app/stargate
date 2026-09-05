// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Locale;
import java.util.stream.Stream;

import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.persistence.entity.AuditLog;
import io.agroal.api.AgroalDataSource;
import io.quarkus.hibernate.orm.panache.Panache;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.transaction.UserTransaction;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behavioural contract for {@link AuditLogService} (T036) against the REAL
 * stack — Agroal-pooled SQLite, Hibernate ORM + Panache, Flyway-migrated
 * {@code V001__init.sql} — the same wiring the runtime module boots (T041).
 * Row shape, vocabulary and actor constants come from data-model.md §4; the
 * append-only mechanism comes from the V001 triggers (arch §6.5).
 *
 * <p>Row-count assertions are DELTAS around each write: the append-only
 * triggers forbid the cleanup deletes a fresh-fixture style would need, so
 * rows accumulate across the run and every test is written to be independent
 * of prior content ({@code ORDER BY id DESC LIMIT 1} reads back the row the
 * test just appended; tests are single-threaded).
 *
 * <p>Read-back goes through raw JDBC with literal column names — asserting
 * the entity's mapping through the entity itself would be tautological.
 */
@QuarkusTest
class AuditLogServiceTest {

    private static final long TS_TOLERANCE_SECONDS = 5;

    /** Action → expected actor, per the data-model.md §4 actor constants. */
    private static final String ACTOR_TOKEN_ACTIONS = "tokens.yaml";
    private static final String ACTOR_SIDECAR_TRANSITIONS = "system";

    @Inject
    AuditLogService service;

    @Inject
    AgroalDataSource dataSource;

    @Inject
    UserTransaction utx;

    /** The five §4 rows: action, target, detail_json, expected actor. */
    static Stream<Arguments> sectionFourRows() {
        return Stream.of(
            Arguments.of("enrolled", "alice-laptop",
                "{\"source\":\"tokens.yaml\",\"generation\":1}", ACTOR_TOKEN_ACTIONS),
            Arguments.of("revoked", "bob",
                "{\"source\":\"tokens.yaml\",\"generation\":2}", ACTOR_TOKEN_ACTIONS),
            Arguments.of("config_error", "tokens.yaml",
                "{\"kind\":\"parse\",\"line\":3}", ACTOR_TOKEN_ACTIONS),
            Arguments.of("sidecar_healthy", "tor",
                "{\"generation\":2}", ACTOR_SIDECAR_TRANSITIONS),
            Arguments.of("sidecar_unhealthy", "tor",
                "{\"kind\":\"STOPPED\"}", ACTOR_SIDECAR_TRANSITIONS));
    }

    @ParameterizedTest
    @MethodSource("sectionFourRows")
    void writePersistsEachOfTheFiveVocabularyActionsWithTheSectionFourActor(
            String action, String target, String detailJson, String expectedActor) {
        long before = countAuditRows();

        service.write(action, target, detailJson);

        assertEquals(before + 1, countAuditRows(), "exactly one row appended");
        AuditRow row = readLastAuditRow();
        assertEquals(expectedActor, row.actor(), "actor per §4 constants");
        assertEquals(action, row.action());
        assertEquals(target, row.target());
        assertEquals(detailJson, row.detailJson(), "detail_json stored verbatim");
        assertTrue(Math.abs(row.ts() - Instant.now().getEpochSecond()) <= TS_TOLERANCE_SECONDS,
            "ts is write-time unix seconds; got " + row.ts());
        assertTrue(row.id() > 0, "id is DB-generated (SQLite IDENTITY); got " + row.id());
    }

    @Test
    void writeRejectsActionOutsideTheFixedVocabularyWithoutWritingARow() {
        // bridge_toggle sits in V001 §6.5's baseline enum comment but outside
        // THIS feature's §4 vocabulary; its writer arrives with a later
        // feature, whose lock-step amendment extends the service.
        long before = countAuditRows();

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> service.write("bridge_toggle", "Bridge 192.0.2.1:9001 ABCDEF", "{}"));

        assertNotNull(ex.getMessage(), "rejection must carry a message");
        assertTrue(ex.getMessage().contains("bridge_toggle"),
            "rejection names the offending action; got: " + ex.getMessage());
        assertEquals(before, countAuditRows(), "rejected action writes no row");
    }

    @Test
    void writeAssignsDistinctGeneratedIds() {
        // Pins what the raw-JDBC read-back CAN observe: every append gets a
        // fresh, DB-generated, non-repeating id. (The ORM's generation
        // strategy itself is not observable from here — SQLite's rowid alias
        // would also auto-assign an id if the mapping were removed — but a
        // constant/reused id cannot survive: the audit_log_no_replace
        // trigger rejects any INSERT whose id already exists, so write()
        // would throw and the read-back would not see two rows.)
        long first = appendAndReadBackId("enrolled", "id-distinct-probe",
            "{\"source\":\"tokens.yaml\",\"generation\":10}");
        long second = appendAndReadBackId("enrolled", "id-distinct-probe",
            "{\"source\":\"tokens.yaml\",\"generation\":11}");
        assertNotEquals(first, second, "successive appends get distinct generated ids");
    }

    @Test
    void panacheMergeAndDeleteAreRejectedByTheAppendOnlyTriggers() {
        // The ORM path must not become a mutation bypass: PanacheEntityBase
        // exposes merge()/delete() mutators, but the V001 triggers reject the
        // underlying UPDATE/DELETE by mechanism (arch §6.5). Each probe runs
        // in its own programmatic transaction so a failed flush cannot poison
        // the other probe's session.
        long id = appendAndReadBackId("enrolled", "orm-path-probe",
            "{\"source\":\"tokens.yaml\",\"generation\":1}");
        String detailBefore = readLastAuditRow().detailJson();

        // UPDATE path: dirty a managed entity and flush, so the trigger sees
        // a real UPDATE statement (an unmodified merge() would be optimized
        // away and prove nothing).
        Exception updateFailure = assertTransactionFails(() -> {
            AuditLog row = (AuditLog) AuditLog.findById(id);
            assertNotNull(row, "seeded row visible through the ORM path");
            row.actor = ACTOR_SIDECAR_TRANSITIONS; // any mutation dirties the row
            Panache.getEntityManager().flush();
        });
        assertTrue(causeChainContains(updateFailure, "append-only"),
            "UPDATE must be rejected by the append-only trigger; got: " + updateFailure);

        // DELETE path.
        Exception deleteFailure = assertTransactionFails(() -> {
            AuditLog row = (AuditLog) AuditLog.findById(id);
            assertNotNull(row);
            row.delete();
            Panache.getEntityManager().flush();
        });
        assertTrue(causeChainContains(deleteFailure, "append-only"),
            "DELETE must be rejected by the append-only trigger; got: " + deleteFailure);

        // Both aborted statements left the row untouched (RAISE(ABORT) rolls
        // back the statement; the surrounding transaction rolls back).
        AuditRow after = readLastAuditRow();
        assertEquals(id, after.id(), "row still present");
        assertEquals(ACTOR_TOKEN_ACTIONS, after.actor(), "actor unchanged after aborted mutations");
        assertEquals(detailBefore, after.detailJson(), "detail_json unchanged after aborted mutations");
    }

    @Test
    void serviceSatisfiesTheTokenLoaderAuditSinkPort() {
        // T035a pins the seam: the loader binds TokenLoaderContract.AuditSink;
        // this service is its production adapter, with the exact
        // write(action, target, detailJson) shape and actor derivation
        // ("the sink derives actor (tokens.yaml for the three token actions)
        // from the action").
        TokenLoaderContract.AuditSink sink = service;

        long before = countAuditRows();
        sink.write("enrolled", "sink-port-probe", "{\"source\":\"tokens.yaml\",\"generation\":9}");

        assertEquals(before + 1, countAuditRows(), "row appended through the port");
        AuditRow row = readLastAuditRow();
        assertEquals(ACTOR_TOKEN_ACTIONS, row.actor(), "port call derives the token-action actor");
        assertEquals("enrolled", row.action());
        assertEquals("sink-port-probe", row.target());
    }

    // --- helpers ---------------------------------------------------------

    /** The last appended audit row, read back through raw JDBC. */
    private record AuditRow(long id, long ts, String actor, String action,
                            String target, String detailJson) {
    }

    private long countAuditRows() {
        try (Connection c = dataSource.getConnection();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM audit_log")) {
            assertTrue(rs.next());
            return rs.getLong(1);
        } catch (SQLException e) {
            throw new IllegalStateException("count failed", e);
        }
    }

    private AuditRow readLastAuditRow() {
        try (Connection c = dataSource.getConnection();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                 "SELECT id, ts, actor, action, target, detail_json "
                 + "FROM audit_log ORDER BY id DESC LIMIT 1")) {
            assertTrue(rs.next(), "at least one audit row exists");
            return new AuditRow(
                rs.getLong("id"), rs.getLong("ts"), rs.getString("actor"),
                rs.getString("action"), rs.getString("target"), rs.getString("detail_json"));
        } catch (SQLException e) {
            throw new IllegalStateException("read-back failed", e);
        }
    }

    private long appendAndReadBackId(String action, String target, String detailJson) {
        service.write(action, target, detailJson);
        return readLastAuditRow().id();
    }

    /**
     * Runs {@code action} inside one programmatic JTA transaction (the
     * blocking Panache API has no {@code withTransaction}) and expects the
     * database to reject it. Returns the failure — never null; a transaction
     * that commits fails the probe outright, because the append-only
     * properties under test must never pass silently.
     */
    private Exception assertTransactionFails(ThrowingAction action) {
        try {
            utx.begin();
            action.run();
            utx.commit();
        } catch (Exception e) {
            try {
                utx.rollback();
            } catch (Exception rollbackFailure) {
                e.addSuppressed(rollbackFailure);
            }
            return e;
        }
        throw new AssertionError("transaction committed; expected an append-only rejection");
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }

    /**
     * Depth-capped walk of {@code failure}'s cause chain looking for
     * {@code needle}. The cap doubles as the self-referential-cause guard
     * ({@code getCause()} may return the throwable itself), avoiding a
     * reference-equality comparison that Error Prone's ReferenceEquality
     * check rejects.
     */
    private static boolean causeChainContains(Throwable failure, String needle) {
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < 16; depth++) {
            String message = cause.getMessage();
            if (message != null && message.toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }
}
