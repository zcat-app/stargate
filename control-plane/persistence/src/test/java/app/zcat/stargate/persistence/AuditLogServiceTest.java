// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.persistence;

import java.sql.Connection;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;
import io.agroal.api.AgroalDataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.transaction.UserTransaction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Real SQLite/JTA tests derived from Constitution III, data-model §4 and T152. */
@QuarkusTest
class AuditLogServiceTest {
    @Inject AuditLogService service;
    @Inject AgroalDataSource dataSource;
    @Inject UserTransaction utx;
    private final MutableClock clock = new MutableClock();
    private static final long HOUR = 1_800_000_000L;

    @BeforeEach
    void reset() throws Exception {
        service.close();
        try (Connection c = dataSource.getConnection(); var st = c.createStatement()) {
            st.executeUpdate("DELETE FROM operational_aggregates");
        }
        clock.seconds = HOUR + 20;
        service.initialize(clock, true);
    }

    @Test
    void operationalEventsDoNotPersistPerEventRows() throws Exception {
        service.write("enrolled", "T152-private-label", "{\"generation\":8675309}");
        service.write("enrolled", "T152-private-label", "{\"generation\":8675310}");
        service.flush();
        assertEquals(0, nonzeroRowCount());
        clock.seconds = HOUR + 3600;
        service.flush();
        assertEquals(2, count(HOUR, "enrolled"));
        assertEquals(1, nonzeroRowCount(), "one count, not two event records");
        assertEquals(Set.of("hour_bucket", "category", "count"), columns());
    }

    @Test
    void finalizedBucketsNeverChangeDuringPollingOrClockRegression() throws Exception {
        service.write("revoked", "secret", "detail");
        clock.seconds += 3600;
        service.flush();
        for (int i = 0; i < 10; i++) {
            service.write("revoked", "other", "detail");
            service.flush();
            assertEquals(1, count(HOUR, "revoked"));
            assertEquals(1, nonzeroRowCount());
        }
        clock.seconds = HOUR + 10;
        service.write("revoked", "old-clock", "detail");
        service.flush();
        assertEquals(1, count(HOUR, "revoked"));
        // A restart must not reopen any previously persisted hour/category.
        service.initialize(clock, true);
        service.write("enrolled", "old-clock-new-category", "detail");
        clock.seconds = HOUR + 3600;
        service.flush();
        assertEquals(1, nonzeroRowCount());
    }

    @Test
    void transactionCommitCountsAtCompletionAndRollbackDiscardsEvents() throws Exception {
        utx.begin();
        service.write("enrolled", "committed", "detail");
        clock.seconds = HOUR + 3600;
        service.flush();
        utx.commit();
        assertEquals(0, nonzeroRowCount(), "commit after boundary belongs to the new open hour");
        utx.begin();
        service.write("revoked", "rolled-back", "detail");
        utx.rollback();
        clock.seconds += 3600;
        service.flush();
        assertEquals(1, count(HOUR + 3600, "enrolled"));
        assertEquals(1, nonzeroRowCount());
    }

    @Test
    void retentionExpiresAtSevenDaysFromBucketEndAndCanBeDisabled() throws Exception {
        service.write("config_error", "secret", "detail");
        clock.seconds = HOUR + 3600;
        service.flush();
        clock.seconds = HOUR + 3600 + 7 * 86400 - 1;
        service.flush();
        assertEquals(1, nonzeroRowCount());
        clock.seconds++;
        service.flush();
        assertEquals(0, nonzeroRowCount());
        service.write("config_error", "secret", "detail");
        clock.seconds += 3600;
        service.flush();
        assertEquals(1, nonzeroRowCount());
        service.initialize(clock, false);
        service.write("enrolled", "secret", "detail");
        clock.seconds += 3600;
        service.flush();
        assertEquals(0, nonzeroRowCount());
    }

    @Test
    void restartDropsOpenHourAndRejectsUnknownCategoryWithoutEchoingIt() throws Exception {
        service.write("sidecar_healthy", "tor", "detail");
        service.initialize(clock, true);
        clock.seconds += 3600;
        service.flush();
        assertEquals(0, nonzeroRowCount(), "open-hour counters are volatile across restart");
        var error = assertThrows(IllegalArgumentException.class,
                () -> service.write("T152-private-category", "label", "detail"));
        assertNotNull(error.getMessage());
        assertFalse(error.getMessage().contains("T152-private"));
    }

    @Test
    void sqliteRejectsForbiddenCategoriesMisalignedHoursNegativeCountsAndUpdates() throws Exception {
        service.write("enrolled", "secret", "detail");
        clock.seconds += 3600;
        service.flush();
        try (Connection c = dataSource.getConnection(); var st = c.createStatement()) {
            for (String sql : new String[] {
                "INSERT INTO operational_aggregates VALUES(0,'private-label',1)",
                "INSERT INTO operational_aggregates VALUES(1,'enrolled',1)",
                "INSERT INTO operational_aggregates VALUES(0,'enrolled',-1)",
                "UPDATE operational_aggregates SET count=count+1"}) {
                assertThrows(java.sql.SQLException.class, () -> st.executeUpdate(sql));
            }
            st.executeUpdate("INSERT OR REPLACE INTO operational_aggregates VALUES(" + HOUR + ",'enrolled',99)");
        }
        assertEquals(1, count(HOUR, "enrolled"));
    }

    @Test
    void expiredHistoryDoesNotLoseTheRestartClockBoundary() throws Exception {
        service.write("enrolled", "private", "detail");
        clock.seconds = HOUR + 3600;
        service.flush();
        clock.seconds += 8 * 86400;
        service.flush();
        assertEquals(0, nonzeroRowCount());
        clock.seconds = HOUR + 10;
        service.initialize(clock, true);
        service.write("enrolled", "old-clock", "detail");
        clock.seconds += 3600;
        service.flush();
        assertEquals(0, nonzeroRowCount(), "expired buckets cannot reappear after restart/clock rollback");
    }

    @Test
    void rollbackOnlyTransactionCannotEscapeThroughTheStandalonePath() throws Exception {
        utx.begin();
        utx.setRollbackOnly();
        service.write("enrolled", "rolled-back", "detail");
        utx.rollback();
        clock.seconds += 3600;
        service.flush();
        assertEquals(0, nonzeroRowCount());
    }

    private long nonzeroRowCount() throws Exception {
        try (Connection c = dataSource.getConnection(); var st = c.createStatement();
                var rs = st.executeQuery("SELECT COUNT(*) FROM operational_aggregates WHERE count > 0")) {
            assertTrue(rs.next()); return rs.getLong(1);
        }
    }
    private long count(long hour, String category) throws Exception {
        try (Connection c = dataSource.getConnection(); var ps = c.prepareStatement(
                "SELECT count FROM operational_aggregates WHERE hour_bucket=? AND category=?")) {
            ps.setLong(1, hour); ps.setString(2, category);
            try (var rs = ps.executeQuery()) { assertTrue(rs.next()); return rs.getLong(1); }
        }
    }
    private Set<String> columns() throws Exception {
        Set<String> result = new HashSet<>();
        try (Connection c = dataSource.getConnection(); var st = c.createStatement();
                var rs = st.executeQuery("PRAGMA table_info(operational_aggregates)")) {
            while (rs.next()) result.add(rs.getString("name"));
        }
        return result;
    }
    static final class MutableClock extends Clock {
        long seconds;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return Instant.ofEpochSecond(seconds); }
    }
}
