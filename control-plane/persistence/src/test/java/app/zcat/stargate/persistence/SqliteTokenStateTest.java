// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Collectors;

import app.zcat.stargate.auth.HmacVerifierMinter;
import app.zcat.stargate.auth.TokenLoader;
import app.zcat.stargate.auth.TokenLoaderContract;
import io.agroal.api.AgroalDataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.UserTransaction;
import org.flywaydb.core.Flyway;
import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sqlite.BusyHandler;
import org.sqlite.SQLiteConnection;

/**
 * Behavioural contract for {@link SqliteTokenState} (T041; Principle VII
 * tests-first — the token push path is authentication surface) against the
 * REAL stack — Agroal-pooled SQLite, Hibernate ORM, Flyway-migrated
 * {@code V001__init.sql} — the same wiring the runtime boot relies on (the
 * T036 test shape, promoted). Ports: data-model.md §1.8
 * ({@code token_generation} singleton) and §1.9 ({@code configured_tokens});
 * the transactional interplay with the §4 audit sink is the property the
 * loader's write order (§1.7: reserve generation → store candidate → push,
 * diff rows inside the store transaction) depends on.
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

    private @Nullable Row readTokenRow(String label) {
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT label, verifier "
                        + "FROM configured_tokens WHERE label = '" + label + "'")) {
            if (!rs.next()) {
                return null;
            }
            return new Row(rs.getString(1), rs.getBytes(2));
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

    @Test
    void flywayCreatesOneClearDurableDeliveryState() throws SQLException {
        try (Connection c = dataSource.getConnection()) {
            boolean present;
            try (ResultSet tables = c.getMetaData().getTables(null, null, "auth_delivery", new String[] { "TABLE" })) {
                present = tables.next();
            }
            assertTrue(present, "V003 creates the durable auth-delivery singleton");
            try (Statement s = c.createStatement();
                    ResultSet rows = s.executeQuery("SELECT id, state, generation FROM auth_delivery")) {
                assertTrue(rows.next(), "the migration initializes the current state");
                assertEquals(1, rows.getInt("id"));
                assertEquals("CLEAR", rows.getString("state"));
                assertEquals(0L, rows.getLong("generation"));
                assertFalse(rows.next(), "the table stores one current state, not history");
            }
        }
    }

    @Test
    void deliveryMarkerTransitionsAreExactDurableAndStaleIsAbsorbing() throws SQLException {
        resetDeliveryMarker();
        var clear = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0);
        var unresolved = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 9);
        var stale = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.STALE, 9);
        assertEquals(clear, state.deliveryMarker(), "V003 starts at the single clear marker");
        assertTrue(state.prearmDelivery(9), "a complete candidate can be durably armed");
        assertEquals(unresolved, new SqliteTokenState(em, utx).deliveryMarker(),
                "prearm survives a fresh adapter/connection");
        assertFalse(state.acknowledgeDelivery(8), "an older or mismatched ACK cannot clear the marker");
        assertTrue(state.recordStaleDelivery(9), "the matching stale refusal is persisted");
        SqliteTokenState restarted = new SqliteTokenState(em, utx);
        assertEquals(stale, restarted.deliveryMarker(), "the stale state survives a fresh adapter");
        assertFalse(restarted.prearmDelivery(10), "STALE blocks a different generation");
        assertFalse(restarted.acknowledgeDelivery(9), "a delayed ACK cannot clear STALE");
        assertTrue(restarted.recordStaleDelivery(9), "recording the same stale state is idempotent");
        assertEquals(stale, state.deliveryMarker());
    }

    @Test
    void onlyExactAcknowledgementClearsUnresolvedAndKeepsSqliteDurable() throws SQLException {
        resetDeliveryMarker();
        assertTrue(state.prearmDelivery(12));
        assertFalse(state.acknowledgeDelivery(11));
        assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 12),
                new SqliteTokenState(em, utx).deliveryMarker());
        assertTrue(state.acknowledgeDelivery(12));
        assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0),
                new SqliteTokenState(em, utx).deliveryMarker());
        assertEquals(1, countDeliveryRows(), "the table remains one current marker, not history");
    }

    @Test
    void sqliteTransitionFailuresPreserveThePriorDurableMarker() throws SQLException {
        resetDeliveryMarker();
        executeSql("CREATE TRIGGER t201_fail_prearm BEFORE UPDATE ON auth_delivery "
                + "WHEN OLD.state = 'CLEAR' AND NEW.state = 'UNRESOLVED' "
                + "BEGIN SELECT RAISE(ABORT, 'injected prearm write failure'); END");
        try {
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> state.prearmDelivery(29), "failed prearm is an ordinary storage failure");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0),
                    new SqliteTokenState(em, utx).deliveryMarker(),
                    "a failed prearm does not leave a partial unresolved marker");
        } finally {
            executeSql("DROP TRIGGER t201_fail_prearm");
        }

        assertTrue(state.prearmDelivery(29));
        executeSql("CREATE TRIGGER t201_fail_terminal BEFORE UPDATE ON auth_delivery "
                + "WHEN OLD.state = 'UNRESOLVED' AND NEW.state IN ('CLEAR', 'STALE') "
                + "BEGIN SELECT RAISE(ABORT, 'injected terminal write failure'); END");
        try {
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> state.acknowledgeDelivery(29), "failed ACK clear propagates as storage failure");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 29),
                    new SqliteTokenState(em, utx).deliveryMarker(),
                    "a failed ACK clear retains the committed restart barrier");
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> state.recordStaleDelivery(29), "failed stale persistence propagates as storage failure");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 29),
                    new SqliteTokenState(em, utx).deliveryMarker(),
                    "failed stale persistence retains the earlier unresolved marker across a fresh adapter");
        } finally {
            executeSql("DROP TRIGGER t201_fail_terminal");
        }
        SqliteTokenState restarted = new SqliteTokenState(em, utx);
        assertFalse(restarted.prearmDelivery(30),
                "a changed candidate cannot replace the retained marker after a simulated process restart");
        assertFalse(restarted.acknowledgeDelivery(30),
                "a mismatched ACK cannot erase the unresolved marker after a simulated process restart");
        assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 29),
                restarted.deliveryMarker());
    }

    private void executeSql(String sql) throws SQLException {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    @Test
    void literalQuickstartRecoveryClearsOnlyMarkerOnRealFlywayV003Database(@TempDir Path dir)
            throws Exception {
        String snippet = quickstartRecoverySnippet();
        Path db = dir.resolve("control.db");
        createFlywayRecoveryFixture(db);
        assertEquals("003", successfulV003Version(db),
                "the positive fixture's schema identity comes from the production V003 migration");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = c.createStatement()) {
            s.executeUpdate("INSERT INTO token_generation(generation) VALUES (41)");
            s.executeUpdate("INSERT INTO configured_tokens(label,verifier) "
                    + "VALUES ('fixture-label', X'010203')");
            s.executeUpdate("UPDATE auth_delivery SET state='UNRESOLVED',generation=41 WHERE id=1");
        }
        var originalOwner = Files.getOwner(db);
        var originalMode = Files.getPosixFilePermissions(db);

        CapturedProcess unconfirmed = runRecoverySnippet(snippet, db, "NO");
        assertTrue(unconfirmed.exitCode() != 0, "the literal confirmation is required");
        assertEquals("UNRESOLVED", readMarkerState(db));

        Path missing = dir.resolve("missing/control.db");
        Files.createDirectories(missing.getParent());
        CapturedProcess absent = runRecoverySnippet(snippet, missing, "CLEAR-UNRESOLVED-TOKEN-DELIVERY");
        assertTrue(absent.exitCode() != 0, "mode=rw refuses a missing database");
        assertFalse(Files.exists(missing), "recovery does not create a database");

        CapturedProcess clear = runRecoverySnippet(snippet, db, "CLEAR-UNRESOLVED-TOKEN-DELIVERY");
        assertEquals(0, clear.exitCode(), clear.output());
        assertEquals("CLEAR", readMarkerState(db));
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = c.createStatement()) {
            try (ResultSet rows = s.executeQuery("SELECT generation FROM token_generation")) {
                assertTrue(rows.next());
                assertEquals(41L, rows.getLong(1));
                assertFalse(rows.next());
            }
            try (ResultSet rows = s.executeQuery(
                    "SELECT label,verifier FROM configured_tokens")) {
                assertTrue(rows.next());
                assertEquals("fixture-label", rows.getString(1));
                assertArrayEquals(new byte[] { 1, 2, 3 }, rows.getBytes(2));
                assertFalse(rows.next());
            }
        }
        assertEquals(originalOwner, Files.getOwner(db));
        assertEquals(originalMode, Files.getPosixFilePermissions(db));
    }

    @Test
    void literalQuickstartSchemaProbeUsesControlDbPathAndSeparatesSchemaGuard(@TempDir Path dir)
            throws Exception {
        String snippet = quickstartRecoverySnippet();
        Path db = dir.resolve("malformed/control.db");
        createMalformedRecoveryFixture(db);
        assertEquals("003", successfulV003Version(db), "the schema probe passes the independent version prerequisite");

        CapturedProcess refused = runRecoverySnippet(snippet, db, "CLEAR-UNRESOLVED-TOKEN-DELIVERY");
        assertTrue(refused.output().contains("refused: expected T201 V003 singleton schema"), refused.output());
        assertTrue(refused.exitCode() != 0);
        assertEquals("UNRESOLVED", readMarkerState(db));

        String fullGuard = "if not version or not ddl or any(item not in normalized_ddl for item in required) "
                + "or not {\"id\", \"state\", \"generation\"}.issubset(columns) or len(rows) != 1:";
        String versionOnlyGuard = "if not version:";
        assertEquals(1, occurrences(snippet, fullGuard), "the private mutant changes only the combined schema guard");
        CapturedProcess mutant = runRecoverySnippet(snippet.replace(fullGuard, versionOnlyGuard), db,
                "CLEAR-UNRESOLVED-TOKEN-DELIVERY");
        if (snippet.contains("version='3'")) {
            assertTrue(mutant.exitCode() != 0, "the pre-fix version predicate still blocks this control");
            assertEquals("UNRESOLVED", readMarkerState(db));
        } else {
            assertEquals(0, mutant.exitCode(), mutant.output());
            assertEquals("CLEAR", readMarkerState(db),
                    "after the query-only fix, removing only schema checks lets this malformed control clear");
        }
    }

    @Test
    void literalQuickstartRejectsHeldWriterLockOnRealFlywayControlDb(@TempDir Path dir)
            throws Exception {
        String snippet = quickstartRecoverySnippet();
        Path db = dir.resolve("locked/control.db");
        Files.createDirectories(db.getParent());
        createFlywayRecoveryFixture(db);
        assertEquals("003", successfulV003Version(db), "the lock probe uses the production V003 migration");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = c.createStatement()) {
            s.executeUpdate("UPDATE auth_delivery SET state='UNRESOLVED',generation=41 WHERE id=1");
        }
        try (Connection lock = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = lock.createStatement()) {
            lock.setAutoCommit(false);
            s.executeUpdate("UPDATE auth_delivery SET state='UNRESOLVED',generation=41 WHERE id=1");
            CapturedProcess refusedLock = runRecoverySnippet(snippet, db,
                    "CLEAR-UNRESOLVED-TOKEN-DELIVERY");
            assertTrue(refusedLock.exitCode() != 0 && refusedLock.exitCode() != 124 && refusedLock.exitCode() != 137,
                    "SQLite must refuse before the outer timeout: " + refusedLock);
            assertTrue(refusedLock.output().toLowerCase(java.util.Locale.ROOT).contains("locked"),
                    "the literal must reach the SQLite lock failure, not an earlier schema guard: " + refusedLock);
            assertTrue(refusedLock.elapsed().compareTo(java.time.Duration.ofSeconds(10)) < 0,
                    "the existing outer ten-second bound remains effective");
            assertEquals("UNRESOLVED", readMarkerState(db));
            lock.rollback();
        }
    }

    private static String quickstartRecoverySnippet() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isRegularFile(root.resolve("scripts/stargate"))) {
            root = root.getParent();
        }
        assertNotNull(root, "repository root");
        String doc = Files.readString(root.resolve("specs/001-tor-route/quickstart.md"));
        String marker = "timeout 10s python3 - \"$DB_PATH\" CLEAR-UNRESOLVED-TOKEN-DELIVERY <<'PY'\n";
        int start = doc.indexOf(marker);
        assertTrue(start >= 0, "quickstart contains the literal bounded recovery snippet");
        start += marker.length();
        int end = doc.indexOf("\n   PY\n", start);
        assertTrue(end > start, "quickstart recovery snippet has its terminator");
        return doc.substring(start, end).stripIndent();
    }

    private static CapturedProcess runRecoverySnippet(String snippet, Path db, String confirmation) throws Exception {
        long started = System.nanoTime();
        Process process = new ProcessBuilder("timeout", "10s", "python3", "-", db.toString(), confirmation)
                .redirectErrorStream(true).start();
        try (var input = process.getOutputStream()) {
            input.write(snippet.getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(process.waitFor(11, TimeUnit.SECONDS), "bounded offline recovery snippet terminates");
        if (process.isAlive()) {
            process.destroyForcibly();
            process.waitFor(1, TimeUnit.SECONDS);
            throw new AssertionError("recovery snippet exceeded the 10-second bound");
        }
        byte[] output = process.getInputStream().readNBytes(16 * 1024);
        return new CapturedProcess(process.exitValue(), new String(output, StandardCharsets.UTF_8),
                java.time.Duration.ofNanos(System.nanoTime() - started));
    }

    private record CapturedProcess(int exitCode, String output, java.time.Duration elapsed) {
    }

    private static int occurrences(String text, String needle) {
        int count = 0;
        for (int from = 0; (from = text.indexOf(needle, from)) >= 0; from += needle.length()) {
            count++;
        }
        return count;
    }

    private static String readMarkerState(Path db) throws SQLException {
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = c.createStatement();
                ResultSet rows = s.executeQuery("SELECT state FROM auth_delivery WHERE id=1")) {
            assertTrue(rows.next());
            return rows.getString(1);
        }
    }

    private static void createFlywayRecoveryFixture(Path db) {
        String url = "jdbc:sqlite:" + db.toAbsolutePath();
        Flyway.configure().dataSource(url, "", "").load().migrate();
    }

    private static @Nullable String successfulV003Version(Path db) throws SQLException {
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = c.createStatement();
                ResultSet rows = s.executeQuery(
                        "SELECT version FROM flyway_schema_history WHERE version='003' AND success=1")) {
            return rows.next() ? rows.getString(1) : null;
        }
    }

    private static void createMalformedRecoveryFixture(Path db) throws Exception {
        java.nio.file.Files.createDirectories(db.getParent());
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
                Statement s = c.createStatement()) {
            s.execute("CREATE TABLE flyway_schema_history(version TEXT, success INTEGER)");
            s.execute("INSERT INTO flyway_schema_history VALUES ('003',1)");
            s.execute("CREATE TABLE auth_delivery(id INTEGER,state TEXT,generation INTEGER)");
            s.execute("INSERT INTO auth_delivery VALUES (1,'UNRESOLVED',41)");
        }
    }

    private void resetDeliveryMarker() throws SQLException {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.executeUpdate("UPDATE auth_delivery SET state = 'CLEAR', generation = 0 WHERE id = 1");
        }
    }

    private int countDeliveryRows() throws SQLException {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement();
                ResultSet rows = s.executeQuery("SELECT COUNT(*) FROM auth_delivery")) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private record Row(String label, byte[] verifier) {
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
    void upsertStoresOnlyCurrentCredentialAndRefreshesVerifier() {
        String label = "created-at-probe-" + System.nanoTime();
        // upsert/delete are the loader's in-window writes (§1.7): each probe
        // drives them through the same begin/commit shape the loader uses.
        state.begin();
        state.upsert(label, VERIFIER_A);
        state.commit();
        Row first = readTokenRow(label);
        assertNotNull(first, "the row persists");
        assertTrue(java.util.Arrays.equals(VERIFIER_A, first.verifier()), "verifier persisted");

        state.begin();
        state.upsert(label, VERIFIER_B);
        state.commit();
        Row second = readTokenRow(label);
        assertNotNull(second, "the re-upserted row persists");
        assertTrue(java.util.Arrays.equals(VERIFIER_B, second.verifier()),
                "the fresh verifier overwrites (§1.7 full-set rewrite — the pepper-rotation property)");

        List<String> labels = state.storedTokens().stream()
                .map(TokenLoaderContract.StoredToken::label)
                .collect(Collectors.toList());
        assertTrue(labels.contains(label), "the label feeds the diff (storedLabels)");
    }

    @Test
    void deleteRemovesCredentialWithoutRetainingRevocationHistory() {
        String label = "revoke-probe-" + System.nanoTime();
        state.begin();
        state.upsert(label, VERIFIER_A);
        state.delete(label);
        state.commit();

        Row row = readTokenRow(label);
        assertNull(row, "revocation must not retain per-device operational history");
        assertTrue(state.storedTokens().stream().noneMatch(t -> t.label().equals(label)),
                "a deleted label leaves the diff view (§1.4/§1.9)");
    }

    @Test
    void aggregateWriterCannotAbortInitialCredentialCommit() throws Exception {
        // §1.7–1.9 requires the candidate to commit before ReloadTokens. A concurrent
        // §4 aggregate writer must not turn the first credential into SQLITE_BUSY.
        // Hold the token writer for 3.5s after the competing BEGIN reaches SQLite;
        // the fixture's 12s busy budget allows that delay plus a stalled runner.
        String label = "concurrent-enrollment-" + System.nanoTime();
        CountDownLatch writerInterleaved = new CountDownLatch(1);
        CountDownLatch writerContending = new CountDownLatch(1);
        CountDownLatch writerAcquired = new CountDownLatch(1);
        CountDownLatch releaseWriter = new CountDownLatch(1);
        try (var executor = Executors.newSingleThreadExecutor()) {
            state.begin();
            // A miss forces the same deferred read-to-write window as initial upsert.
            state.delete(label);
            var aggregateWriter = executor.submit(() -> {
                try (Connection connection = dataSource.getConnection();
                        Statement statement = connection.createStatement()) {
                    // The first busy callback proves BEGIN actually reached the
                    // reserved writer lock. On an unfixed store, BEGIN succeeds
                    // instead and the acquired latch establishes that ordering.
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
                    SQLiteConnection sqlite = connection.unwrap(SQLiteConnection.class);
                    int inheritedBusyTimeout = sqlite.getBusyTimeout();
                    BusyHandler.setHandler(sqlite, new BusyHandler() {
                        @Override
                        protected int callback(int count) {
                            writerContending.countDown();
                            writerInterleaved.countDown();
                            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(10));
                            return System.nanoTime() < deadline ? 1 : 0;
                        }
                    });
                    try {
                        statement.execute("BEGIN IMMEDIATE");
                        writerAcquired.countDown();
                        writerInterleaved.countDown();
                        statement.executeUpdate("INSERT OR IGNORE INTO operational_aggregates "
                                + "(hour_bucket, category, count) VALUES (1800000000, 'enrolled', 0)");
                        if (!releaseWriter.await(12, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("fixture did not release the aggregate writer");
                        }
                        statement.execute("COMMIT");
                    } finally {
                        // Agroal may reuse the physical connection in another test.
                        sqlite.setBusyTimeout(inheritedBusyTimeout);
                        try (ResultSet timeout = statement.executeQuery("PRAGMA busy_timeout")) {
                            assertTrue(timeout.next());
                            assertEquals(inheritedBusyTimeout, timeout.getInt(1),
                                    "the pooled connection must retain its inherited busy wait");
                        }
                    }
                }
                return null;
            });
            try {
                assertTrue(writerInterleaved.await(5, TimeUnit.SECONDS),
                        "fixture never reached BEGIN IMMEDIATE; cannot test contention");
                boolean writerAcquiredBeforeCommit = writerAcquired.getCount() == 0;
                Thread.sleep(3500); // Exceeds the inherited 3s SQLite wait budget.
                state.upsert(label, VERIFIER_A);
                state.commit();
                assertFalse(writerAcquiredBeforeCommit,
                        "aggregate writer acquired before token commit");
                assertEquals(0, writerContending.getCount(),
                        "aggregate writer never encountered the token reservation");
            } finally {
                releaseWriter.countDown();
                state.rollback();
            }
            aggregateWriter.get(10, TimeUnit.SECONDS);
        }
        assertNotNull(readTokenRow(label), "the first configured credential must commit");
    }

    @Test
    void rollbackDiscardsCredentialChangesAndOperationalCounts() throws Exception {
        audit.close();
        var clock = new AuditLogServiceTest.MutableClock();
        clock.seconds = 1_900_000_800L;
        audit.initialize(clock, true);
        String label = "rollback-credential";
        state.begin();
        audit.write("enrolled", label, "legacy detail discarded");
        state.upsert(label, VERIFIER_A);
        state.rollback();
        assertNull(readTokenRow(label));
        assertTrue(state.storedTokens().stream().noneMatch(t -> t.label().equals(label)));
        clock.seconds += 3600;
        audit.flush();
        try (Connection c = dataSource.getConnection(); var st = c.createStatement();
                var rs = st.executeQuery("SELECT COALESCE(SUM(count),0) FROM operational_aggregates WHERE hour_bucket=1900000800")) {
            assertTrue(rs.next());
            assertEquals(0, rs.getLong(1), "rollback contributes no finalized count");
        }
    }

    @Test
    void productionProcessesRecoverOriginalSqliteAfterBothCrashBoundaries(@TempDir Path dir)
            throws Exception {
        assertCrashRecovery(dir, "reserve-revoke", "recover-revoke",
                "last=3\npushed=3\nlabels=\n");
        assertCrashRecovery(dir, "commit-revoke", "recover-revoke",
                "last=2\npushed=2\nlabels=\n");
        assertCrashRecovery(dir, "reserve-enroll", "recover-enroll",
                "last=2\npushed=2\nlabels=first\n");
        assertCrashRecovery(dir, "commit-enroll", "recover-enroll",
                "last=1\npushed=1\nlabels=first\n");
    }

    private static void assertCrashRecovery(Path root, String crashMode, String recoverMode,
            String expected) throws Exception {
        Path scenario = Files.createDirectories(root.resolve(crashMode));
        Process crashed = startCrashChild(scenario, crashMode);
        awaitMarkerThenKill(crashed, scenario, crashMode);
        runRecoveryChild(scenario, recoverMode);
        assertEquals(expected, Files.readString(scenario.resolve("result")),
                crashMode + " must reopen the original SQLite database in a fresh process");
    }

    private static Process startCrashChild(Path scenario, String mode) throws Exception {
        Path module = Path.of(System.getProperty("basedir")).toAbsolutePath().normalize();
        Path controlPlane = module.getFileName().toString().equals("persistence")
                ? java.util.Objects.requireNonNull(module.getParent()) : module;
        Path log = scenario.resolve(mode + ".log");
        Files.deleteIfExists(scenario.resolve("marker"));
        ProcessBuilder builder = new ProcessBuilder(
                controlPlane.resolve("mvnw").toString(), "-B", "-pl", "persistence", "-am", "test",
                "-Dtest=T159SqliteCrashChild", "-Dsurefire.failIfNoSpecifiedTests=false",
                "-Dquarkus.datasource.jdbc.url=jdbc:sqlite:"
                        + scenario.resolve("control.db").toAbsolutePath(),
                "-Dquarkus.flyway.clean-at-start=false",
                "-Dt159.crash.mode=" + mode,
                "-Dt159.crash.dir=" + scenario.toAbsolutePath())
                .directory(controlPlane.toFile())
                .redirectErrorStream(true)
                .redirectOutput(log.toFile());
        return builder.start();
    }

    private static void awaitMarkerThenKill(Process process, Path scenario, String mode)
            throws Exception {
        Path marker = scenario.resolve("marker");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        long sqliteOwnerPid = -1L;
        while (sqliteOwnerPid < 0 && process.isAlive() && System.nanoTime() < deadline) {
            if (Files.exists(marker)) {
                try {
                    sqliteOwnerPid = Long.parseLong(Files.readString(marker).strip());
                } catch (NumberFormatException incompleteMarker) {
                    // The writer may have created the marker but not finished
                    // its short PID payload. Wait for the completed boundary.
                }
            }
            Thread.sleep(20);
        }
        assertTrue(sqliteOwnerPid > 0,
                mode + " child did not reach its crash boundary:\n"
                        + Files.readString(scenario.resolve(mode + ".log")));

        List<ProcessHandle> descendants = process.toHandle().descendants().toList();
        long ownerPid = sqliteOwnerPid;
        assertTrue(descendants.stream().anyMatch(child -> child.pid() == ownerPid),
                "the marker writer must be the SQLite-owning child JVM, not the Maven launcher");
        ProcessHandle sqliteOwner = ProcessHandle.of(ownerPid).orElseThrow();
        sqliteOwner.destroyForcibly();
        sqliteOwner.onExit().get(10, TimeUnit.SECONDS);
        descendants.reversed().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        process.waitFor(10, TimeUnit.SECONDS);
        long killDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (descendants.stream().anyMatch(ProcessHandle::isAlive)
                && System.nanoTime() < killDeadline) {
            descendants.stream().filter(ProcessHandle::isAlive)
                    .forEach(ProcessHandle::destroyForcibly);
            Thread.sleep(20);
        }
        assertFalse(sqliteOwner.isAlive(),
                "the exact SQLite-owning child JVM must be abruptly terminated");
        assertFalse(process.isAlive(), "the child build launcher must also be reaped");
        assertTrue(descendants.stream().noneMatch(ProcessHandle::isAlive),
                "the SQLite-owning child process must be abruptly terminated before reopen");
    }

    private static void runRecoveryChild(Path scenario, String mode) throws Exception {
        Process process = startCrashChild(scenario, mode);
        boolean exited = process.waitFor(90, TimeUnit.SECONDS);
        if (!exited) {
            process.toHandle().descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
        }
        assertTrue(exited, mode + " child timed out");
        assertEquals(0, process.exitValue(),
                mode + " child failed:\n" + Files.readString(scenario.resolve(mode + ".log")));
    }
}

/**
 * Child-only Quarkus fixture for the T159 physical SQLite crash probes. Its
 * name intentionally does not end in {@code Test}, so normal discovery never
 * runs it; the parent selects it explicitly in a separate JVM.
 */
@QuarkusTest
class T159SqliteCrashChild {

    private static final String EXAMPLE = "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b";

    @Inject
    SqliteTokenState state;

    @Test
    void runSelectedCrashBoundary() throws Exception {
        String mode = System.getProperty("t159.crash.mode");
        Path dir = Path.of(System.getProperty("t159.crash.dir"));
        Path yaml = dir.resolve("tokens.yaml");
        HmacVerifierMinter minter = new HmacVerifierMinter(new byte[32]);

        switch (mode) {
            case "reserve-revoke" -> {
                seedRevocation(minter);
                Files.writeString(yaml, "tokens: []\n", StandardCharsets.UTF_8);
                load(yaml, state, barrierAfterReservation(state, dir.resolve("marker")),
                        acknowledged(), minter);
            }
            case "commit-revoke" -> {
                seedRevocation(minter);
                Files.writeString(yaml, "tokens: []\n", StandardCharsets.UTF_8);
                load(yaml, state, state, barrierAfterCommit(dir.resolve("marker")), minter);
            }
            case "recover-revoke" -> {
                Files.writeString(yaml, "tokens: []\n", StandardCharsets.UTF_8);
                recover(yaml, dir, minter);
            }
            case "reserve-enroll" -> {
                assertEquals(0L, state.lastGeneration(),
                        "first enrollment starts from an isolated generation-zero database");
                writeEnrollment(yaml);
                load(yaml, state, barrierAfterReservation(state, dir.resolve("marker")),
                        acknowledged(), minter);
            }
            case "commit-enroll" -> {
                assertEquals(0L, state.lastGeneration(),
                        "first enrollment starts from an isolated generation-zero database");
                writeEnrollment(yaml);
                load(yaml, state, state, barrierAfterCommit(dir.resolve("marker")), minter);
            }
            case "recover-enroll" -> {
                writeEnrollment(yaml);
                recover(yaml, dir, minter);
            }
            default -> throw new IllegalStateException("unknown T159 crash mode");
        }
    }

    private void seedRevocation(HmacVerifierMinter minter) {
        assertEquals(0L, state.lastGeneration());
        state.record(1L);
        state.begin();
        state.upsert("old", minter.mint(EXAMPLE.getBytes(StandardCharsets.UTF_8)));
        state.commit();
    }

    private void recover(Path yaml, Path dir, HmacVerifierMinter minter) throws Exception {
        AtomicLong pushed = new AtomicLong(-1L);
        load(yaml, state, state, (generation, verifiers) -> {
            pushed.set(generation);
            return new TokenLoaderContract.PushResult(false, generation);
        }, minter);
        String labels = state.storedTokens().stream()
                .map(TokenLoaderContract.StoredToken::label).sorted()
                .collect(Collectors.joining(","));
        Files.writeString(dir.resolve("result"),
                "last=" + state.lastGeneration() + "\npushed=" + pushed.get()
                        + "\nlabels=" + labels + "\n",
                StandardCharsets.UTF_8);
    }

    private static void load(Path yaml, TokenLoaderContract.ConfiguredTokenStore store,
            TokenLoaderContract.GenerationStore generations, TokenLoaderContract.ReloadChannel reload,
            HmacVerifierMinter minter) {
        new TokenLoader(yaml, new byte[32], store, generations,
                (action, target, detail) -> { }, reload, minter).load();
    }

    private static TokenLoaderContract.GenerationStore barrierAfterReservation(
            SqliteTokenState delegate, Path marker) {
        return new TokenLoaderContract.GenerationStore() {
            @Override
            public long lastGeneration() {
                return delegate.lastGeneration();
            }

            @Override
            public void record(long generation) {
                delegate.record(generation);
                blockAt(marker);
            }

            @Override
            public TokenLoaderContract.GenerationStore.DeliveryMarker deliveryMarker() {
                return delegate.deliveryMarker();
            }

            @Override
            public boolean prearmDelivery(long generation) {
                return delegate.prearmDelivery(generation);
            }

            @Override
            public boolean acknowledgeDelivery(long generation) {
                return delegate.acknowledgeDelivery(generation);
            }

            @Override
            public boolean recordStaleDelivery(long generation) {
                return delegate.recordStaleDelivery(generation);
            }
        };
    }

    private static TokenLoaderContract.ReloadChannel barrierAfterCommit(Path marker) {
        return (generation, verifiers) -> {
            blockAt(marker);
            return new TokenLoaderContract.PushResult(false, generation);
        };
    }

    private static TokenLoaderContract.ReloadChannel acknowledged() {
        return (generation, verifiers) -> new TokenLoaderContract.PushResult(false, generation);
    }

    private static void blockAt(Path marker) {
        try {
            Files.writeString(marker, Long.toString(ProcessHandle.current().pid()),
                    StandardCharsets.US_ASCII);
            while (true) {
                Thread.sleep(60_000);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("crash fixture interrupted", interrupted);
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("cannot publish crash boundary", failure);
        }
    }

    private static void writeEnrollment(Path yaml) throws java.io.IOException {
        Files.writeString(yaml,
                "tokens:\n  - label: first\n    token: " + EXAMPLE + "\n",
                StandardCharsets.UTF_8);
    }
}
