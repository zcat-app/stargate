// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import app.zcat.stargate.auth.HmacVerifierMinter;
import app.zcat.stargate.auth.TokenLoader;
import app.zcat.stargate.auth.TokenLoaderContract;
import io.agroal.api.AgroalDataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.UserTransaction;
import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
