// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.sidecar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Contract suite for the Tor ControlPort monitor (T039) — pins the ticket's
 * must-holds against a scripted fake ControlPort server: COOKIE auth with the
 * exact hex of the mounted cookie, the read-only command allowlist, the
 * fixed-vocabulary (kind, detail) pairings (control-grpc.md §"WatchEvents"),
 * the edge-triggered §4 {@code sidecar_healthy} audit row, and survivability
 * of every failed-cycle shape (Principle II — the monitor is advisory
 * surface and must never take the control plane down).
 */
class SidecarMonitorTest {

    private static final byte[] COOKIE = new byte[32];
    private static final LongSupplier GENERATION_7 = () -> 7L;

    static {
        for (int i = 0; i < COOKIE.length; i++) {
            COOKIE[i] = (byte) (0xA0 + i);
        }
    }

    @TempDir
    Path tempDir;

    private final List<FakeControlPort> fakes = new ArrayList<>();
    private final List<SidecarMonitor> monitors = new ArrayList<>();

    @AfterEach
    void tearDown() {
        monitors.forEach(SidecarMonitor::close);
        fakes.forEach(FakeControlPort::close);
    }

    // ─── fakes ───────────────────────────────────────────────────────────

    /**
     * Scripted ControlPort server. Accepts connections sequentially; per
     * line: AUTHENTICATE (hex-compared against the seeded cookie),
     * GETINFO status/bootstrap-phase (canned multi-line reply), QUIT.
     * Everything received is recorded for the allowlist assertions.
     */
    private static final class FakeControlPort implements AutoCloseable {

        final ServerSocket serverSocket;
        final List<String> received = new ArrayList<>();
        final AtomicInteger connections = new AtomicInteger();
        final AtomicReference<String> bootstrapReply = new AtomicReference<>(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
                + "250 OK\r\n");
        volatile boolean rejectAuth;
        volatile boolean malformedAuthReply;
        private final Thread accepter;
        private volatile boolean closed;

        FakeControlPort(byte[] cookie) throws IOException {
            this.serverSocket = new ServerSocket(0, 16, java.net.InetAddress.getLoopbackAddress());
            final String expectedHex = SidecarMonitorTest.hex(cookie);
            this.accepter = new Thread(() -> {
                while (!closed) {
                    try (Socket conn = serverSocket.accept()) {
                        connections.incrementAndGet();
                        handle(conn, expectedHex);
                    } catch (IOException e) {
                        if (!closed) {
                            // accept loop keeps serving the next cycle
                        }
                    }
                }
            }, "fake-control-port");
            accepter.setDaemon(true);
            accepter.start();
        }

        private void handle(Socket conn, String expectedHex) throws IOException {
            conn.setSoTimeout(5000);
            final BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.ISO_8859_1));
            final Writer out = new OutputStreamWriter(conn.getOutputStream(), StandardCharsets.ISO_8859_1);
            String line;
            while ((line = in.readLine()) != null) {
                synchronized (received) {
                    received.add(line);
                }
                if (line.startsWith("AUTHENTICATE")) {
                    if (rejectAuth) {
                        out.write("513 Authentication failed.\r\n");
                    } else if (malformedAuthReply) {
                        out.write("HELLO NOT-A-CONTROL-REPLY\r\n");
                    } else if (line.equals("AUTHENTICATE " + expectedHex)) {
                        out.write("250 OK\r\n");
                    } else {
                        out.write("513 Authentication failed.\r\n");
                    }
                } else if (line.equals("GETINFO status/bootstrap-phase")) {
                    out.write(bootstrapReply.get());
                } else if (line.equals("QUIT")) {
                    out.write("250 closing connection\r\n");
                    out.flush();
                    return;
                } else {
                    out.write("510 Unrecognized command.\r\n");
                }
                out.flush();
            }
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        List<String> lines() {
            synchronized (received) {
                return List.copyOf(received);
            }
        }

        /** Waits until the fake has recorded the QUIT of the current cycle. */
        void awaitCycle() throws InterruptedException {
            awaitLines("QUIT");
        }

        /** Waits until the fake has recorded the given line (e.g. auth-only
         * cycles end without a QUIT). */
        void awaitLines(String lastLine) throws InterruptedException {
            final long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (System.nanoTime() < deadline) {
                List<String> snapshot = lines();
                if (!snapshot.isEmpty() && lastLine.equals(snapshot.get(snapshot.size() - 1))) {
                    return;
                }
                Thread.sleep(10);
            }
            throw new AssertionError("fake never saw '" + lastLine + "'; recorded: " + lines());
        }

        @Override
        public void close() {
            closed = true;
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // test fake shutdown
            }
            accepter.interrupt();
        }
    }

    private static final class Recorder implements SidecarMonitor.EventSink, SidecarMonitor.AuditSink {
        final List<SidecarMonitor.Event> events = new ArrayList<>();
        final List<String[]> rows = new ArrayList<>();

        @Override
        public void publish(SidecarMonitor.Event event) {
            events.add(event);
        }

        @Override
        public void write(String action, String target, String detailJson) {
            rows.add(new String[] { action, target, detailJson });
        }
    }

    private FakeControlPort startFake() throws IOException {
        FakeControlPort fake = new FakeControlPort(COOKIE);
        fakes.add(fake);
        return fake;
    }

    private SidecarMonitor monitor(FakeControlPort fake, Path cookiePath, Recorder recorder) {
        SidecarMonitor m = new SidecarMonitor("127.0.0.1", fake.port(), cookiePath,
                Duration.ofSeconds(10), GENERATION_7, recorder, recorder);
        monitors.add(m);
        return m;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private Path writeCookie() throws IOException {
        Path cookie = tempDir.resolve("control_auth_cookie");
        Files.write(cookie, COOKIE);
        return cookie;
    }

    // ─── a. event sequence + vocabulary ──────────────────────────────────

    @Test
    void emitsStartedThenHealthyWithFixedVocabulary() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();

        assertEquals(2, recorder.events.size(), "STARTED + HEALTHY on first healthy cycle");
        SidecarMonitor.Event started = recorder.events.get(0);
        SidecarMonitor.Event healthy = recorder.events.get(1);
        assertEquals(SidecarMonitor.Kind.STARTED, started.kind());
        assertEquals("container_start", started.detail());
        assertEquals("tor", started.sidecar());
        assertEquals(SidecarMonitor.Kind.HEALTHY, healthy.kind());
        assertEquals("healthcheck_pass", healthy.detail());
        assertEquals("tor", healthy.sidecar());
        assertTrue(started.ts() != null && !started.ts().isAfter(healthy.ts()),
                "events carry the emission instant, in order");
        assertEquals(1, recorder.rows.size(), "one §4 row on entering healthy");
        assertEquals("sidecar_healthy", recorder.rows.get(0)[0]);
        assertEquals("tor", recorder.rows.get(0)[1]);
        assertEquals("{\"generation\":7}", recorder.rows.get(0)[2]);

        // Still-healthy second cycle: level, not an entry — nothing new.
        fake.awaitCycle();
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.events.size(), "no repeated events while level");
        assertEquals(1, recorder.rows.size(), "no repeated audit row while level");
    }

    // ─── b. COOKIE auth only ─────────────────────────────────────────────

    @Test
    void authenticatesWithHexOfMountedCookie() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();
        fake.awaitCycle();

        List<String> lines = fake.lines();
        assertFalse(lines.isEmpty());
        assertEquals("AUTHENTICATE " + hex(COOKIE), lines.get(0),
                "first wire line must be COOKIE auth with the mounted cookie's exact hex");
        // The fake only answers 250 OK to that exact line; events flowing at
        // all proves the exchange succeeded with no other auth method.
        assertEquals(2, recorder.events.size());
    }

    @Test
    void authFailureIsASilentFailedCycle() throws Exception {
        FakeControlPort fake = startFake();
        fake.rejectAuth = true;
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();
        fake.awaitLines("AUTHENTICATE " + hex(COOKIE));

        assertEquals(0, recorder.events.size(), "no events from a rejected exchange");
        assertEquals(0, recorder.rows.size(), "no audit row from a rejected exchange");
    }

    // ─── c. read-only command allowlist ──────────────────────────────────

    @Test
    void wireTrafficStaysInsideTheReadOnlyAllowlist() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        // Several cycles, including a degraded one, to cover the whole shape.
        m.runOnce();
        fake.awaitCycle();
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=95 TAG=circuit_create\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        m.runOnce();
        fake.awaitCycle();

        for (String line : fake.lines()) {
            boolean allowed =
                    line.matches("AUTHENTICATE [0-9a-f]{64}")
                            || line.equals("GETINFO status/bootstrap-phase")
                            || line.equals("QUIT");
            assertTrue(allowed, "wire line outside the read-only allowlist: " + line);
        }
    }

    // ─── d. edge-triggered audit ─────────────────────────────────────────

    @Test
    void auditRowFiresOnEachEntryIntoHealthyOnly() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        // 1: entry (95 → not healthy, no row)
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=95 TAG=circuit_create\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(0, recorder.rows.size(), "not healthy yet: no row");
        assertEquals(1, recorder.events.size(), "STARTED only");

        // 2: entry into healthy → row
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(1, recorder.rows.size());
        assertEquals("{\"generation\":7}", recorder.rows.get(0)[2]);

        // 3: level → no row
        m.runOnce();
        fake.awaitCycle();
        assertEquals(1, recorder.rows.size());

        // 4/5: drop out and re-enter → second row
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=95 TAG=circuit_create\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.rows.size(), "each entry into healthy writes one row");
        for (String[] row : recorder.rows) {
            assertEquals("sidecar_healthy", row[0]);
            assertEquals("tor", row[1]);
        }
        // STARTED is edge-triggered per session too: it fired once at cycle 1
        // and never re-fired inside one continuous authenticated session.
        assertEquals(1, recorder.events.stream().filter(e -> e.kind() == SidecarMonitor.Kind.STARTED).count());
    }

    // ─── e. survivability ────────────────────────────────────────────────

    @Test
    void refusedConnectionIsASilentFailedCycle() throws Exception {
        Recorder recorder = new Recorder();
        Path cookie = writeCookie();
        // A bound-then-closed port: connect gets refused, nothing listens.
        ServerSocket dead;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            dead = s;
        }
        int deadPort = dead.getLocalPort();
        SidecarMonitor m = new SidecarMonitor("127.0.0.1", deadPort, cookie,
                Duration.ofSeconds(10), GENERATION_7, recorder, recorder);
        monitors.add(m);

        m.runOnce();

        assertEquals(0, recorder.events.size());
        assertEquals(0, recorder.rows.size());
    }

    @Test
    void missingCookieSkipsTheCycleWithoutDialing() throws Exception {
        FakeControlPort fake = startFake();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, tempDir.resolve("absent_control_auth_cookie"), recorder);

        m.runOnce();

        assertEquals(0, fake.connections.get(), "no dial without the cookie");
        assertEquals(0, recorder.events.size());
        assertEquals(0, recorder.rows.size());
    }

    @Test
    void malformedReplyIsASilentFailedCycle() throws Exception {
        FakeControlPort fake = startFake();
        fake.malformedAuthReply = true;
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();

        assertEquals(0, recorder.events.size(), "no events from a non-250 reply");
        assertEquals(0, recorder.rows.size());
        // The next cycle still works once the sidecar speaks protocol again.
        fake.malformedAuthReply = false;
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.events.size(), "monitor survives and resumes");
    }

    // ─── f. no free text ─────────────────────────────────────────────────

    @Test
    void detailNeverEchoesSidecarReplyText() throws Exception {
        FakeControlPort fake = startFake();
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP EXOTIC=secret-sauce PROGRESS=100 TAG=done\r\n250 OK\r\n");
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();
        fake.awaitCycle();

        for (SidecarMonitor.Event event : recorder.events) {
            assertTrue(
                    event.detail().equals("container_start") || event.detail().equals("healthcheck_pass"),
                    "detail escaped the fixed vocabulary: " + event.detail());
        }
    }

    // ─── g. injected-port containment (review round 1, finding 1) ────────

    @Test
    void throwingGenerationSupplierIsContainedAndRetried() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        // Swappable supplier: throws first, works after recovery.
        final class Swappable implements LongSupplier {
            LongSupplier delegate = () -> { throw new IllegalStateException("generation store down"); };
            @Override
            public long getAsLong() {
                return delegate.getAsLong();
            }
        }
        Swappable gen = new Swappable();
        SidecarMonitor m = new SidecarMonitor("127.0.0.1", fake.port(), cookie,
                Duration.ofSeconds(10), gen, recorder, recorder);
        monitors.add(m);

        // HEALTHY edge with a throwing supplier: contained, no throw.
        m.runOnce();
        assertEquals(2, recorder.events.size(), "STARTED + HEALTHY still emitted");
        assertEquals(0, recorder.rows.size(), "row deferred, not written with a dead supplier");

        // Still-throwing next cycle: the edge was re-armed, so HEALTHY is
        // re-emitted and the row retried (still contained).
        fake.awaitCycle();
        m.runOnce();
        fake.awaitCycle();
        assertEquals(3, recorder.events.size(), "HEALTHY edge re-armed");
        assertEquals(0, recorder.rows.size());

        // Supplier recovers → the deferred §4 row lands on the re-entry.
        gen.delegate = () -> 7L;
        m.runOnce();
        fake.awaitCycle();
        assertEquals(1, recorder.rows.size(), "deferred row written once the supplier recovers");
        assertEquals("{\"generation\":7}", recorder.rows.get(0)[2]);
        assertEquals("sidecar_healthy", recorder.rows.get(0)[0]);
    }

    // ─── h. bounded-reply guards are load-bearing (round 1, finding 2) ───

    @Test
    void oversizedReplyLineIsASilentFailedCycle() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=" + "x".repeat(9000) + " PROGRESS=100\r\n250 OK\r\n");
        m.runOnce();

        assertEquals(0, recorder.events.size(), "oversized reply line must abort the cycle");
        assertEquals(0, recorder.rows.size());

        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.events.size(), "monitor resumes after the bound trips");
    }

    @Test
    void overLongReplyIsASilentFailedCycle() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        StringBuilder tooManyLines = new StringBuilder();
        for (int i = 0; i < 67; i++) {
            tooManyLines.append("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=50\r\n");
        }
        tooManyLines.append("250 OK\r\n");
        fake.bootstrapReply.set(tooManyLines.toString());
        m.runOnce();

        assertEquals(0, recorder.events.size(), "over-long reply must abort the cycle");
        assertEquals(0, recorder.rows.size());

        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.events.size(), "monitor resumes after the bound trips");
    }
}
