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
 * Contract suite for the Tor ControlPort monitor (T039 + T074) — pins the
 * tickets' must-holds against a scripted fake ControlPort server: COOKIE auth
 * with the exact hex of the mounted cookie, the read-only command allowlist,
 * the fixed-vocabulary (kind, detail) pairings (control-grpc.md §"WatchEvents",
 * all six kinds), the edge-triggered §4 audit rows ({@code sidecar_healthy} on
 * each entry into HEALTHY; {@code sidecar_unhealthy} with {@code kind} on each
 * UNHEALTHY/STOPPED/CRASHED edge, once per lost session, never for RESTARTED),
 * and survivability of every failed-cycle shape (Principle II — the monitor is
 * advisory surface and must never take the control plane down).
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

        final int port;
        final List<String> received = new ArrayList<>();
        final AtomicInteger connections = new AtomicInteger();
        final AtomicReference<String> bootstrapReply = new AtomicReference<>(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
                + "250 OK\r\n");
        volatile boolean rejectAuth;
        volatile boolean malformedAuthReply;
        // T074 crash shape: answer 250 OK to AUTHENTICATE, then sever the
        // connection before GETINFO is answered (the abrupt-death shape the
        // monitor must report as CRASHED once a session was observed).
        volatile boolean dropAfterAuth;
        private volatile ServerSocket serverSocket;
        private volatile boolean acceptIdle;
        private final Thread accepter;
        private volatile boolean closed;

        FakeControlPort(byte[] cookie) throws IOException {
            ServerSocket ss = new ServerSocket(0, 16, java.net.InetAddress.getLoopbackAddress());
            this.serverSocket = ss;
            this.port = ss.getLocalPort();
            // Bounded accept: the accept loop revisits the (volatile) server
            // socket every 50 ms, so stopListening() can deterministically
            // wait for the accepter to leave a blocked accept() before the
            // next monitor dial (Linux does not wake accept() on close()).
            ss.setSoTimeout(50);
            final String expectedHex = SidecarMonitorTest.hex(cookie);
            this.accepter = new Thread(() -> {
                while (!closed) {
                    final ServerSocket current = serverSocket;
                    if (current == null || current.isClosed()) {
                        acceptIdle = true;
                        sleepQuietly(5);
                        continue;
                    }
                    try (Socket conn = current.accept()) {
                        connections.incrementAndGet();
                        handle(conn, expectedHex);
                    } catch (java.net.SocketTimeoutException stalled) {
                        acceptIdle = true;
                    } catch (IOException e) {
                        acceptIdle = true;
                        if (closed) {
                            break;
                        }
                        sleepQuietly(5);
                    }
                }
            }, "fake-control-port");
            accepter.setDaemon(true);
            accepter.start();
        }

        private static void sleepQuietly(long millis) {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
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
                        out.flush();
                        if (dropAfterAuth) {
                            conn.close();
                            return;
                        }
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
            return port;
        }

        /** Closes the listening socket: the monitor's next dial is REFUSED —
         * the honest "container exited, no listener" shape. Returns only once
         * the accepter has left a possibly-still-blocked accept(), so no
         * zombie listener can serve the next dial. */
        void stopListening() throws IOException, InterruptedException {
            acceptIdle = false;
            serverSocket.close();
            final long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
            while (!acceptIdle && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            if (!acceptIdle) {
                throw new IllegalStateException("fake accepter never released its accept() after close");
            }
        }

        /** Re-binds the same port after {@link #stopListening()}: the monitor's
         * next dial finds the sidecar back (the reconnect shape). */
        void resumeListening() throws IOException {
            ServerSocket ss = new ServerSocket(port, 16, java.net.InetAddress.getLoopbackAddress());
            ss.setSoTimeout(50);
            serverSocket = ss;
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

    /**
     * T074 containment probe: records events and healthy rows, but the audit
     * store throws whenever the §4 {@code sidecar_unhealthy} row is attempted.
     */
    private static final class UnhealthyRowThrower
            implements SidecarMonitor.EventSink, SidecarMonitor.AuditSink {
        final List<SidecarMonitor.Event> events = new ArrayList<>();
        final List<String[]> rows = new ArrayList<>();

        @Override
        public void publish(SidecarMonitor.Event event) {
            events.add(event);
        }

        @Override
        public void write(String action, String target, String detailJson) {
            if (action.equals(SidecarMonitor.ACTION_SIDECAR_UNHEALTHY)) {
                throw new IllegalStateException("audit store down");
            }
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
        // T074 shapes: a refused dial adds no wire line at all; a reconnect
        // and a mid-session crash use the same three commands.
        fake.stopListening();
        m.runOnce();
        fake.resumeListening();
        m.runOnce();
        fake.awaitCycle();
        fake.dropAfterAuth = true;
        m.runOnce();
        // the crash shape severs the connection before GETINFO is read, so
        // the fake's last recorded line is the AUTHENTICATE of that cycle
        fake.awaitLines("AUTHENTICATE " + hex(COOKIE));
        fake.dropAfterAuth = false;

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

        // 4: drop out of healthy — the T074 UNHEALTHY edge (data-model.md §4
        // supersedes the silent drop-out this leg pinned before T074)
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=95 TAG=circuit_create\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.rows.size(), "the regression edge writes the sidecar_unhealthy row");
        assertEquals("sidecar_unhealthy", recorder.rows.get(1)[0]);
        assertEquals("{\"kind\":\"UNHEALTHY\"}", recorder.rows.get(1)[2]);
        assertEquals(SidecarMonitor.Kind.UNHEALTHY,
                recorder.events.get(recorder.events.size() - 1).kind());

        // 5: re-enter → second healthy row
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(3, recorder.rows.size(), "each entry into healthy writes one row");
        assertEquals("sidecar_healthy", recorder.rows.get(2)[0]);
        // the drop-out was a bootstrap regression on a live session — no
        // lifecycle re-fire (no STARTED duplicate, no RESTARTED)
        assertEquals(1, recorder.events.stream().filter(e -> e.kind() == SidecarMonitor.Kind.STARTED).count());
        assertEquals(0, recorder.events.stream().filter(e -> e.kind() == SidecarMonitor.Kind.RESTARTED).count());
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

    // ─── i. failure transitions (T074) ───────────────────────────────────

    @Test
    void emitsUnhealthyOnBootstrapRegression() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        // 1: entry into healthy
        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.events.size());
        assertEquals(1, recorder.rows.size());

        // 2: regression while the session stays up → the UNHEALTHY edge
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=95 TAG=circuit_create\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        SidecarMonitor.Event unhealthy = recorder.events.get(2);
        assertEquals(SidecarMonitor.Kind.UNHEALTHY, unhealthy.kind());
        assertEquals("healthcheck_fail", unhealthy.detail());
        assertEquals("tor", unhealthy.sidecar());
        assertEquals(2, recorder.rows.size(), "exactly one §4 row on the regression edge");
        assertEquals("sidecar_unhealthy", recorder.rows.get(1)[0]);
        assertEquals("tor", recorder.rows.get(1)[1]);
        assertEquals("{\"kind\":\"UNHEALTHY\"}", recorder.rows.get(1)[2]);

        // 3: level stall — edge already consumed, nothing new
        m.runOnce();
        fake.awaitCycle();
        assertEquals(3, recorder.events.size(), "no repeated event while stalled");
        assertEquals(2, recorder.rows.size(), "no repeated row while stalled");

        // 4: recovery → HEALTHY edge + sidecar_healthy row again
        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(SidecarMonitor.Kind.HEALTHY, recorder.events.get(3).kind());
        assertEquals(3, recorder.rows.size());
        assertEquals("sidecar_healthy", recorder.rows.get(2)[0]);
        // the regression happened on a live session — no lifecycle re-fire
        assertEquals(1, recorder.events.stream().filter(e -> e.kind() == SidecarMonitor.Kind.STARTED).count());
        assertEquals(0, recorder.events.stream().filter(e -> e.kind() == SidecarMonitor.Kind.RESTARTED).count());
    }

    @Test
    void emitsStoppedWhenListenerVanishesAfterObservedSession() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();
        fake.awaitCycle();

        fake.stopListening();
        m.runOnce();
        SidecarMonitor.Event stopped = recorder.events.get(2);
        assertEquals(SidecarMonitor.Kind.STOPPED, stopped.kind());
        assertEquals("container_exit", stopped.detail());
        assertEquals(2, recorder.rows.size());
        assertEquals("sidecar_unhealthy", recorder.rows.get(1)[0]);
        assertEquals("{\"kind\":\"STOPPED\"}", recorder.rows.get(1)[2]);

        m.runOnce();
        assertEquals(3, recorder.events.size(), "the drop edge is consumed: exactly-once per lost session");
        assertEquals(2, recorder.rows.size());

        fake.resumeListening();
        m.runOnce();
        fake.awaitCycle();
        SidecarMonitor.Event restarted = recorder.events.get(3);
        assertEquals(SidecarMonitor.Kind.RESTARTED, restarted.kind());
        assertEquals("container_start", restarted.detail());
        // the drop reset the healthy edge, so the reconnecting cycle also
        // re-enters HEALTHY and writes the sidecar_healthy row again
        assertEquals(SidecarMonitor.Kind.HEALTHY, recorder.events.get(4).kind());
        assertEquals(3, recorder.rows.size());
        assertEquals("sidecar_healthy", recorder.rows.get(2)[0]);
    }

    @Test
    void emitsCrashedOnMidSessionDrop() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();
        fake.awaitCycle();

        fake.dropAfterAuth = true;
        m.runOnce();
        SidecarMonitor.Event crashed = recorder.events.get(2);
        assertEquals(SidecarMonitor.Kind.CRASHED, crashed.kind());
        assertEquals("container_exit", crashed.detail());
        assertEquals(2, recorder.rows.size());
        assertEquals("sidecar_unhealthy", recorder.rows.get(1)[0]);
        assertEquals("{\"kind\":\"CRASHED\"}", recorder.rows.get(1)[2]);

        fake.dropAfterAuth = false;
        fake.stopListening();
        m.runOnce();
        assertEquals(3, recorder.events.size(), "no second drop report in the same outage window");
        assertEquals(2, recorder.rows.size());

        fake.resumeListening();
        m.runOnce();
        fake.awaitCycle();
        assertEquals(SidecarMonitor.Kind.RESTARTED, recorder.events.get(3).kind());
        assertEquals(SidecarMonitor.Kind.HEALTHY, recorder.events.get(4).kind());
        assertEquals(3, recorder.rows.size());
        assertEquals("sidecar_healthy", recorder.rows.get(2)[0]);
    }

    @Test
    void coldFailuresBeforeFirstSessionEmitNoLifecycleEvents() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        // refused dials before ANY session: silence — no STOPPED/CRASHED
        fake.stopListening();
        m.runOnce();
        assertEquals(0, recorder.events.size(), "no lifecycle event before the first session");
        assertEquals(0, recorder.rows.size());

        // first-ever success: STARTED, not RESTARTED
        fake.resumeListening();
        m.runOnce();
        fake.awaitCycle();
        assertEquals(SidecarMonitor.Kind.STARTED, recorder.events.get(0).kind());
        assertEquals(2, recorder.events.size());

        // cold auth rejection: still no lifecycle claims
        FakeControlPort authFake = startFake();
        authFake.rejectAuth = true;
        Recorder authRecorder = new Recorder();
        SidecarMonitor authMonitor = monitor(authFake, writeCookie(), authRecorder);
        authMonitor.runOnce();
        authFake.awaitLines("AUTHENTICATE " + hex(COOKIE));
        assertEquals(0, authRecorder.events.size());
        assertEquals(0, authRecorder.rows.size());

        authFake.rejectAuth = false;
        authMonitor.runOnce();
        authFake.awaitCycle();
        assertEquals(SidecarMonitor.Kind.STARTED, authRecorder.events.get(0).kind(),
                "silent failed cycles do not turn the first success into a RESTARTED");
        assertEquals(0, authRecorder.events.stream()
                .filter(e -> e.kind() == SidecarMonitor.Kind.RESTARTED).count());
    }

    @Test
    void restartedIsEventOnly() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        Recorder recorder = new Recorder();
        SidecarMonitor m = monitor(fake, cookie, recorder);

        m.runOnce();
        fake.awaitCycle();

        fake.stopListening();
        m.runOnce();
        fake.resumeListening();
        m.runOnce();
        fake.awaitCycle();

        assertTrue(recorder.events.stream().anyMatch(
                e -> e.kind() == SidecarMonitor.Kind.RESTARTED && e.detail().equals("container_start")),
                "RESTARTED pairs container_start");
        for (String[] row : recorder.rows) {
            assertEquals("tor", row[1]);
            assertTrue(row[0].equals("sidecar_healthy") || row[0].equals("sidecar_unhealthy"),
                    "unexpected action: " + row[0]);
            if (row[0].equals("sidecar_unhealthy")) {
                // data-model.md §4: the sidecar_unhealthy kind vocabulary
                // excludes RESTARTED — and RESTARTED writes no row at all
                assertTrue(row[2].equals("{\"kind\":\"UNHEALTHY\"}")
                        || row[2].equals("{\"kind\":\"STOPPED\"}")
                        || row[2].equals("{\"kind\":\"CRASHED\"}"),
                        "sidecar_unhealthy vocabulary violation: " + row[2]);
            }
        }
        assertEquals(3, recorder.rows.size(), "healthy, STOPPED, healthy — and no RESTARTED row");
    }

    @Test
    void unhealthyAuditSinkThrowIsContained() throws Exception {
        FakeControlPort fake = startFake();
        Path cookie = writeCookie();
        UnhealthyRowThrower recorder = new UnhealthyRowThrower();
        SidecarMonitor m = new SidecarMonitor("127.0.0.1", fake.port(), cookie,
                Duration.ofSeconds(10), GENERATION_7, recorder, recorder);
        monitors.add(m);

        m.runOnce();
        fake.awaitCycle();
        assertEquals(2, recorder.events.size());
        assertEquals(1, recorder.rows.size());

        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=90 TAG=rendezvous\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(SidecarMonitor.Kind.UNHEALTHY, recorder.events.get(2).kind(),
                "the event still emits with a dead audit sink");
        assertEquals(1, recorder.rows.size(), "the unhealthy row was lost to the throwing sink");

        fake.bootstrapReply.set(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
        m.runOnce();
        fake.awaitCycle();
        assertEquals(SidecarMonitor.Kind.HEALTHY, recorder.events.get(3).kind(),
                "the monitor survives the sink throw");
        assertEquals(2, recorder.rows.size());
        assertEquals("sidecar_healthy", recorder.rows.get(1)[0]);
    }
}
