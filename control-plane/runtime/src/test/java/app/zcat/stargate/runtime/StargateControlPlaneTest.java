// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import app.zcat.stargate.auth.HmacVerifierMinter;
import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.sidecar.SidecarMonitor;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;
import io.quarkus.stargate.control.grpc.ControlGrpcService;
import io.quarkus.stargate.control.grpc.CpTls;
import io.quarkus.stargate.control.grpc.ReloadTokensClient;
import stargate.v1.ControlGrpc;
import stargate.v1.ControlOuterClass;
import stargate.v1.EventsOuterClass;

/**
 * Boot-sequence contract for the Quarkus control plane (T041; Principle VII
 * tests-first — the pepper/verifier wiring is authentication surface). The
 * suite drives the SAME {@code bootstrap} seam the production
 * {@code QuarkusApplication.run()} drives, with the real collaborators in
 * place — real {@code TokenLoader} (T035), real {@code ControlGrpcService}
 * (T038), real {@code ReloadTokensClient} (T038) over a real unix socket,
 * real {@code HmacVerifierMinter} — and fakes only where the spec's own seam
 * contract injects test doubles (the store/generation ports, T035a; the §4
 * audit sink).
 *
 * <p>Pinned here (ticket §Acceptance):
 *
 * <ul>
 *   <li>pepper fail-fast: a missing / non-32-byte {@code pepper.key} aborts
 *       the boot before anything binds (§1.7 — provisioning is T088's,
 *       validation is the reader's);</li>
 *   <li>failure ⇒ no push, boot survives: a missing or empty
 *       {@code tokens.yaml} logs and continues (FR-018 + T092 M1 — the DP
 *       keeps its last-known list; the verbatim body's "proceed with empty
 *       list" wording is retired by T092), with the §4 first-boot exemption
 *       (missing: no row) and the validation row (empty file);</li>
 *   <li>a valid file pushes HMAC verifiers under the pepper — end-to-end
 *       through the real channel and a DP stand-in on a real unix socket:
 *       generation = persisted 0 + 1, one 32-byte verifier equal to the
 *       reference HMAC, never the plaintext, never the pepper (§1.5/§1.6);</li>
 *   <li>a broken store is contained — the boot completes and the CP stays up
 *       (Principle II: the CP is advisory; a crash-loop would be
 *       indistinguishable from a DP outage);</li>
 *   <li>monitor events reach WatchEvents as mapped proto through the
 *       production event-sink adapter (fixed vocabulary, data-model §2);</li>
 *   <li>the ReloadTokens response maps to the T092 {@code PushResult}
 *       (stale + {@code current_generation}) and a transport failure is
 *       contained, never thrown (§1.8 durability: the next boot re-syncs);</li>
 *   <li>the minter is the §1.5 reference mint — and does NOT clear its input
 *       buffer (the loader owns the clear; a clearing minter would make
 *       TokenLoaderTest's buffer assertion tautological).</li>
 * </ul>
 *
 * <p>No plaintext fixture is ever assigned to a {@code token}-named local
 * (gitleaks generic-api-key hygiene, per TokenLifecycleContractTest's
 * precedent); the literal is the repo's documented example bearer token.
 */
class StargateControlPlaneTest {

    private static final int PEPPER_LEN = 32;
    private static final byte[] TEST_PEPPER = repeat((byte) 0x5a, PEPPER_LEN);

    /** The repo's documented example bearer token (allowlisted; inlined). */
    private static final String EXAMPLE_HEX = "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b";

    @TempDir
    Path tmp;

    // --- fixtures --------------------------------------------------------------

    private static byte[] repeat(byte b, int n) {
        byte[] out = new byte[n];
        Arrays.fill(out, b);
        return out;
    }

    private static KeyPair ed25519() {
        return KeyPairGeneratorHolder.GENERATOR.generateKeyPair();
    }

    /** Ed25519 is mandatory on TLS 1.3 JVMs; the holder just funnels the checked lookup. */
    private static final class KeyPairGeneratorHolder {
        static final java.security.KeyPairGenerator GENERATOR = holder();

        private static java.security.KeyPairGenerator holder() {
            try {
                return java.security.KeyPairGenerator.getInstance("Ed25519");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Ed25519 unavailable", e);
            }
        }
    }

    /** Writes a PEM file (64-column Base64, RFC 7468 armour) — InterPlaneWireTest's fixture. */
    private static void writePem(Path path, String type, byte[] der) throws IOException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + base64
                + "\n-----END " + type + "-----\n", StandardCharsets.US_ASCII);
    }

    /** The stargate-keys volume shape bootstrap reads: cp.priv / cp.pub / dp.pub. */
    private Path keysDir() throws IOException {
        Path keys = Files.createDirectories(tmp.resolve("keys"));
        KeyPair cp = ed25519();
        KeyPair dp = ed25519();
        writePem(keys.resolve("cp.priv"), "PRIVATE KEY", cp.getPrivate().getEncoded());
        writePem(keys.resolve("cp.pub"), "PUBLIC KEY", cp.getPublic().getEncoded());
        writePem(keys.resolve("dp.pub"), "PUBLIC KEY", dp.getPublic().getEncoded());
        // Test-only: the DP stand-in's private key, matching the pinned dp.pub
        // (in deployment the DP owns it; the stand-in lives in this JVM).
        writePem(keys.resolve("dp.priv"), "PRIVATE KEY", dp.getPrivate().getEncoded());
        return keys;
    }

    private Path pepperFile(byte[] content) throws IOException {
        Path p = tmp.resolve("pepper.key");
        Files.write(p, content);
        return p;
    }

    private Path tokensFile(String content) throws IOException {
        Path p = tmp.resolve("tokens.yaml");
        Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }

    private Path runDir() {
        try {
            return Files.createDirectories(tmp.resolve("run"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private StargateControlPlane.BootConfig cfg(Path tokensYaml, Path keys, Path dpSock) {
        return new StargateControlPlane.BootConfig(tokensYaml, tmp.resolve("pepper.key"), keys,
                runDir().resolve("control.sock"), dpSock, "tor", 9051,
                runDir().resolve("control_auth_cookie"), Duration.ofSeconds(10));
    }

    /** Reference §1.5 mint — mirrors TokenLifecycleContractTest cross-module. */
    private static byte[] referenceMint(byte[] pepper, String token) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
            return mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new AssertionError("HMAC-SHA-256 unavailable: " + e.getMessage(), e);
        }
    }

    /** Records the store/generation port calls; can fail {@code begin()} on demand. */
    private static final class RecordingState
            implements TokenLoaderContract.ConfiguredTokenStore, TokenLoaderContract.GenerationStore {

        final List<String> upserts = new CopyOnWriteArrayList<>();
        final List<String> deletes = new CopyOnWriteArrayList<>();
        final List<Long> recorded = new CopyOnWriteArrayList<>();
        long lastGeneration;
        volatile RuntimeException beginFailure;

        @Override
        public java.util.Collection<TokenLoaderContract.StoredToken> storedTokens() {
            return List.of();
        }

        @Override
        public void begin() {
            RuntimeException failure = beginFailure;
            if (failure != null) {
                throw failure;
            }
        }

        @Override
        public void upsert(String label, byte[] verifier) {
            upserts.add(label);
        }

        @Override
        public void delete(String label) {
            deletes.add(label);
        }

        @Override
        public void commit() {
        }

        @Override
        public long lastGeneration() {
            return lastGeneration;
        }

        @Override
        public void record(long generation) {
            recorded.add(generation);
        }
    }

    /** Records §4 audit rows as (action, target, detailJson) triples. */
    private static final class RecordingAudit implements TokenLoaderContract.AuditSink {
        final List<String[]> rows = new CopyOnWriteArrayList<>();

        @Override
        public void write(String action, String target, String detailJson) {
            rows.add(new String[] { action, target, detailJson });
        }
    }

    /**
     * A DP stand-in on dp.sock — the mirror of the real DP server (T045): DP
     * identity cert, clients pinned against cp.pub, answering OK. Records
     * every ReloadTokensRequest so the test can assert what crossed the wire.
     */
    private static final class RecordingDp implements AutoCloseable {

        final List<ControlOuterClass.ReloadTokensRequest> requests;
        final List<Long> completedGenerations;
        private final io.grpc.Server server;
        private final EpollEventLoopGroup boss;
        private final EpollEventLoopGroup workers;

        private RecordingDp(io.grpc.Server server, EpollEventLoopGroup boss,
                EpollEventLoopGroup workers, List<ControlOuterClass.ReloadTokensRequest> requests,
                List<Long> completedGenerations) {
            this.server = server;
            this.boss = boss;
            this.workers = workers;
            this.requests = requests;
            this.completedGenerations = completedGenerations;
        }

        static RecordingDp start(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false);
        }

        static RecordingDp startWithDelayedStaleThenOk(
                Path dpSock, Path keysDir, Path dpPubPath, Path cpPub) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, true);
        }

        private static RecordingDp start(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                boolean delayedStaleThenOk) throws Exception {
            // The DP stand-in's identity: a cert carrying the pinned dp keypair,
            // derived through the public file-based path (deriveCpIdentity's CN
            // is cosmetic — §3 pins the public key, not the name).
            var dpIdentity = CpTls.deriveCpIdentity(keysDir.resolve("dp.priv"), dpPubPath);
            var boss = new EpollEventLoopGroup(1);
            var workers = new EpollEventLoopGroup();
            List<ControlOuterClass.ReloadTokensRequest> captured = new CopyOnWriteArrayList<>();
            List<Long> completed = new CopyOnWriteArrayList<>();
            var attempts = new java.util.concurrent.atomic.AtomicInteger();
            io.grpc.Server server;
            try {
                server = NettyServerBuilder
                        .forAddress((java.net.SocketAddress) new DomainSocketAddress(dpSock.toString()))
                        .bossEventLoopGroup(boss)
                        .workerEventLoopGroup(workers)
                        .channelType(EpollServerDomainSocketChannel.class)
                        .sslContext(CpTls.serverContext(dpIdentity, cpPub))
                        .addService(new ControlGrpc.ControlImplBase() {
                            @Override
                            public void reloadTokens(ControlOuterClass.ReloadTokensRequest request,
                                    StreamObserver<ControlOuterClass.ReloadTokensResponse> response) {
                                captured.add(request);
                                int attempt = attempts.incrementAndGet();
                                if (delayedStaleThenOk) {
                                    try {
                                        Thread.sleep(TimeUnit.SECONDS.toMillis(attempt == 1 ? 6 : 5));
                                    } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                        response.onError(e);
                                        return;
                                    }
                                }
                                var reply = ControlOuterClass.ReloadTokensResponse.newBuilder();
                                if (delayedStaleThenOk && attempt == 1) {
                                    reply.setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_STALE_GENERATION)
                                            .setCurrentGeneration(5);
                                } else {
                                    reply.setAppliedGeneration(request.getGeneration())
                                            .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK);
                                }
                                response.onNext(reply.build());
                                response.onCompleted();
                                completed.add(request.getGeneration());
                            }
                        })
                        .intercept(new ServerInterceptor() {
                            @Override
                            public <ReqT, RespT> io.grpc.ServerCall.Listener<ReqT> interceptCall(
                                    ServerCall<ReqT, RespT> call, Metadata headers,
                                    ServerCallHandler<ReqT, RespT> next) {
                                return next.startCall(call, headers);
                            }
                        })
                        .build()
                        .start();
            } catch (Exception e) {
                boss.shutdownGracefully();
                workers.shutdownGracefully();
                throw e;
            }
            return new RecordingDp(server, boss, workers, captured, completed);
        }

        @Override
        public void close() {
            server.shutdownNow();
            try {
                server.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            boss.shutdownGracefully();
            workers.shutdownGracefully();
        }
    }

    // --- pepper fail-fast (§1.7; T092 a) ---------------------------------------

    @Test
    void missingPepperFailsFast() throws Exception {
        StargateControlPlane.BootConfig cfg = cfg(tmp.resolve("tokens.yaml"), keysDir(),
                runDir().resolve("dp.sock"));
        // no pepper.key written
        IllegalStateException err = assertThrows(IllegalStateException.class,
                () -> StargateControlPlane.bootstrap(cfg, new RecordingAudit(), new RecordingState(),
                        new RecordingState()),
                "a missing pepper must abort the boot (§1.7 — the CP cannot mint verifiers)");
        assertTrue(err.getMessage().contains("pepper"), "the failure names the concern");
        assertFalse(Files.exists(runDir().resolve("control.sock")),
                "no partial start: the control.sock server must not have bound");
    }

    @Test
    void shortPepperFailsFast() throws Exception {
        pepperFile(repeat((byte) 0x11, 31));
        StargateControlPlane.BootConfig cfg = cfg(tmp.resolve("tokens.yaml"), keysDir(),
                runDir().resolve("dp.sock"));
        IllegalStateException err = assertThrows(IllegalStateException.class,
                () -> StargateControlPlane.bootstrap(cfg, new RecordingAudit(), new RecordingState(),
                        new RecordingState()),
                "a non-32-byte pepper must abort the boot (§1.7 edge validation)");
        assertTrue(err.getMessage().contains("32"),
                "the failure names the required length, not the bytes");
        assertFalse(Files.exists(runDir().resolve("control.sock")), "no partial start");
    }

    // --- failure ⇒ no push, boot survives (FR-018 + T092 M1) -------------------

    @Test
    void bootsWithoutTokensFile() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        // no tokens.yaml — the legitimate first-boot state
        RecordingState state = new RecordingState();
        RecordingAudit audit = new RecordingAudit();
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tmp.resolve("tokens.yaml"), keys, runDir().resolve("dp.sock")), audit, state, state)) {
            assertNotNull(handle, "boot completes");
            assertTrue(Files.exists(runDir().resolve("control.sock")),
                    "the CP wire surface (control.sock) is up");
            assertTrue(state.upserts.isEmpty() && state.recorded.isEmpty(),
                    "missing file: no store writes (§1.1/§1.6)");
            assertTrue(audit.rows.isEmpty(), "missing file: NO audit row (§4 first-boot exemption)");
        }
    }

    /**
     * Round-1 review F1 (the Major): the monitor-start step of the boot
     * sequence must be OBSERVED, not just inspection-pinned. A fake tor
     * ControlPort answers the cookie-auth handshake; the boot-wired monitor's
     * first tick enters HEALTHY and its §4 {@code sidecar_healthy} row arrives
     * through the production {@code audit::write} adapter, carrying the
     * generation supplier's value. Deleting {@code monitor.start()} (or
     * unwiring the adapter / the supplier) leaves the await empty → red.
     *
     * <p>The start-BEFORE-load ordering sub-property of acceptance item 3
     * stays inspection-pinned — the fake answers on the monitor's own thread
     * and no load-side hook exists to order against; this probe claims the
     * START + wiring, not the order. (This test's fast poll + live fake is its
     * own BootConfig; {@code bootsWithoutTokensFile}'s 10 s poll + absent tor
     * guarantees its no-audit-row assertion stays valid.)
     */
    @Test
    void monitorStartIsWiredAtBootAndFeedsTheAuditAdapter() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        byte[] cookie = new byte[32];
        Arrays.fill(cookie, (byte) 0xA0);
        Files.write(runDir().resolve("control_auth_cookie"), cookie);
        try (FakeControlPort tor = new FakeControlPort()) {
            StargateControlPlane.BootConfig fastPoll = new StargateControlPlane.BootConfig(
                    tmp.resolve("tokens.yaml"), tmp.resolve("pepper.key"), keys,
                    runDir().resolve("control.sock"), runDir().resolve("dp.sock"),
                    "127.0.0.1", tor.port, runDir().resolve("control_auth_cookie"),
                    Duration.ofMillis(50));
            RecordingState state = new RecordingState();
            RecordingAudit audit = new RecordingAudit();
            try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                    fastPoll, audit, state, state)) {
                assertNotNull(handle, "boot completes");
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while (audit.rows.stream().noneMatch(r -> "sidecar_healthy".equals(r[0]))
                        && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                java.util.Optional<String[]> row = audit.rows.stream()
                        .filter(r -> "sidecar_healthy".equals(r[0]))
                        .findFirst();
                assertTrue(row.isPresent(),
                        "the boot-wired monitor entered HEALTHY and wrote its §4 row through "
                                + "the production audit adapter (monitor.start() is live)");
                assertEquals("tor", row.get()[1], "target is the one sidecar (control-grpc §\"WatchEvents\")");
                assertEquals("{\"generation\":0}", row.get()[2],
                        "the §1.8 generation supplier is wired to the store (fresh state ⇒ 0)");
            }
        }
    }

    /**
     * Round-1 review F2: the shutdown teardown must be observed — a leaked
     * control.sock (emptied {@code close()}, dropped reverse-order teardown)
     * makes the SECOND bind on the same path fail. Booting twice through the
     * same BootConfig is the mechanical probe for acceptance item 3's
     * "closes monitor/client/server on shutdown".
     */
    @Test
    void teardownReleasesTheControlSockForRebind() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        StargateControlPlane.BootConfig shared = cfg(tmp.resolve("tokens.yaml"), keys,
                runDir().resolve("dp.sock"));
        try (StargateControlPlane.BootHandle first = StargateControlPlane.bootstrap(
                shared, new RecordingAudit(), new RecordingState(), new RecordingState())) {
            assertNotNull(first, "first boot binds control.sock");
        }
        try (StargateControlPlane.BootHandle second = StargateControlPlane.bootstrap(
                shared, new RecordingAudit(), new RecordingState(), new RecordingState())) {
            assertNotNull(second, "close() released control.sock: the same path binds again");
        }
    }

    /**
     * Minimal tor ControlPort stand-in: loops back the only three commands the
     * monitor may send (T039's allowlist) with 2xx replies, bootstrap phase
     * PROGRESS=100 — the first session's HEALTHY edge. The wire-level
     * properties (hex cookie, allowlist, reply parsing) are SidecarMonitorTest's
     * ground; this fake exists only to make the boot's monitor wiring observable.
     */
    private static final class FakeControlPort implements AutoCloseable {

        final int port;
        private final java.net.ServerSocket serverSocket;
        private final Thread accepter;
        private volatile boolean closed;

        FakeControlPort() throws IOException {
            java.net.ServerSocket ss = new java.net.ServerSocket(0, 8,
                    java.net.InetAddress.getLoopbackAddress());
            this.serverSocket = ss;
            this.port = ss.getLocalPort();
            this.accepter = new Thread(this::acceptLoop, "fake-tor-controlport");
            this.accepter.setDaemon(true);
            this.accepter.start();
        }

        private void acceptLoop() {
            while (!closed) {
                try (java.net.Socket socket = serverSocket.accept()) {
                    serve(socket);
                } catch (IOException quiet) {
                    // close() or a failed cycle — the monitor's next dial retries
                }
            }
        }

        private void serve(java.net.Socket socket) {
            try {
                socket.setSoTimeout(2000);
                var in = new java.io.BufferedReader(new java.io.InputStreamReader(
                        socket.getInputStream(), StandardCharsets.ISO_8859_1));
                var out = new java.io.OutputStreamWriter(socket.getOutputStream(),
                        StandardCharsets.ISO_8859_1);
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.startsWith("GETINFO")) {
                        out.write("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n");
                    }
                    out.write("250 OK\r\n");
                    out.flush();
                    if (line.startsWith("QUIT")) {
                        break;
                    }
                }
            } catch (IOException quiet) {
                // the cycle died mid-session; the monitor classifies it
            }
        }

        @Override
        public void close() throws IOException {
            closed = true;
            serverSocket.close();
        }
    }

    @Test
    void bootsWithEmptyTokensFileAndWritesConfigError() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("");
        RecordingState state = new RecordingState();
        RecordingAudit audit = new RecordingAudit();
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tokens, keys, runDir().resolve("dp.sock")), audit, state, state)) {
            assertNotNull(handle, "an empty tokens.yaml must not kill the boot (FR-018)");
            assertEquals(1, audit.rows.size(), "exactly one config_error row");
            assertEquals("config_error", audit.rows.get(0)[0]);
            assertEquals("tokens.yaml", audit.rows.get(0)[1]);
            assertTrue(audit.rows.get(0)[2].startsWith("{\"kind\":\"validation\""),
                    "an empty document is a structural validation failure: " + audit.rows.get(0)[2]);
            assertTrue(state.upserts.isEmpty() && state.recorded.isEmpty(),
                    "failure semantics: no store writes, no generation bump");
        }
    }

    // --- valid file: the push crosses the wire (§1.5/§1.6/§1.7) ----------------

    @Test
    void validTokensFilePushesHmacVerifiersUnderPepper() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp.sock");
        try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"),
                        keys.resolve("cp.pub"));
                StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                        cfg(tokens, keys, dpSock), new RecordingAudit(), new RecordingState(),
                        new RecordingState())) {
            assertNotNull(handle);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (dp.requests.isEmpty() && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertEquals(1, dp.requests.size(), "exactly one ReloadTokens push");
            ControlOuterClass.ReloadTokensRequest request = dp.requests.get(0);
            assertEquals(1L, request.getGeneration(), "generation = persisted 0 + 1 (§1.8)");
            assertEquals(1, request.getTokensCount());
            byte[] verifier = request.getTokens(0).getVerifier().toByteArray();
            assertArrayEquals(referenceMint(TEST_PEPPER, EXAMPLE_HEX), verifier,
                    "the pushed verifier is HMAC-SHA-256(pepper, token) (§1.5)");
            assertFalse(Arrays.equals(TEST_PEPPER, verifier),
                    "the pepper NEVER crosses the wire (§1.6)");
            assertFalse(new String(verifier, StandardCharsets.US_ASCII).contains(EXAMPLE_HEX),
                    "the plaintext never crosses the wire (§1.6)");
        }
    }

    @Test
    void staleReconciliationGetsFreshDeadlineForTheNextAttempt() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp.sock");
        RecordingState state = new RecordingState();
        try (RecordingDp dp = RecordingDp.startWithDelayedStaleThenOk(
                        dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                        cfg(tokens, keys, dpSock), new RecordingAudit(), state, state)) {
            assertNotNull(handle);
            assertEquals(List.of(1L, 6L),
                    dp.requests.stream().map(ControlOuterClass.ReloadTokensRequest::getGeneration).toList(),
                    "the loader adopts current_generation + 1 for its bounded stale retry");
            assertEquals(List.of(1L, 6L), dp.completedGenerations,
                    "both delayed RPCs complete because the retry receives a fresh deadline");
            assertEquals(List.of(1L, 6L), state.recorded,
                    "the existing generation-recording policy is preserved");
        }
    }

    // --- broken infrastructure is contained (Principle II) ----------------------

    @Test
    void brokenStoreDoesNotKillBoot() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        RecordingState state = new RecordingState();
        state.beginFailure = new IllegalStateException("sqlite gone");
        RecordingAudit audit = new RecordingAudit();
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tokens, keys, runDir().resolve("dp.sock")), audit, state, state)) {
            assertNotNull(handle, "a broken store is contained: the CP stays up (Principle II)");
            assertTrue(audit.rows.isEmpty(), "the failed load wrote no audit rows");
        }
    }

    // --- WatchEvents surface (control-grpc §"WatchEvents"; data-model §2) -------

    @Test
    void sidecarEventsReachWatchEventsAsMappedProto() {
        ControlGrpcService events = new ControlGrpcService();
        List<EventsOuterClass.SidecarEvent> received = new CopyOnWriteArrayList<>();
        events.watchEvents(EventsOuterClass.WatchEventsRequest.getDefaultInstance(),
                new StreamObserver<>() {
                    @Override
                    public void onNext(EventsOuterClass.SidecarEvent value) {
                        received.add(value);
                    }

                    @Override
                    public void onError(Throwable t) {
                    }

                    @Override
                    public void onCompleted() {
                    }
                });
        SidecarMonitor.EventSink sink = StargateControlPlane.eventSink(events);
        record Mapping(SidecarMonitor.Kind kind, String detail, EventsOuterClass.EventKind proto) {
        }
        List<Mapping> mappings = List.of(
                new Mapping(SidecarMonitor.Kind.STARTED, "container_start",
                        EventsOuterClass.EventKind.EVENT_KIND_STARTED),
                new Mapping(SidecarMonitor.Kind.HEALTHY, "healthcheck_pass",
                        EventsOuterClass.EventKind.EVENT_KIND_HEALTHY),
                new Mapping(SidecarMonitor.Kind.UNHEALTHY, "healthcheck_fail",
                        EventsOuterClass.EventKind.EVENT_KIND_UNHEALTHY),
                new Mapping(SidecarMonitor.Kind.STOPPED, "container_exit",
                        EventsOuterClass.EventKind.EVENT_KIND_STOPPED),
                new Mapping(SidecarMonitor.Kind.CRASHED, "container_exit",
                        EventsOuterClass.EventKind.EVENT_KIND_CRASHED),
                new Mapping(SidecarMonitor.Kind.RESTARTED, "container_start",
                        EventsOuterClass.EventKind.EVENT_KIND_RESTARTED));
        Instant now = Instant.now();
        for (Mapping m : mappings) {
            sink.publish(new SidecarMonitor.Event(now, SidecarMonitor.SIDECAR_TOR, m.kind(), m.detail()));
        }
        assertEquals(6, received.size(), "every mapped event reached the live stream");
        for (int i = 0; i < mappings.size(); i++) {
            EventsOuterClass.SidecarEvent proto = received.get(i);
            assertEquals(SidecarMonitor.SIDECAR_TOR, proto.getSidecar());
            assertEquals(mappings.get(i).proto(), proto.getKind(), "kind mapped 1:1");
            assertEquals(mappings.get(i).detail(), proto.getDetail(),
                    "fixed vocabulary passes through");
            assertTrue(proto.hasTs() && proto.getTs().getSeconds() >= now.getEpochSecond() - 1,
                    "ts is the emission instant");
        }
    }

    // --- ReloadTokens response mapping + transport containment (§1.8) -----------

    @Test
    void staleAndOkResponsesMapToPushResult() {
        var stale = ControlOuterClass.ReloadTokensResponse.newBuilder()
                .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_STALE_GENERATION)
                .setCurrentGeneration(9)
                .build();
        TokenLoaderContract.PushResult mapped = GrpcReloadChannel.toPushResult(stale);
        assertTrue(mapped.stale(),
                "STALE_GENERATION maps to stale=true (compared via the proto3 _VALUE accessor — "
                        + "the T022 row-10 gate greps the lowerCamelCase getter literal)");
        assertEquals(9L, mapped.currentGeneration(),
                "the DP's current_generation rides the result (T092 reconciliation)");

        var ok = ControlOuterClass.ReloadTokensResponse.newBuilder()
                .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK)
                .setAppliedGeneration(5)
                .build();
        TokenLoaderContract.PushResult okMapped = GrpcReloadChannel.toPushResult(ok);
        assertFalse(okMapped.stale(), "OK maps to stale=false");
    }

    @Test
    void transportFailureIsContained() throws Exception {
        Path keys = keysDir();
        // a real client dialing an ABSENT dp.sock: the connect fails immediately (ENOENT)
        try (ReloadTokensClient client = ReloadTokensClient.create(keys, runDir().resolve("no-dp.sock"))) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client);
            TokenLoaderContract.PushResult result = channel.push(3, List.of(repeat((byte) 0x2a, 32)));
            assertNotNull(result, "the transport failure is contained, never thrown (§1.8)");
            assertFalse(result.stale(), "a contained failure is not a stale rejection");
        }
        assertFalse(Thread.currentThread().isInterrupted(), "containment leaves no phantom interrupt");
    }

    // --- the production minter (§1.5) -------------------------------------------

    @Test
    void minterMintsReferenceHmacWithoutClearingInput() {
        HmacVerifierMinter minter = new HmacVerifierMinter(TEST_PEPPER);
        byte[] input = EXAMPLE_HEX.getBytes(StandardCharsets.UTF_8);
        byte[] verifier = minter.mint(input);
        assertArrayEquals(referenceMint(TEST_PEPPER, EXAMPLE_HEX), verifier,
                "the production minter is the §1.5 reference mint");
        assertEquals(32, verifier.length);
        byte[] again = minter.mint(input);
        assertArrayEquals(verifier, again, "deterministic (§1.5 restart-safety)");
        assertNotEquals(0, input[0],
                "the minter does NOT clear its input buffer — the clear is the loader's "
                        + "mint-then-clear step (§1.1 narrowed claim; T035a non-tautology)");
    }
}
