// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;

import app.zcat.stargate.auth.HmacVerifierMinter;
import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.persistence.SqliteTokenState;
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
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.UserTransaction;
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
    static final byte[] TEST_PEPPER = repeat((byte) 0x5a, PEPPER_LEN);

    /** The repo's documented example bearer token (allowlisted; inlined). */
    static final String EXAMPLE_HEX = "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b";
    private static final String REPLACEMENT_HEX = "2b3c4d5e6f70819a8b7c6d5e4f3a2b1c";

    @TempDir
    Path tmp;

    // --- fixtures --------------------------------------------------------------

    static byte[] repeat(byte b, int n) {
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
        return writeKeys(tmp);
    }

    static Path writeKeys(Path root) throws IOException {
        Path keys = Files.createDirectories(root.resolve("keys"));
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
                runDir().resolve("control.sock"), dpSock,
                runDir().resolve("observer.sock"), Duration.ofSeconds(10), deliveryStatus());
    }

    /** T187: the CP-private volatile status file (tmpfs in deployment). */
    private Path deliveryStatus() {
        return tmp.resolve("cp-status").resolve("auth-delivery");
    }

    /** Current status file content, or {@code null} when none is published. */
    private String readDeliveryStatus() throws IOException {
        Path status = deliveryStatus();
        return Files.exists(status) ? Files.readString(status, StandardCharsets.US_ASCII) : null;
    }

    record StatusCommandResult(int exitCode, String output) {
    }

    private record RequestCensus(int count, boolean settled) {
    }

    private static RequestCensus awaitStableRequestCount(List<?> requests) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        long stableSince = System.nanoTime();
        int count = requests.size();
        while (System.nanoTime() < deadline && System.nanoTime() - stableSince < TimeUnit.MILLISECONDS.toNanos(250)) {
            Thread.sleep(20);
            int current = requests.size();
            if (current != count) {
                count = current;
                stableSince = System.nanoTime();
            }
        }
        return new RequestCensus(count, System.nanoTime() - stableSince >= TimeUnit.MILLISECONDS.toNanos(250));
    }

    private StatusCommandResult statusCommandForFile(Path statusFile) throws Exception {
        return statusCommandForFile(statusFile, tmp);
    }

    static StatusCommandResult statusCommandForFile(Path statusFile, Path tempRoot) throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (repo != null && !Files.isRegularFile(repo.resolve("scripts/stargate"))) {
            repo = repo.getParent();
        }
        assertNotNull(repo, "repository root with scripts/stargate");
        String actualState = Files.readString(statusFile, StandardCharsets.US_ASCII).stripTrailing();
        Path bin = Files.createDirectories(tempRoot.resolve("status-from-channel-bin"));
        Path docker = bin.resolve("docker");
        Files.writeString(docker, """
                #!/bin/sh
                case "$1" in
                  info) exit 0 ;;
                  compose)
                    case "$*" in
                      *" version"*) exit 0 ;;
                      *" ps "*) echo 0123abcd; exit 0 ;;
                      *" exec "*) printf '%s\\n' "$STUB_EXEC"; exit 0 ;;
                    esac ;;
                esac
                exit 0
                """);
        docker.toFile().setExecutable(true);
        var processBuilder = new ProcessBuilder("/bin/bash", repo.resolve("scripts/stargate").toString(), "status")
                .redirectErrorStream(true);
        processBuilder.environment().put("PATH", bin + ":/usr/bin:/bin");
        processBuilder.environment().put("STUB_EXEC", actualState);
        processBuilder.environment().put("STARGATE_ENV_FILE", tempRoot.resolve("local.env").toString());
        processBuilder.environment().put("STARGATE_ENV_EXAMPLE", tempRoot.resolve("absent.env.example").toString());
        Process process = processBuilder.start();
        byte[] output = process.getInputStream().readNBytes(16 * 1024);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "bounded local status command exits");
        return new StatusCommandResult(process.exitValue(), new String(output, StandardCharsets.UTF_8));
    }

    private String awaitDeliveryStatus(String expected) throws Exception {
        return awaitDeliveryStatus(expected, Duration.ofSeconds(10));
    }

    private String awaitDeliveryStatus(String expected, Duration within) throws Exception {
        long deadline = System.nanoTime() + within.toNanos();
        String seen = readDeliveryStatus();
        while (!expected.equals(seen) && System.nanoTime() < deadline) {
            Thread.sleep(20);
            seen = readDeliveryStatus();
        }
        return seen;
    }

    private static long rowCount(RecordingAudit audit, String action) {
        return audit.rows.stream().filter(row -> row[0].equals(action)).count();
    }

    /** Durable CP authority at generation 1 holding laptop + phone. */
    private static RecordingState laptopAndPhoneAtGeneration1() {
        RecordingState state = new RecordingState();
        state.stored.add(new TokenLoaderContract.StoredToken("laptop", referenceMint(TEST_PEPPER, EXAMPLE_HEX)));
        state.stored.add(new TokenLoaderContract.StoredToken("phone", referenceMint(TEST_PEPPER, REPLACEMENT_HEX)));
        state.lastGeneration = 1;
        return state;
    }

    private static ReloadTokensClient shortLivedReloadClient(Path keys, Path dpSock,
            Duration lifetime) throws Exception {
        var factory = ReloadTokensClient.class.getDeclaredMethod("create",
                Path.class, Path.class, Path.class, Duration.class);
        factory.setAccessible(true);
        return (ReloadTokensClient) factory.invoke(null, keys, dpSock, keys.resolve("dp.pub"), lifetime);
    }

    /** Reference §1.5 mint — mirrors TokenLifecycleContractTest cross-module. */
    static byte[] referenceMint(byte[] pepper, String token) {
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
        final List<TokenLoaderContract.StoredToken> stored = new CopyOnWriteArrayList<>();
        long lastGeneration;
        volatile RuntimeException beginFailure;
        volatile RuntimeException deliveryFailure;
        volatile RuntimeException prearmFailure;
        volatile RuntimeException acknowledgementFailure;
        volatile RuntimeException staleFailure;
        final AtomicInteger acknowledgementAttempts = new AtomicInteger();
        final AtomicInteger staleAttempts = new AtomicInteger();
        final AtomicInteger prearmAttempts = new AtomicInteger();
        volatile java.util.concurrent.CountDownLatch prearmAttemptFinished;
        volatile java.util.concurrent.CountDownLatch acknowledgementAttemptFinished;
        volatile java.util.concurrent.CountDownLatch staleAttemptFinished;
        volatile TokenLoaderContract.GenerationStore.DeliveryMarker delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0);

        @Override
        public java.util.Collection<TokenLoaderContract.StoredToken> storedTokens() {
            return List.copyOf(stored);
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
            stored.removeIf(row -> row.label().equals(label));
            stored.add(new TokenLoaderContract.StoredToken(label, verifier.clone()));
        }

        @Override
        public void delete(String label) {
            deletes.add(label);
            stored.removeIf(row -> row.label().equals(label));
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
            lastGeneration = generation;
        }

        @Override
        public synchronized TokenLoaderContract.GenerationStore.DeliveryMarker deliveryMarker() {
            RuntimeException failure = deliveryFailure;
            if (failure != null) {
                throw failure;
            }
            return delivery;
        }

        @Override
        public synchronized boolean prearmDelivery(long generation) {
            prearmAttempts.incrementAndGet();
            try {
                RuntimeException transitionFailure = prearmFailure;
                if (transitionFailure != null) {
                    throw transitionFailure;
                }
                RuntimeException failure = deliveryFailure;
                if (failure != null) {
                    throw failure;
                }
                if (delivery.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE
                        || (delivery.state() == TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                                && delivery.generation() != generation)) {
                    return false;
                }
                delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, generation);
                return true;
            } finally {
                java.util.concurrent.CountDownLatch finished = prearmAttemptFinished;
                if (finished != null) {
                    finished.countDown();
                }
            }
        }

        @Override
        public synchronized boolean acknowledgeDelivery(long generation) {
            acknowledgementAttempts.incrementAndGet();
            try {
                RuntimeException transitionFailure = acknowledgementFailure;
                if (transitionFailure != null) {
                    throw transitionFailure;
                }
                RuntimeException failure = deliveryFailure;
                if (failure != null) {
                    throw failure;
                }
                if (delivery.state() != TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                        || delivery.generation() != generation) {
                    return false;
                }
                delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0);
                return true;
            } finally {
                java.util.concurrent.CountDownLatch finished = acknowledgementAttemptFinished;
                if (finished != null) {
                    finished.countDown();
                }
            }
        }

        @Override
        public synchronized boolean recordStaleDelivery(long generation) {
            staleAttempts.incrementAndGet();
            try {
                RuntimeException transitionFailure = staleFailure;
                if (transitionFailure != null) {
                    throw transitionFailure;
                }
                RuntimeException failure = deliveryFailure;
                if (failure != null) {
                    throw failure;
                }
                if (delivery.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE) {
                    return delivery.generation() == generation;
                }
                if (delivery.state() != TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                        || delivery.generation() != generation) {
                    return false;
                }
                delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.STALE, generation);
                return true;
            } finally {
                java.util.concurrent.CountDownLatch finished = staleAttemptFinished;
                if (finished != null) {
                    finished.countDown();
                }
            }
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
     * identity cert, clients pinned against cp.pub, returning an exact T159
     * durable acknowledgment unless the stale fixture is selected. Records
     * every ReloadTokensRequest so the test can assert what crossed the wire.
     */
    static final class RecordingDp implements AutoCloseable {

        private record UnavailableThenHeldRetry(
                java.util.concurrent.CountDownLatch firstArrived,
                java.util.concurrent.CountDownLatch releaseFirstFailure,
                java.util.concurrent.CountDownLatch retryArrived,
                java.util.concurrent.CountDownLatch releaseRetryAck) {
        }

        final List<ControlOuterClass.ReloadTokensRequest> requests;
        final List<Long> completedGenerations;
        private final io.grpc.Server server;
        private final EpollEventLoopGroup boss;
        private final EpollEventLoopGroup workers;
        private final java.util.concurrent.CountDownLatch requestArrived;
        private final java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();

        private RecordingDp(io.grpc.Server server, EpollEventLoopGroup boss,
                EpollEventLoopGroup workers, List<ControlOuterClass.ReloadTokensRequest> requests,
                List<Long> completedGenerations, java.util.concurrent.CountDownLatch requestArrived) {
            this.server = server;
            this.boss = boss;
            this.workers = workers;
            this.requests = requests;
            this.completedGenerations = completedGenerations;
            this.requestArrived = requestArrived;
        }

        static RecordingDp start(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, false, false, false, null);
        }

        /** T187: every reply waits for {@code release}, holding the RPC outstanding. */
        static RecordingDp startHeld(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                java.util.concurrent.CountDownLatch release) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, false, false, false, release);
        }

        static RecordingDp startHeldObserved(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                java.util.concurrent.CountDownLatch release, java.util.concurrent.CountDownLatch arrived)
                throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, false, false, false, release, arrived);
        }

        static RecordingDp startUnavailableThenHeldRetryObserved(Path dpSock, Path keysDir,
                Path dpPubPath, Path cpPub,
                java.util.concurrent.CountDownLatch firstArrived,
                java.util.concurrent.CountDownLatch releaseFirstFailure,
                java.util.concurrent.CountDownLatch retryArrived,
                java.util.concurrent.CountDownLatch releaseRetryAck) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, false, false, false,
                    null, null, new UnavailableThenHeldRetry(
                            firstArrived, releaseFirstFailure, retryArrived, releaseRetryAck));
        }

        static RecordingDp startHeldStale(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                java.util.concurrent.CountDownLatch release) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, true, false, false, false, release);
        }

        static RecordingDp startHeldStaleObserved(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                java.util.concurrent.CountDownLatch release,
                java.util.concurrent.CountDownLatch arrived) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, true, false, false, false, release, arrived);
        }

        static RecordingDp startWithDelayedStaleThenOk(
                Path dpSock, Path keysDir, Path dpPubPath, Path cpPub) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, true, false, false, false, null);
        }

        static RecordingDp startWrongGeneration(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub)
                throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, false, true, false, null);
        }

        static RecordingDp startWrongCommitment(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub)
                throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, false, false, true, null);
        }

        static RecordingDp startLegacy(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub)
                throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, false, true, false, false, null);
        }

        private static RecordingDp start(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                boolean delayedStaleThenOk, boolean legacyResponse, boolean wrongGeneration,
                boolean wrongCommitment,
                java.util.concurrent.@org.jspecify.annotations.Nullable CountDownLatch hold) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, delayedStaleThenOk, legacyResponse,
                    wrongGeneration, wrongCommitment, hold, null);
        }

        private static RecordingDp start(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                boolean delayedStaleThenOk, boolean legacyResponse, boolean wrongGeneration,
                boolean wrongCommitment,
                java.util.concurrent.@org.jspecify.annotations.Nullable CountDownLatch hold,
                java.util.concurrent.@org.jspecify.annotations.Nullable CountDownLatch arrived) throws Exception {
            return start(dpSock, keysDir, dpPubPath, cpPub, delayedStaleThenOk, legacyResponse,
                    wrongGeneration, wrongCommitment, hold, arrived, null);
        }

        private static RecordingDp start(Path dpSock, Path keysDir, Path dpPubPath, Path cpPub,
                boolean delayedStaleThenOk, boolean legacyResponse, boolean wrongGeneration,
                boolean wrongCommitment,
                java.util.concurrent.@org.jspecify.annotations.Nullable CountDownLatch hold,
                java.util.concurrent.@org.jspecify.annotations.Nullable CountDownLatch arrived,
                @org.jspecify.annotations.Nullable UnavailableThenHeldRetry retryScript)
                throws Exception {
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
                                if (arrived != null) {
                                    arrived.countDown();
                                }
                                if (hold != null) {
                                    try {
                                        hold.await(20, TimeUnit.SECONDS);
                                    } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                    }
                                }
                                int attempt = attempts.incrementAndGet();
                                if (retryScript != null) {
                                    var seen = attempt == 1 ? retryScript.firstArrived() : retryScript.retryArrived();
                                    var release = attempt == 1
                                            ? retryScript.releaseFirstFailure()
                                            : retryScript.releaseRetryAck();
                                    seen.countDown();
                                    try {
                                        if (!release.await(20, TimeUnit.SECONDS)) {
                                            response.onError(io.grpc.Status.DEADLINE_EXCEEDED
                                                    .withDescription("bounded retry fixture was not released")
                                                    .asRuntimeException());
                                            return;
                                        }
                                    } catch (InterruptedException interrupted) {
                                        Thread.currentThread().interrupt();
                                        response.onError(io.grpc.Status.CANCELLED
                                                .withDescription("bounded retry fixture interrupted")
                                                .asRuntimeException());
                                        return;
                                    }
                                    if (attempt == 1) {
                                        response.onError(io.grpc.Status.UNAVAILABLE
                                                .withDescription("synthetic reconnect delivery failure")
                                                .asRuntimeException());
                                        return;
                                    }
                                }
                                var reply = ControlOuterClass.ReloadTokensResponse.newBuilder();
                                if (delayedStaleThenOk && attempt == 1) {
                                    reply.setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_STALE_GENERATION)
                                            .setCurrentGeneration(5);
                                } else if (legacyResponse) {
                                    reply.setAppliedGeneration(request.getGeneration())
                                            .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK);
                                } else {
                                    long acknowledgedGeneration = request.getGeneration() + (wrongGeneration ? 1 : 0);
                                    reply.setAppliedGeneration(acknowledgedGeneration)
                                            .setCurrentGeneration(acknowledgedGeneration)
                                            .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK);
                                    if (request.hasDurable()) {
                                        reply.setAcknowledgmentVersion(1)
                                                .setCommitment(wrongCommitment
                                                        ? com.google.protobuf.ByteString.copyFrom(
                                                                repeat((byte) 0x4b, 32))
                                                        : request.getDurable().getCommitment());
                                    }
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
            return new RecordingDp(server, boss, workers, captured, completed, arrived);
        }

        @Override
        public void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
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

    @Test
    void absentObserverDoesNotBlockControlPlaneBoot() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        RecordingState state = new RecordingState();
        RecordingAudit audit = new RecordingAudit();
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tmp.resolve("tokens.yaml"), keys, runDir().resolve("dp.sock")),
                audit, state, state)) {
            assertNotNull(handle, "observer absence is advisory");
            assertTrue(audit.rows.isEmpty(), "no fabricated Tor health audit row");
        }
    }

    @Test
    void monitorStartAuthenticatesObserverAndFeedsProductionAuditAdapter() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        KeyPair observer = ed25519();
        writePem(keys.resolve("observer.pub"), "PUBLIC KEY", observer.getPublic().getEncoded());
        writePem(tmp.resolve("observer.priv"), "PRIVATE KEY", observer.getPrivate().getEncoded());
        Files.copy(keys.resolve("cp.pub"), tmp.resolve("cp.pub"));

        Path goDir = Path.of("../../data-plane").toAbsolutePath().normalize();
        ProcessBuilder builder = new ProcessBuilder("go", "test", "./cmd/tor-observer",
                "-run", "^TestJavaClientInteropFixture$", "-count=1", "-timeout=30s");
        builder.directory(goDir.toFile());
        builder.environment().put("T164_INTEROP_DIR", tmp.toString());
        builder.redirectErrorStream(true);
        builder.redirectOutput(tmp.resolve("observer-go.log").toFile());
        Process fixture = builder.start();
        try {
            long readyDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
            while (!Files.exists(tmp.resolve("ready")) && fixture.isAlive()
                    && System.nanoTime() < readyDeadline) {
                Thread.sleep(10);
            }
            assertTrue(Files.exists(tmp.resolve("ready")),
                    "Go observer fixture started: " + Files.readString(tmp.resolve("observer-go.log")));
            RecordingState state = new RecordingState();
            state.lastGeneration = 7;
            RecordingAudit audit = new RecordingAudit();
            StargateControlPlane.BootConfig config = new StargateControlPlane.BootConfig(
                    tmp.resolve("tokens.yaml"), tmp.resolve("pepper.key"), keys,
                    runDir().resolve("control.sock"), runDir().resolve("dp.sock"),
                    tmp.resolve("health.sock"), Duration.ofMillis(50));
            try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                    config, audit, state, state)) {
                long eventDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while (audit.rows.isEmpty() && System.nanoTime() < eventDeadline) {
                    Thread.sleep(10);
                }
                assertEquals(1, audit.rows.size(), "production boot must start the health monitor");
                assertArrayEquals(new String[] {"sidecar_healthy", "tor", "{\"generation\":7}"},
                        audit.rows.get(0), "authenticated READY reaches the §4 audit adapter");
            }
            Files.write(tmp.resolve("stop"), new byte[0]);
            assertTrue(fixture.waitFor(5, TimeUnit.SECONDS), "Go observer fixture exited");
            assertEquals(0, fixture.exitValue(), Files.readString(tmp.resolve("observer-go.log")));
        } finally {
            fixture.destroyForcibly();
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
            assertEquals(0, request.getTokensCount(),
                    "legacy token list stays empty so an old DP sees revoke-all only");
            assertTrue(request.hasDurable(), "the mandatory auth-set-v1 envelope is present");
            assertEquals(1, request.getDurable().getSemanticsVersion());
            assertEquals(1L, request.getDurable().getGeneration());
            assertEquals(1, request.getDurable().getTokensCount());
            byte[] verifier = request.getDurable().getTokens(0).getVerifier().toByteArray();
            assertArrayEquals(referenceMint(TEST_PEPPER, EXAMPLE_HEX), verifier,
                    "the pushed verifier is HMAC-SHA-256(pepper, token) (§1.5)");
            assertFalse(Arrays.equals(TEST_PEPPER, verifier),
                    "the pepper NEVER crosses the wire (§1.6)");
            assertFalse(new String(verifier, StandardCharsets.US_ASCII).contains(EXAMPLE_HEX),
                    "the plaintext never crosses the wire (§1.6)");
        }
    }

    @Test
    void reloadClientMatchesPinnedAuthSetCommitmentVector() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-vector.sock");
        byte[] ascending = new byte[32];
        byte[] descending = new byte[32];
        for (int i = 0; i < 32; i++) {
            ascending[i] = (byte) i;
            descending[i] = (byte) (255 - i);
        }
        var tokens = List.of(descending, ascending, descending).stream()
                .map(bytes -> ControlOuterClass.TokenVerifier.newBuilder()
                        .setVerifier(com.google.protobuf.ByteString.copyFrom(bytes))
                        .build())
                .toList();
        try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"),
                        keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            client.reload(1L, tokens);
            assertEquals(1, dp.requests.size());
            assertArrayEquals(
                    HexFormat.of().parseHex("090dc7c7c4c28962f5ebe37fb34db11a67afffa98c8b5a1784587e1aa2f2c4c0"),
                    dp.requests.get(0).getDurable().getCommitment().toByteArray(),
                    "Java auth-set-v1 encoding must match the contract's independent duplicate/sort vector");
        }
    }

    @Test
    void pendingCandidateRedeliversWhenDataPlaneReturns() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-late.sock");
        try (ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, new RecordingState());
            byte[] verifier = repeat((byte) 0x2a, 32);
            TokenLoaderContract.PushResult pending = channel.push(3L, List.of(verifier));
            assertEquals(0L, pending.currentGeneration(), "initial absent-DP delivery is pending");

            try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"),
                    keys.resolve("cp.pub"))) {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (dp.requests.isEmpty() && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertEquals(1, dp.requests.size(),
                        "the current durable candidate is delivered when DP returns without restarting CP");
                assertEquals(3L, dp.requests.get(0).getGeneration());
                assertArrayEquals(verifier,
                        dp.requests.get(0).getDurable().getTokens(0).getVerifier().toByteArray());
            }
        }
    }

    @Test
    void runningControlPlaneReconcilesRestartedRealDataPlane() throws Exception {
        Path keys = keysDir();
        Files.write(keys.resolve("pepper.key"), TEST_PEPPER);
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: replacement\n    token: "
                + REPLACEMENT_HEX + "\n");
        Path dpSock = runDir().resolve("dp.sock");
        Path stateDir = Files.createDirectories(tmp.resolve("dp-state"));

        byte[] oldVerifier = referenceMint(TEST_PEPPER, EXAMPLE_HEX);
        byte[] oldCommitment = referenceSingleCommitment(oldVerifier);
        String snapshot = "{\"schemaVersion\":3,\"authSetVersion\":1,\"generation\":1,"
                + "\"commitment\":\"" + Base64.getEncoder().encodeToString(oldCommitment) + "\","
                + "\"loadedAt\":\"2026-09-24T00:00:00Z\",\"verifiers\":[{\"verifier\":\""
                + Base64.getEncoder().encodeToString(oldVerifier) + "\"}]}";
        Files.writeString(stateDir.resolve("dp-snapshot.json"), snapshot, StandardCharsets.US_ASCII);

        RecordingState authority = new RecordingState();
        authority.lastGeneration = 1L;
        authority.stored.add(new TokenLoaderContract.StoredToken("old", oldVerifier));
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tokens, keys, dpSock), new RecordingAudit(), authority, authority)) {
            assertEquals(List.of(2L), authority.recorded,
                    "the unavailable-DP revocation candidate is durably assigned once");

            Path goDir = Path.of("../../data-plane").toAbsolutePath().normalize();
            ProcessBuilder fixtureBuilder = new ProcessBuilder("go", "test", "./internal/controlclient",
                    "-run", "^TestJavaReloadInteropFixture$", "-count=1", "-timeout=30s")
                    .directory(goDir.toFile())
                    .redirectErrorStream(true)
                    .redirectOutput(tmp.resolve("dp-run.log").toFile());
            fixtureBuilder.environment().put("T159_JAVA_INTEROP_DIR", tmp.toString());
            Process dp = fixtureBuilder.start();
            try {
                long readyDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
                while (!Files.exists(tmp.resolve("ready")) && dp.isAlive()
                        && System.nanoTime() < readyDeadline) {
                    Thread.sleep(20);
                }
                assertTrue(Files.exists(tmp.resolve("ready")),
                        "real Go DP control server starts: " + Files.readString(tmp.resolve("dp-run.log")));
                byte[] replacement = referenceMint(TEST_PEPPER, REPLACEMENT_HEX);
                String replacementB64 = Base64.getEncoder().encodeToString(replacement);
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
                boolean reconciled = false;
                while (System.nanoTime() < deadline && dp.isAlive()) {
                    String current = Files.readString(stateDir.resolve("dp-snapshot.json"));
                    reconciled = current.contains("\"generation\":2")
                            && current.contains(replacementB64)
                            && !current.contains(Base64.getEncoder().encodeToString(oldVerifier));
                    if (reconciled) {
                        break;
                    }
                    Thread.sleep(50);
                }
                assertTrue(reconciled,
                        "running CP must replace the restarted real DP's stale generation without CP restart; "
                                + Files.readString(tmp.resolve("dp-run.log")));
            } finally {
                Files.write(tmp.resolve("stop"), new byte[0]);
                if (!dp.waitFor(5, TimeUnit.SECONDS)) {
                    dp.destroyForcibly();
                    dp.waitFor(5, TimeUnit.SECONDS);
                }
            }

            // After that exact authority was acknowledged, lose the DP cache
            // and restart only the DP. The running CP must retain and resend
            // generation 2 on the authenticated channel's reconnect edge.
            Files.deleteIfExists(tmp.resolve("ready"));
            Files.deleteIfExists(tmp.resolve("stop"));
            Files.delete(stateDir.resolve("dp-snapshot.json"));
            Process restarted = fixtureBuilder.start();
            try {
                long readyDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
                while (!Files.exists(tmp.resolve("ready")) && restarted.isAlive()
                        && System.nanoTime() < readyDeadline) {
                    Thread.sleep(20);
                }
                assertTrue(Files.exists(tmp.resolve("ready")),
                        "restarted Go DP control server starts: "
                                + Files.readString(tmp.resolve("dp-run.log")));
                String replacementB64 = Base64.getEncoder().encodeToString(
                        referenceMint(TEST_PEPPER, REPLACEMENT_HEX));
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
                boolean reconciled = false;
                while (System.nanoTime() < deadline && restarted.isAlive()) {
                    Path snapshotPath = stateDir.resolve("dp-snapshot.json");
                    if (Files.exists(snapshotPath)) {
                        String current = Files.readString(snapshotPath);
                        reconciled = current.contains("\"generation\":2")
                                && current.contains(replacementB64);
                    }
                    if (reconciled) {
                        break;
                    }
                    Thread.sleep(50);
                }
                assertTrue(reconciled,
                        "acknowledged authority must repopulate a restarted DP with lost state; "
                                + Files.readString(tmp.resolve("dp-run.log")));
            } finally {
                Files.write(tmp.resolve("stop"), new byte[0]);
                if (!restarted.waitFor(5, TimeUnit.SECONDS)) {
                    restarted.destroyForcibly();
                    restarted.waitFor(5, TimeUnit.SECONDS);
                }
            }
        }
    }

    @Test
    void localChannelRetirementDoesNotReplayButPeerRestartDoes() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-retirement.sock");
        RecordingDp initial = RecordingDp.start(
                dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
        try (ReloadTokensClient client = shortLivedReloadClient(
                keys, dpSock, Duration.ofMillis(500))) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, new RecordingState());
            try {
                TokenLoaderContract.PushResult result = channel.push(8L,
                        List.of(repeat((byte) 0x48, 32)));
                assertEquals(8L, result.currentGeneration());
                Thread.sleep(1_300);
                assertEquals(1, initial.requests.size(),
                        "scheduled client channel retirement must not replay current authority");
            }
            finally {
                initial.close();
            }

            Files.deleteIfExists(dpSock);
            // Keep the peer down through another client-side retirement. A
            // real outage already observed must remain pending across that
            // local epoch change.
            Thread.sleep(700);
            try (RecordingDp restarted = RecordingDp.start(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while (restarted.requests.isEmpty() && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertEquals(1, restarted.requests.size(),
                        "a real peer restart still replays the retained current authority");
                assertEquals(8L, restarted.requests.get(0).getGeneration());
            }
        }
    }

    private static byte[] referenceSingleCommitment(byte[] verifier) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("stargate-auth-set-v1".getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) 0);
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(1L).array());
        digest.update(verifier);
        return digest.digest();
    }

    @Test
    void staleAuthorityIsNotRenumberedOrRetried() throws Exception {
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
            assertEquals(List.of(1L),
                    dp.requests.stream().map(ControlOuterClass.ReloadTokensRequest::getGeneration).toList(),
                    "rejected content is never relabelled at current_generation + 1");
            assertEquals(List.of(1L), dp.completedGenerations);
            assertEquals(List.of(1L), state.recorded,
                    "the pending candidate retains its originally assigned generation");
        }
    }

    // --- T187: finite current delivery state; counts only after exact ack --------

    /**
     * T187 acceptance 3 (Constitution II failure table): with the DP
     * unreachable the revocation is reported PENDING and not counted. When
     * the DP returns while this CP runs, the exact acknowledgement turns the
     * status into ACKNOWLEDGED(2) and the revocation is counted once.
     */
    @Test
    void unreachableDataPlaneReportsPendingAndCountsOnlyAfterAcknowledgement() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp-late-revocation.sock");
        RecordingState state = laptopAndPhoneAtGeneration1();
        RecordingAudit audit = new RecordingAudit();
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tokens, keys, dpSock), audit, state, state)) {
            assertNotNull(handle);
            assertEquals(List.of("phone"), state.deletes, "the candidate itself is durable");
            assertEquals("PENDING\n", readDeliveryStatus(),
                    "an undelivered revocation is reported pending, not success");
            assertEquals(0, rowCount(audit, "revoked"), "a pending revocation is never counted");

            try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"),
                    keys.resolve("cp.pub"))) {
                assertEquals("ACKNOWLEDGED(2)\n", awaitDeliveryStatus("ACKNOWLEDGED(2)\n"),
                        "the exact redelivered acknowledgement is reported with its generation");
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (rowCount(audit, "revoked") == 0 && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertEquals(1, rowCount(audit, "revoked"), "the acknowledged revocation counts once");
                assertEquals(0, rowCount(audit, "enrolled"));
            }
        }
    }

    @Test
    void staleReplyOnRetryWorkerPersistsConflictAndStopsFurtherDispatch() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-late-stale.sock");
        RecordingState state = new RecordingState();
        try (ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            TokenLoaderContract.PushResult initial = channel.push(4L, List.of(repeat((byte) 0x2a, 32)));
            assertFalse(initial.stale());
            assertEquals(0L, initial.currentGeneration());
            assertEquals("PENDING\n", readDeliveryStatus());
            try (RecordingDp dp = RecordingDp.startWithDelayedStaleThenOk(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
                assertEquals("STALE_CONFLICT\n", awaitDeliveryStatus("STALE_CONFLICT\n"),
                        "the retry worker records a stale refusal");
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.STALE, 4), state.deliveryMarker());
                Thread.sleep(250);
                assertEquals(1, dp.requests.size(), "the retry worker stops after stale persistence");
            }
        }
    }

    @Test
    void staleReplyOnAuthenticatedReconnectPersistsConflictAndStopsReplay() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-reconnect-stale.sock");
        RecordingState state = new RecordingState();
        try (RecordingDp first = RecordingDp.start(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            TokenLoaderContract.PushResult acknowledged = channel.push(4L, List.of(repeat((byte) 0x2a, 32)));
            assertEquals(4L, acknowledged.currentGeneration());
            assertEquals(1, first.requests.size(), "the initial DP accepted and acknowledged the candidate");
            assertEquals("ACKNOWLEDGED(4)\n", readDeliveryStatus());
            first.close();
            try (RecordingDp restarted = RecordingDp.startWithDelayedStaleThenOk(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
                assertEquals("STALE_CONFLICT\n", awaitDeliveryStatus("STALE_CONFLICT\n"),
                        "an authenticated peer reconnect that refuses retained authority becomes terminal");
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.STALE, 4), state.deliveryMarker());
                Thread.sleep(250);
                assertEquals(1, restarted.requests.size(), "a reconnect stale reply is never replayed again");
            }
        }
    }

    @Test
    void authenticatedReconnectPublishesPendingWhenStaleMarkerWriteFails() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-reconnect-stale-write-failure.sock");
        RecordingState state = new RecordingState();
        var release = new java.util.concurrent.CountDownLatch(1);
        try (RecordingDp first = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            assertEquals(4L, channel.push(4L, List.of(repeat((byte) 0x2a, 32))).currentGeneration());
            assertEquals("ACKNOWLEDGED(4)\n", readDeliveryStatus());
            first.close();
            state.staleFailure = new IllegalStateException("injected stale persistence failure");
            state.staleAttemptFinished = new java.util.concurrent.CountDownLatch(1);
            try (RecordingDp restarted = RecordingDp.startHeldStale(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"), release)) {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
                while (restarted.requests.isEmpty() && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertEquals(1, restarted.requests.size(), "the authenticated reconnect replay is held by the real RPC");
                String heldStatus = awaitDeliveryStatus("PENDING\n", Duration.ofSeconds(3));
                StatusCommandResult held = statusCommandForFile(deliveryStatus());
                release.countDown();
                boolean staleWriteAttempted = state.staleAttemptFinished.await(5, TimeUnit.SECONDS);
                String terminal = readDeliveryStatus();
                StatusCommandResult terminalStatus = statusCommandForFile(deliveryStatus());
                int requestsAfterStale = restarted.requests.size();
                TokenLoaderContract.PushResult stoppedPush = channel.push(4L,
                        List.of(repeat((byte) 0x2a, 32)));
                client.close();
                TokenLoaderContract.PushResult restartedPush;
                String restartedStatus;
                StatusCommandResult restartedStatusCommand;
                int requestsBeforeFreshPush;
                int requestsAfterFreshPush;
                try (ReloadTokensClient freshClient = ReloadTokensClient.create(keys, dpSock)) {
                    GrpcReloadChannel freshChannel = new GrpcReloadChannel(freshClient, state, deliveryStatus());
                    requestsBeforeFreshPush = restarted.requests.size();
                    restartedPush = freshChannel.push(4L, List.of(repeat((byte) 0x2a, 32)));
                    requestsAfterFreshPush = restarted.requests.size();
                    restartedStatus = readDeliveryStatus();
                    restartedStatusCommand = statusCommandForFile(deliveryStatus());
                }
                assertAll("stale persistence failure remains unresolved through channel restart",
                        () -> assertEquals("PENDING\n", heldStatus,
                                "the old ACK is withdrawn while replay remains outstanding"),
                        () -> assertEquals(30, held.exitCode(), held.output()),
                        () -> assertTrue(held.output().contains("PENDING"), held.output()),
                        () -> assertTrue(staleWriteAttempted, "the actual stale persistence callback completed"),
                        () -> assertEquals(1, state.staleAttempts.get()),
                        () -> assertEquals("PENDING\n", terminal,
                                "a failed stale write retains unresolved status"),
                        () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 4),
                                state.deliveryMarker()),
                        () -> assertEquals(30, terminalStatus.exitCode(), terminalStatus.output()),
                        () -> assertTrue(terminalStatus.output().contains("PENDING"), terminalStatus.output()),
                        () -> assertEquals(1, requestsAfterStale, "stale authority is not replayed again"),
                        () -> assertEquals(0L, stoppedPush.currentGeneration()),
                        () -> assertEquals(0L, restartedPush.currentGeneration()),
                        () -> assertEquals(requestsBeforeFreshPush, requestsAfterFreshPush,
                                "a fresh channel cannot dispatch while the durable marker is UNRESOLVED"),
                        () -> assertEquals("PENDING\n", restartedStatus),
                        () -> assertEquals(30, restartedStatusCommand.exitCode(), restartedStatusCommand.output()));
            }
        } finally {
            release.countDown();
        }
    }

    @Test
    void authenticatedReconnectPublishesPendingWhenAckClearFails() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-reconnect-ack-clear-failure.sock");
        RecordingState state = new RecordingState();
        var release = new java.util.concurrent.CountDownLatch(1);
        try (RecordingDp first = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            assertEquals(4L, channel.push(4L, List.of(repeat((byte) 0x2a, 32))).currentGeneration());
            assertEquals("ACKNOWLEDGED(4)\n", readDeliveryStatus());
            first.close();
            state.acknowledgementFailure = new IllegalStateException("injected ACK-clear failure");
            state.acknowledgementAttemptFinished = new java.util.concurrent.CountDownLatch(1);
            try (RecordingDp restarted = RecordingDp.startHeld(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"), release)) {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
                while (restarted.requests.isEmpty() && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertEquals(1, restarted.requests.size(), "the authenticated reconnect replay is held by the real RPC");
                String heldStatus = awaitDeliveryStatus("PENDING\n", Duration.ofSeconds(3));
                StatusCommandResult held = statusCommandForFile(deliveryStatus());
                release.countDown();
                boolean acknowledgementAttempted = state.acknowledgementAttemptFinished.await(5, TimeUnit.SECONDS);
                String terminal = readDeliveryStatus();
                StatusCommandResult terminalStatus = statusCommandForFile(deliveryStatus());
                int acknowledgementAttempts = state.acknowledgementAttempts.get();
                client.close();
                RequestCensus settledRequests = awaitStableRequestCount(restarted.requests);
                TokenLoaderContract.PushResult restartedPush;
                String restartedStatus;
                StatusCommandResult restartedStatusCommand;
                int requestsBeforeFreshPush;
                int requestsAfterFreshPush;
                try (ReloadTokensClient freshClient = ReloadTokensClient.create(keys, dpSock)) {
                    GrpcReloadChannel freshChannel = new GrpcReloadChannel(freshClient, state, deliveryStatus());
                    requestsBeforeFreshPush = settledRequests.count();
                    restartedPush = freshChannel.push(4L, List.of(repeat((byte) 0x2a, 32)));
                    requestsAfterFreshPush = restarted.requests.size();
                    restartedStatus = readDeliveryStatus();
                    restartedStatusCommand = statusCommandForFile(deliveryStatus());
                }
                assertAll("failed ACK clearing retains the restart barrier through channel restart",
                        () -> assertEquals("PENDING\n", heldStatus,
                                "the old ACK is withdrawn while replay remains outstanding"),
                        () -> assertEquals(30, held.exitCode(), held.output()),
                        () -> assertTrue(held.output().contains("PENDING"), held.output()),
                        () -> assertTrue(acknowledgementAttempted,
                                "the actual ACK-clear persistence callback completed"),
                        () -> assertTrue(acknowledgementAttempts >= 2,
                                "initial and reconnect ACK-clear attempts are observed"),
                        () -> assertEquals("PENDING\n", terminal,
                                "a failed ACK clear retains unresolved status"),
                        () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 4),
                                state.deliveryMarker()),
                        () -> assertEquals(30, terminalStatus.exitCode(), terminalStatus.output()),
                        () -> assertTrue(terminalStatus.output().contains("PENDING"), terminalStatus.output()),
                        () -> assertTrue(settledRequests.settled(),
                                "the closed same-process retry worker is quiescent before fresh-channel observation"),
                        () -> assertEquals(0L, restartedPush.currentGeneration()),
                        () -> assertEquals(requestsBeforeFreshPush, requestsAfterFreshPush,
                                "a fresh channel cannot dispatch while the durable marker is UNRESOLVED"),
                        () -> assertEquals("PENDING\n", restartedStatus),
                        () -> assertEquals(30, restartedStatusCommand.exitCode(), restartedStatusCommand.output()));
            }
        } finally {
            release.countDown();
        }
    }

    @Test
    void authenticatedReconnectWithdrawsAcknowledgedBeforePrearmFailure() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-reconnect-prearm-failure.sock");
        RecordingState state = new RecordingState();
        try (RecordingDp first = RecordingDp.start(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            assertEquals(4L, channel.push(4L, List.of(repeat((byte) 0x2a, 32))).currentGeneration());
            assertEquals("ACKNOWLEDGED(4)\n", readDeliveryStatus());

            var prearmFinished = new java.util.concurrent.CountDownLatch(1);
            state.prearmFailure = new IllegalStateException("injected reconnect prearm failure");
            state.prearmAttemptFinished = prearmFinished;
            first.close();
            try (RecordingDp restarted = RecordingDp.start(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
                String pending = awaitDeliveryStatus("PENDING\n", Duration.ofSeconds(3));
                boolean failedPrearmObserved = prearmFinished.await(5, TimeUnit.SECONDS);
                StatusCommandResult pendingCommand = statusCommandForFile(deliveryStatus());
                int requestsBeforeStorageRecovery = restarted.requests.size();
                int attemptsBeforeStorageRecovery = state.prearmAttempts.get();
                state.prearmFailure = null;
                state.prearmAttemptFinished = null;

                long recoveryDeadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
                while (restarted.requests.isEmpty() && System.nanoTime() < recoveryDeadline) {
                    Thread.sleep(20);
                }
                String acknowledged = awaitDeliveryStatus("ACKNOWLEDGED(4)\n", Duration.ofSeconds(10));
                StatusCommandResult acknowledgedCommand = statusCommandForFile(deliveryStatus());
                var markerAfterAck = state.deliveryMarker();
                assertAll("reconnect prearm failure withdraws the old success claim and remains fail-closed",
                        () -> assertEquals("PENDING\n", pending,
                                "authenticated reconnect publishes PENDING before its fallible SQLite prearm"),
                        () -> assertTrue(failedPrearmObserved,
                                "the injected reconnect prearm failure was observed"),
                        () -> assertTrue(attemptsBeforeStorageRecovery >= 2,
                                "initial push and at least one reconnect prearm are observed"),
                        () -> assertEquals(0, requestsBeforeStorageRecovery,
                                "failed prearming dispatches no reconnect RPC"),
                        () -> assertEquals(30, pendingCommand.exitCode(), pendingCommand.output()),
                        () -> assertTrue(pendingCommand.output().contains("PENDING"), pendingCommand.output()),
                        () -> assertEquals("ACKNOWLEDGED(4)\n", acknowledged),
                        () -> assertEquals(1, restarted.requests.size(),
                                "restored storage allows exactly one authenticated replay"),
                        () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), markerAfterAck,
                                "the exact replay ACK commits durable clear"),
                        () -> assertEquals(0, acknowledgedCommand.exitCode(), acknowledgedCommand.output()),
                        () -> assertTrue(acknowledgedCommand.output().contains("ACKNOWLEDGED(4)"),
                                acknowledgedCommand.output()));
            }
        }
    }

    /** T187 acceptance 3: a stale reply is STALE_CONFLICT and never counted. */
    @Test
    void staleReplyReportsStaleConflictAndNeverCountsRevocation() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp.sock");
        RecordingState state = laptopAndPhoneAtGeneration1();
        RecordingAudit audit = new RecordingAudit();
        try (RecordingDp dp = RecordingDp.startWithDelayedStaleThenOk(
                        dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                        cfg(tokens, keys, dpSock), audit, state, state)) {
            assertNotNull(handle);
            assertEquals("STALE_CONFLICT\n", readDeliveryStatus(),
                    "a refused stale candidate is a conflict, not success and not pending");
            Thread.sleep(500);
            assertEquals(1, dp.requests.size(), "the stale candidate is not retried");
            assertEquals("STALE_CONFLICT\n", readDeliveryStatus());
            assertEquals(0, rowCount(audit, "revoked"), "a stale-refused revocation is never counted");
        }
    }

    /** T187 acceptance 3: an exact acknowledgement is ACKNOWLEDGED(gen) and counts once. */
    @Test
    void acknowledgedRevocationReportsGenerationAndCountsOnce() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp.sock");
        RecordingState state = laptopAndPhoneAtGeneration1();
        RecordingAudit audit = new RecordingAudit();
        try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"),
                        keys.resolve("cp.pub"));
                StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                        cfg(tokens, keys, dpSock), audit, state, state)) {
            assertNotNull(handle);
            assertEquals("ACKNOWLEDGED(2)\n", readDeliveryStatus());
            assertEquals(1, rowCount(audit, "revoked"));
            assertEquals(0, rowCount(audit, "enrolled"));
        }
    }

    /**
     * T187 / Constitution III: the status is current state only. A boot
     * clears any earlier value and publishes nothing until it delivers.
     */
    @Test
    void bootClearsEarlierStatusAndPublishesNothingWithoutDelivery() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Files.createDirectories(deliveryStatus().getParent());
        Files.writeString(deliveryStatus(), "ACKNOWLEDGED(9)\n");
        RecordingState state = new RecordingState();
        try (StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                cfg(tmp.resolve("tokens.yaml"), keys, runDir().resolve("dp.sock")),
                new RecordingAudit(), state, state)) {
            assertNotNull(handle);
            assertEquals(null, readDeliveryStatus(), "no earlier state survives into this boot");
        }
    }

    /**
     * T187 review r1 (astra Major 1): a delivery whose initial RPC is still
     * outstanding is already PENDING — the status is never absent (which the
     * operator surface reads as "no delivery state published") while a
     * revocation is in flight.
     */
    @Test
    void pendingIsPublishedWhileInitialDeliveryIsOutstanding() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp-held.sock");
        RecordingState state = laptopAndPhoneAtGeneration1();
        RecordingAudit audit = new RecordingAudit();
        var release = new java.util.concurrent.CountDownLatch(1);
        var boot = java.util.concurrent.Executors.newSingleThreadExecutor();
        try (RecordingDp dp = RecordingDp.startHeld(dpSock, keys, keys.resolve("dp.pub"),
                keys.resolve("cp.pub"), release)) {
            var booted = boot.submit(() -> StargateControlPlane.bootstrap(
                    cfg(tokens, keys, dpSock), audit, state, state));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            while (dp.requests.isEmpty() && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertEquals(1, dp.requests.size(), "the initial ReloadTokens is outstanding at the DP");
            // Well inside the client's 10 s RPC deadline: the RPC is still outstanding.
            assertEquals("PENDING\n", awaitDeliveryStatus("PENDING\n", Duration.ofSeconds(3)),
                    "an outstanding delivery is reported PENDING, never as absent state");
            assertEquals(0, rowCount(audit, "revoked"));
            release.countDown();
            try (StargateControlPlane.BootHandle handle = booted.get(20, TimeUnit.SECONDS)) {
                assertEquals("ACKNOWLEDGED(2)\n", awaitDeliveryStatus("ACKNOWLEDGED(2)\n"));
                assertEquals(1, rowCount(audit, "revoked"));
            }
        } finally {
            release.countDown();
            boot.shutdownNow();
        }
    }

    /**
     * T187 review r1 (astra Major 2): if replacing the status fails, the
     * previous value must not survive as the current state. The obsolete
     * PENDING is withdrawn and the terminal outcome is published once the
     * status can be written again, without resending stale authority.
     */
    @Test
    void failedStatusWriteNeverLeavesObsoleteState() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-publish-failure.sock");
        Path status = deliveryStatus();
        Path obstacle = status.resolveSibling(status.getFileName() + ".tmp").resolve("obstacle");
        try (ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, new RecordingState(), status);
            channel.push(2L, List.of(repeat((byte) 0x2a, 32)));
            assertEquals("PENDING\n", readDeliveryStatus(), "absent DP: delivery is pending");

            Files.createDirectories(obstacle); // the next replacement write cannot create its sibling
            try (RecordingDp dp = RecordingDp.startWithDelayedStaleThenOk(dpSock, keys,
                    keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (Files.exists(status) && System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                assertEquals(null, readDeliveryStatus(),
                        "a failed STALE_CONFLICT write must withdraw the obsolete PENDING");
                Files.delete(obstacle);
                Files.delete(obstacle.getParent());
                assertEquals("STALE_CONFLICT\n", awaitDeliveryStatus("STALE_CONFLICT\n"),
                        "the terminal state is published once the status is writable again");
                assertEquals(1, dp.requests.size(), "stale authority is never resent");
            }
        }
    }

    @Test
    void failedPrearmWriteNeverDispatchesRpc() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-prearm-failure.sock");
        RecordingState state = new RecordingState();
        state.prearmFailure = new IllegalStateException("injected prearm failure");
        try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            TokenLoaderContract.PushResult result = channel.push(1L, List.of(repeat((byte) 0x2a, 32)));
            assertFalse(result.stale());
            assertEquals(0L, result.currentGeneration(), "a failed prearm is pending, not acknowledged");
            Thread.sleep(250);
            assertTrue(dp.requests.isEmpty(), "no initial or retry RPC crosses a failed durable prearm");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker());
        }
    }

    @Test
    void failedAckClearKeepsDurableBarrierAcrossChannelRestart() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-ack-clear-failure.sock");
        RecordingState state = new RecordingState();
        state.acknowledgementFailure = new IllegalStateException("injected ACK-clear failure");
        try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
            ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock);
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            TokenLoaderContract.PushResult result = channel.push(1L, List.of(repeat((byte) 0x2a, 32)));
            assertFalse(result.stale());
            assertEquals(0L, result.currentGeneration(), "an ACK without durable local clear is not completion");
            assertEquals("PENDING\n", readDeliveryStatus());
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 1), state.deliveryMarker());
            client.close();
            int delivered = dp.requests.size();

            try (ReloadTokensClient restartedClient = ReloadTokensClient.create(keys, dpSock)) {
                GrpcReloadChannel restarted = new GrpcReloadChannel(restartedClient, state, deliveryStatus());
                TokenLoaderContract.PushResult blocked = restarted.push(1L, List.of(repeat((byte) 0x2a, 32)));
                assertFalse(blocked.stale());
                assertEquals(0L, blocked.currentGeneration());
                assertEquals(delivered, dp.requests.size(), "a restarted channel cannot replay unresolved authority");
                assertEquals("PENDING\n", readDeliveryStatus());
            }
        }
    }

    @Test
    void failedStaleWriteKeepsUnresolvedBarrierAcrossChannelRestart() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-stale-write-failure.sock");
        RecordingState state = new RecordingState();
        state.staleFailure = new IllegalStateException("injected stale persistence failure");
        int delivered;
        try (RecordingDp dp = RecordingDp.startWithDelayedStaleThenOk(
                        dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))) {
            ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock);
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
            TokenLoaderContract.PushResult result = channel.push(1L, List.of(repeat((byte) 0x2a, 32)));
            assertTrue(result.stale(), "the data plane's stale refusal remains visible to this call");
            assertEquals("PENDING\n", readDeliveryStatus(),
                    "failed stale persistence leaves the earlier unresolved status truthful");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 1), state.deliveryMarker());
            assertEquals(0L, channel.push(1L, List.of(repeat((byte) 0x2a, 32))).currentGeneration(),
                    "the stale latch refuses this channel's later push even though the fixture would next ACK");
            assertEquals(1, dp.requests.size(), "a later exact ACK cannot be solicited after stale refusal");
            client.close();
            delivered = dp.requests.size();
        }
        // The DP is now absent: the persisted UNRESOLVED marker still blocks a
        // fresh channel before it can probe or repopulate lost peer state.
        try (ReloadTokensClient restartedClient = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel restarted = new GrpcReloadChannel(restartedClient, state, deliveryStatus());
            assertEquals(0L, restarted.push(1L, List.of(repeat((byte) 0x2a, 32))).currentGeneration());
            assertEquals(delivered, 1, "the original stale refusal was the only request before DP loss");
            assertEquals("PENDING\n", readDeliveryStatus());
        }
    }

    @Test
    void nonExactAcknowledgementsLeaveDeliveryUnresolved() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-nonexact-ack.sock");
        RecordingState state = new RecordingState();
        List<java.util.function.Supplier<RecordingDp>> variants = List.of(
                () -> uncheckedRecordingDp(() -> RecordingDp.startLegacy(
                        dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))),
                () -> uncheckedRecordingDp(() -> RecordingDp.startWrongGeneration(
                        dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))),
                () -> uncheckedRecordingDp(() -> RecordingDp.startWrongCommitment(
                        dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"))));
        for (java.util.function.Supplier<RecordingDp> variant : variants) {
            state.delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0);
            try (RecordingDp dp = variant.get();
                    ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
                GrpcReloadChannel channel = new GrpcReloadChannel(client, state, deliveryStatus());
                TokenLoaderContract.PushResult result = channel.push(3L, List.of(repeat((byte) 0x2a, 32)));
                client.close();
                assertEquals(0L, result.currentGeneration(), "legacy and mismatched ACKs remain pending");
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 3), state.deliveryMarker());
                assertEquals(1, dp.requests.size());
                try (ReloadTokensClient restartedClient = ReloadTokensClient.create(keys, dpSock)) {
                    GrpcReloadChannel restarted = new GrpcReloadChannel(
                            restartedClient, state, deliveryStatus());
                    assertEquals(0L, restarted.push(3L, List.of(repeat((byte) 0x2a, 32))).currentGeneration());
                    assertEquals(1, dp.requests.size(),
                            "legacy, wrong-generation, and wrong-commitment replies cannot clear restart inhibition");
                    assertEquals("PENDING\n", readDeliveryStatus());
                }
            }
        }
    }

    private static RecordingDp uncheckedRecordingDp(CheckedRecordingDpSupplier supplier) {
        try {
            return supplier.get();
        } catch (Exception e) {
            throw new IllegalStateException("test DP fixture failed to start", e);
        }
    }

    @FunctionalInterface
    private interface CheckedRecordingDpSupplier {
        RecordingDp get() throws Exception;
    }

    /**
     * T187 review r1: the operator command prints only validated vocabulary
     * and never turns an unreadable state into a claim. Docker is a local
     * stub; the real dispatcher and subcommand run.
     */
    @Test
    void statusCommandPrintsValidatedStatesAndRefusesUnreadableState() throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (repo != null && !Files.isRegularFile(repo.resolve("scripts/stargate"))) {
            repo = repo.getParent();
        }
        assertNotNull(repo, "repository root with scripts/stargate");
        Path bin = Files.createDirectories(tmp.resolve("stub-bin"));
        Path docker = bin.resolve("docker");
        Files.writeString(docker, """
                #!/bin/sh
                case "$1" in
                  info) exit 0 ;;
                  compose)
                    case "$*" in
                      *" version"*) exit 0 ;;
                      *" ps "*) [ "$STUB_CP" = down ] || echo 0123abcd; exit 0 ;;
                      *" exec "*)
                        [ "$STUB_EXEC" = fail ] && exit 126
                        printf '%s\\n' "$STUB_EXEC"; exit 0 ;;
                    esac ;;
                esac
                exit 0
                """);
        docker.toFile().setExecutable(true);
        record Case(String cp, String exec, int exit, String shows) { }
        List<Case> cases = List.of(
                new Case("up", "ACKNOWLEDGED(7)", 0, "ACKNOWLEDGED(7)"),
                new Case("up", "PENDING", 30, "PENDING"),
                new Case("up", "STALE_CONFLICT", 40, "STALE_CONFLICT"),
                new Case("up", "ABSENT", 50, "UNKNOWN"),
                new Case("up", "UNKNOWN", 50, "UNKNOWN"),
                new Case("up", "fail", 20, "unavailable"),
                new Case("down", "PENDING", 20, "not running"),
                new Case("up", "PENDING leaked-label", 60, "unrecognised"));
        for (Case c : cases) {
            var pb = new ProcessBuilder("/bin/bash", repo.resolve("scripts/stargate").toString(), "status")
                    .redirectErrorStream(true);
            pb.environment().put("PATH", bin + ":/usr/bin:/bin");
            pb.environment().put("STUB_CP", c.cp());
            pb.environment().put("STUB_EXEC", c.exec());
            pb.environment().put("STARGATE_ENV_FILE", tmp.resolve("local.env").toString());
            pb.environment().put("STARGATE_ENV_EXAMPLE", tmp.resolve("absent.env.example").toString());
            Process process = pb.start();
            String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(process.waitFor(30, TimeUnit.SECONDS));
            assertEquals(c.exit(), process.exitValue(), c + " -> " + out);
            assertTrue(out.contains(c.shows()), c + " -> " + out);
            assertFalse(out.contains("no delivery attempted"), "never claims an unestablished lifecycle: " + out);
            assertFalse(out.contains("leaked-label"), "raw status content is never echoed: " + out);
            if (c.exec().equals("ABSENT")) {
                assertTrue(out.contains("no delivery state published"),
                        "the absent-file sentinel remains distinct from published UNKNOWN: " + out);
            }
            if (c.exec().equals("UNKNOWN")) {
                assertTrue(out.contains("delivery outcome cannot be established"),
                        "published UNKNOWN reports only uncertainty: " + out);
                assertFalse(out.contains("no delivery state published"),
                        "published UNKNOWN is not described as an absent file: " + out);
                assertFalse(out.contains("installed"),
                        "published UNKNOWN makes no data-plane installation claim: " + out);
            }
            if (c.cp().equals("up") && c.exec().equals("PENDING")) {
                assertTrue(out.contains("token delivery: PENDING (delivery is unresolved; credential application and revocation are not confirmed)"),
                        "PENDING reports uncertainty rather than inferring the DP outcome: " + out);
                assertFalse(out.contains("revocations are NOT effective yet"),
                        "a lost ACK does not establish that the DP failed to apply credentials: " + out);
            }
            if (c.cp().equals("down")) {
                assertTrue(out.contains("control plane: not running (token delivery state unavailable; the data plane routes using its existing valid credential state)"),
                        "CP-down output makes no unsupported last-acknowledged claim: " + out);
                assertFalse(out.contains("last acknowledged state"),
                        "the DP may have installed a set whose ACK was lost: " + out);
            }
        }
    }

    @Test
    void productionBootstrapPublishesUnknownWhenDeliveryMarkerCannotBeRead() throws Exception {
        Path keys = keysDir();
        pepperFile(TEST_PEPPER);
        Path tokens = tokensFile("tokens:\n  - label: laptop\n    token: " + EXAMPLE_HEX + "\n");
        Path dpSock = runDir().resolve("dp-marker-unavailable.sock");
        RecordingState state = new RecordingState();
        state.deliveryFailure = new IllegalStateException("injected delivery marker read failure");
        RecordingAudit audit = new RecordingAudit();

        try (RecordingDp dp = RecordingDp.start(dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                StargateControlPlane.BootHandle handle = StargateControlPlane.bootstrap(
                        cfg(tokens, keys, dpSock), audit, state, state)) {
            assertNotNull(handle, "a delivery marker read failure does not prevent CP startup");
            assertEquals("UNKNOWN\n", awaitDeliveryStatus("UNKNOWN\n"),
                    "the production channel publishes uncertainty while the status path is writable");

            StatusCommandResult result = statusCommandForFile(deliveryStatus());
            assertAll("published UNKNOWN remains truthful through the real status command",
                    () -> assertEquals(50, result.exitCode(), result.output()),
                    () -> assertTrue(result.output().contains("delivery outcome cannot be established"), result.output()),
                    () -> assertFalse(result.output().contains("no delivery state published"), result.output()),
                    () -> assertFalse(result.output().contains("installed"), result.output()),
                    () -> assertTrue(state.upserts.isEmpty(), "no token rows are inserted"),
                    () -> assertTrue(state.deletes.isEmpty(), "no token rows are deleted"),
                    () -> assertTrue(state.recorded.isEmpty(), "no generation is recorded"),
                    () -> assertEquals(0, rowCount(audit, "enrolled")),
                    () -> assertEquals(0, rowCount(audit, "revoked")),
                    () -> assertTrue(dp.requests.isEmpty(), "no delivery RPC reaches the data plane"));
        }
    }

    /**
     * T193: a Docker daemon that stops answering must not hang the operator's
     * {@code stargate status}. Each docker call it makes (compose version,
     * info, compose ps, compose exec) is stubbed to hang, with GNU coreutils
     * {@code timeout} on PATH, without it, and with a non-GNU one (both the
     * portable watchdog), and with the hung process tree obeying SIGTERM,
     * ignoring it, or mixed (the direct child obeys while a background
     * descendant ignores it); the bound must not rely on a cooperative child.
     * The hung stub also leaves a background descendant holding its stdout,
     * and the exec stub prints {@code ACKNOWLEDGED(7)} before hanging. Each
     * run must end within the bound plus the kill grace with exit 70 and the
     * static message, claim no state, and leave none of the stub's processes
     * alive. An exec whose direct child prints {@code ACKNOWLEDGED(7)} and
     * fails at once, leaving a TERM-ignoring descendant holding its stdout,
     * must end promptly as "state unavailable" (exit 20) with no survivor. Output goes to a file, so the wait below is the only bound. An
     * invalid bound is refused.
     * Every case runs; failures are reported together.
     */
    @Test
    void statusCommandBoundsAHangingDockerCall() throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (repo != null && !Files.isRegularFile(repo.resolve("scripts/stargate"))) {
            repo = repo.getParent();
        }
        assertNotNull(repo, "repository root with scripts/stargate");
        Path timeoutTool = Path.of("/usr/bin/timeout");
        assertTrue(Files.isExecutable(timeoutTool), "coreutils timeout is needed to cover its branch");
        Path stub = Files.createDirectories(tmp.resolve("hang-stub")).resolve("docker");
        Files.writeString(stub, """
                #!/bin/sh
                hang() {
                  [ "$STUB_TERM" = ignore ] && trap '' TERM
                  [ "$1" = exec ] && echo 'ACKNOWLEDGED(7)'
                  if [ "$STUB_TERM" = mixed ]; then
                    (trap '' TERM; exec sleep 30) &
                  else
                    sleep 30 &
                  fi
                  echo "$!" >> "$STUB_PIDS"
                  echo "$$" >> "$STUB_PIDS"
                  exec sleep 30
                }
                # Direct child fails at once, leaving a TERM-ignoring
                # descendant that holds its stdout.
                early() {
                  echo 'ACKNOWLEDGED(7)'
                  (trap '' TERM; exec sleep 30) &
                  echo "$!" >> "$STUB_PIDS"
                  exit 1
                }
                case "$1" in
                  info) [ "$STUB_HANG" = info ] && hang info; exit 0 ;;
                  compose)
                    case "$*" in
                      *" version"*) [ "$STUB_HANG" = version ] && hang version; exit 0 ;;
                      *" ps "*) [ "$STUB_HANG" = ps ] && hang ps; echo 0123abcd; exit 0 ;;
                      *" exec "*)
                        [ "$STUB_HANG" = exec ] && hang exec
                        [ "$STUB_HANG" = exec-early ] && early
                        echo PENDING; exit 0 ;;
                    esac ;;
                esac
                exit 0
                """);
        stub.toFile().setExecutable(true);
        // The portable PATH has no `timeout`: only the stub and what the
        // watchdog and stub need.
        Path bare = Files.createDirectories(tmp.resolve("hang-bare"));
        Files.createSymbolicLink(bare.resolve("docker"), stub);
        for (String tool : List.of("bash", "sleep")) {
            Path real = Path.of("/usr/bin", tool);
            Files.createSymbolicLink(bare.resolve(tool), Files.isExecutable(real) ? real : Path.of("/bin", tool));
        }
        // A non-GNU `timeout` (busybox-like; this one does not bound at all)
        // must not be trusted: the watchdog has to bound the call instead.
        Path otherTimeout = Files.createDirectories(tmp.resolve("hang-other-timeout"));
        for (Path entry : List.of(bare.resolve("docker"), bare.resolve("bash"), bare.resolve("sleep"))) {
            Files.createSymbolicLink(otherTimeout.resolve(entry.getFileName()), Files.readSymbolicLink(entry));
        }
        Path fakeTimeout = otherTimeout.resolve("timeout");
        Files.writeString(fakeTimeout, """
                #!/bin/sh
                [ "$1" = --version ] && { echo 'timeout (BusyBox-like, child-only)'; exit 0; }
                shift
                exec "$@"
                """);
        fakeTimeout.toFile().setExecutable(true);
        String withTimeout = stub.getParent() + ":/usr/bin:/bin";
        record Case(String path, String hang, String term, String bound, int exit, String shows) { }
        List<Case> cases = new ArrayList<>();
        for (String term : List.of("ignore", "mixed", "default")) {
            for (String path : List.of(withTimeout, bare.toString(), otherTimeout.toString())) {
                for (String hang : List.of("exec", "ps", "info", "version")) {
                    cases.add(new Case(path, hang, term, "2", 70, "Docker did not answer within 2s"));
                }
            }
        }
        for (String path : List.of(withTimeout, bare.toString(), otherTimeout.toString())) {
            cases.add(new Case(path, "exec-early", "default", "2", 20, "state unavailable"));
        }
        cases.add(new Case(withTimeout, "none", "default", "0", 2, "STARGATE_STATUS_TIMEOUT"));
        cases.add(new Case(withTimeout, "none", "default", "5s", 2, "STARGATE_STATUS_TIMEOUT"));
        cases.add(new Case(bare.toString(), "none", "default", "2", 30, "PENDING"));
        List<String> failures = new ArrayList<>();
        int n = 0;
        for (Case c : cases) {
            Path out = tmp.resolve("hang-" + n + ".out");
            Path pids = tmp.resolve("hang-" + n++ + ".pids");
            var pb = new ProcessBuilder("/bin/bash", repo.resolve("scripts/stargate").toString(), "status")
                    .redirectErrorStream(true).redirectOutput(out.toFile());
            pb.environment().put("PATH", c.path());
            pb.environment().put("STUB_HANG", c.hang());
            pb.environment().put("STUB_TERM", c.term());
            pb.environment().put("STUB_PIDS", pids.toString());
            pb.environment().put("STARGATE_STATUS_TIMEOUT", c.bound());
            pb.environment().put("STARGATE_ENV_FILE", tmp.resolve("local.env").toString());
            pb.environment().put("STARGATE_ENV_EXAMPLE", tmp.resolve("absent.env.example").toString());
            Process process = pb.start();
            // bound 2s + 1s kill grace + the watchdog's 1s poll, with slack.
            boolean ended = process.waitFor(8, TimeUnit.SECONDS);
            List<ProcessHandle> left = new ArrayList<>();
            if (Files.exists(pids)) {
                for (String line : Files.readAllLines(pids)) {
                    ProcessHandle.of(Long.parseLong(line.trim())).ifPresent(left::add);
                }
            }
            // A KILLed orphan is reaped by init asynchronously: allow 2s.
            long reapDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            left.removeIf(h -> !h.isAlive());
            while (!left.isEmpty() && System.nanoTime() < reapDeadline) {
                Thread.sleep(50);
                left.removeIf(h -> !h.isAlive());
            }
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            left.forEach(ProcessHandle::destroyForcibly);
            String text = Files.readString(out, StandardCharsets.UTF_8);
            if (!ended) {
                failures.add(c + " did not end within the bound -> " + text);
                continue;
            }
            if (process.exitValue() != c.exit() || !text.contains(c.shows())) {
                failures.add(c + " exit " + process.exitValue() + " -> " + text);
            }
            if ((c.exit() == 70 || c.exit() == 20) && (text.contains("PENDING") || text.contains("ACKNOWLEDGED"))) {
                failures.add(c + " an unavailable read claimed state -> " + text);
            }
            if (!left.isEmpty()) {
                failures.add(c + " left stub processes alive: " + left);
            }
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }

    /** T187: the production status file is CP-private, never in the DP-shared IPC volume. */
    @Test
    void deliveryStatusPathIsOutsideSharedIpcVolume() {
        Path status = StargateControlPlane.DELIVERY_STATUS;
        assertTrue(status.isAbsolute() && status.startsWith("/tmp"),
                "the status lives on the CP container's private /tmp tmpfs");
        assertFalse(status.startsWith("/run/stargate"), "never inside the stargate-ipc volume");
        assertFalse(status.startsWith("/var/lib/stargate"), "never in persistent CP state");
    }

    @Test
    void serializedNewControlPlaneToLegacyResponseStaysPending() throws Exception {
        Path keys = keysDir();
        Path dpSock = runDir().resolve("dp-legacy.sock");
        try (RecordingDp legacy = RecordingDp.startLegacy(dpSock, keys, keys.resolve("dp.pub"),
                        keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, new RecordingState());
            TokenLoaderContract.PushResult result = channel.push(4L,
                    List.of(repeat((byte) 0x31, 32)));
            assertFalse(result.stale());
            assertEquals(0L, result.currentGeneration(),
                    "serialized markerless legacy OK is pending, never durable success");
            assertEquals(0, legacy.requests.get(0).getTokensCount(),
                    "the legacy field exposes at most revoke-all to an old DP");
            assertTrue(legacy.requests.get(0).hasDurable());
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
                .setCurrentGeneration(5)
                .setAcknowledgmentVersion(1)
                .setCommitment(com.google.protobuf.ByteString.copyFrom(repeat((byte) 0x4a, 32)))
                .build();
        TokenLoaderContract.PushResult okMapped = GrpcReloadChannel.toPushResult(ok);
        assertFalse(okMapped.stale(), "OK maps to stale=false");
        assertEquals(5L, okMapped.currentGeneration(), "recognized durable ack carries generation");

        var legacyOk = ControlOuterClass.ReloadTokensResponse.newBuilder()
                .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK)
                .setAppliedGeneration(5)
                .build();
        TokenLoaderContract.PushResult pending = GrpcReloadChannel.toPushResult(legacyOk);
        assertFalse(pending.stale());
        assertEquals(0L, pending.currentGeneration(),
                "markerless old-DP OK is pending, never durable acknowledgment");

        var expectedCommitment = com.google.protobuf.ByteString.copyFrom(repeat((byte) 0x4a, 32));
        var wrongCommitment = ok.toBuilder()
                .setCommitment(com.google.protobuf.ByteString.copyFrom(repeat((byte) 0x4b, 32)))
                .build();
        TokenLoaderContract.PushResult mismatched = GrpcReloadChannel.toPushResult(
                5L, expectedCommitment, wrongCommitment);
        assertFalse(mismatched.stale());
        assertEquals(0L, mismatched.currentGeneration(),
                "a marked OK for different content is pending, never an exact durable acknowledgment");
    }

    @Test
    void transportFailureIsContained() throws Exception {
        Path keys = keysDir();
        // a real client dialing an ABSENT dp.sock: the connect fails immediately (ENOENT)
        try (ReloadTokensClient client = ReloadTokensClient.create(keys, runDir().resolve("no-dp.sock"))) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, new RecordingState());
            TokenLoaderContract.PushResult result = channel.push(3, List.of(repeat((byte) 0x2a, 32)));
            assertNotNull(result, "the transport failure is contained, never thrown (§1.8)");
            assertFalse(result.stale(), "a contained failure is not a stale rejection");
            assertEquals(0L, result.currentGeneration(),
                    "transport failure is pending, not acknowledged at the requested generation");
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

/**
 * T159's restored-authority probe uses the production SQLite/JTA adapter,
 * production bootstrap, and production Go control server together. Keeping
 * this Quarkus test beside the plain bootstrap suite preserves one reviewed
 * path while preventing its container lifecycle from slowing every unit test.
 */
@QuarkusTest
@TestProfile(T159ProductionAuthorityRecoveryTest.Profile.class)
class T159ProductionAuthorityRecoveryTest {

    @Inject
    SqliteTokenState state;

    @Inject
    EntityManager entityManager;

    @Inject
    UserTransaction transaction;

    private Map<String, byte[]> reconnectRacePriorRows = Map.of();
    private long reconnectRacePriorGeneration;
    private boolean restoreReconnectRaceState;

    @TempDir
    Path tmp;

    @BeforeEach
    void resetDeliveryMarker() throws Exception {
        transaction.begin();
        try {
            entityManager.createNativeQuery(
                    "UPDATE auth_delivery SET state = 'CLEAR', generation = 0 WHERE id = 1")
                    .executeUpdate();
            entityManager.createNativeQuery(
                    "DELETE FROM configured_tokens WHERE label = 't201-reconnect-restart-marker'")
                    .executeUpdate();
            transaction.commit();
        } catch (Exception failure) {
            try {
                transaction.rollback();
            } catch (Exception ignored) {
                failure.addSuppressed(ignored);
            }
            throw failure;
        }
    }

    @AfterEach
    void restoreReconnectRaceDatabase() throws Exception {
        if (!restoreReconnectRaceState) {
            return;
        }
        try {
            Map<String, byte[]> currentRows = verifierRows(state.storedTokens());
            boolean sameRows = currentRows.keySet().equals(reconnectRacePriorRows.keySet());
            if (sameRows) {
                for (String label : currentRows.keySet()) {
                    if (!MessageDigest.isEqual(currentRows.get(label), reconnectRacePriorRows.get(label))) {
                        sameRows = false;
                        break;
                    }
                }
            }
            if (!sameRows) {
                state.begin();
                for (String label : currentRows.keySet()) {
                    if (!reconnectRacePriorRows.containsKey(label)) {
                        state.delete(label);
                    }
                }
                for (Map.Entry<String, byte[]> row : reconnectRacePriorRows.entrySet()) {
                    state.upsert(row.getKey(), row.getValue());
                }
                state.commit();
            }
            state.record(reconnectRacePriorGeneration);
            transaction.begin();
            try {
                entityManager.createNativeQuery(
                        "UPDATE auth_delivery SET state = 'CLEAR', generation = 0 WHERE id = 1")
                        .executeUpdate();
                transaction.commit();
            } catch (Exception failure) {
                try {
                    transaction.rollback();
                } catch (Exception ignored) {
                    failure.addSuppressed(ignored);
                }
                throw failure;
            }
        } finally {
            restoreReconnectRaceState = false;
            reconnectRacePriorRows = Map.of();
        }
    }

    @Test
    void reconnectReplayAdmittedAfterAckClearSurvivesOlderCompletion() throws Exception {
        Path keys = StargateControlPlaneTest.writeKeys(tmp);
        Path dpSock = tmp.resolve("dp-ack-clear-reconnect-race.sock");
        Path statusFile = tmp.resolve("auth-delivery");
        var firstReplayArrived = new java.util.concurrent.CountDownLatch(1);
        var releaseFirstReplayFailure = new java.util.concurrent.CountDownLatch(1);
        var retryArrived = new java.util.concurrent.CountDownLatch(1);
        var releaseRetryAck = new java.util.concurrent.CountDownLatch(1);
        var pauseNextClear = new java.util.concurrent.atomic.AtomicBoolean();
        var atClearBoundary = new java.util.concurrent.CountDownLatch(1);
        var releaseOlderCompletion = new java.util.concurrent.CountDownLatch(1);
        var initialResult = new AtomicReference<TokenLoaderContract.PushResult>();
        var initialFailure = new AtomicReference<Throwable>();
        assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker());

        try (StargateControlPlaneTest.RecordingDp first = StargateControlPlaneTest.RecordingDp.start(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, statusFile, () -> {
                if (pauseNextClear.compareAndSet(true, false)) {
                    atClearBoundary.countDown();
                    try {
                        if (!releaseOlderCompletion.await(10, TimeUnit.SECONDS)) {
                            throw new AssertionError("bounded ACK-clear test boundary was not released");
                        }
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError("ACK-clear test boundary interrupted", interrupted);
                    }
                }
            });
            byte[] verifier = StargateControlPlaneTest.repeat((byte) 0x2a, 32);
            assertEquals(4L, channel.push(4L, List.of(verifier)).currentGeneration(),
                    "retain the exact candidate for authenticated reconnect replay");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker(),
                    "the initial exact ACK was committed to the real SQLite adapter");

            pauseNextClear.set(true);
            Thread olderCompletion = new Thread(() -> {
                try {
                    initialResult.set(channel.push(4L, List.of(verifier)));
                } catch (Throwable failure) {
                    initialFailure.set(failure);
                }
            }, "t201-initial-ack-completion");
            olderCompletion.start();
            assertTrue(atClearBoundary.await(10, TimeUnit.SECONDS),
                    "initial exact ACK durably cleared UNRESOLVED before the local completion boundary");
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker(),
                    "the race boundary follows the committed SQLite clear");

            first.close();
            try (StargateControlPlaneTest.RecordingDp restarted =
                    StargateControlPlaneTest.RecordingDp.startUnavailableThenHeldRetryObserved(
                            dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"),
                            firstReplayArrived, releaseFirstReplayFailure, retryArrived, releaseRetryAck)) {
                assertTrue(firstReplayArrived.await(10, TimeUnit.SECONDS),
                        "authenticated reconnect admitted and dispatched the retained generation");
                String heldStatus = awaitStatus(statusFile, "PENDING\n", Duration.ofSeconds(3));
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 4), state.deliveryMarker(),
                        "the replay is durably prearmed in SQLite while its RPC remains held");

                releaseOlderCompletion.countDown();
                olderCompletion.join(TimeUnit.SECONDS.toMillis(5));
                assertFalse(olderCompletion.isAlive(), "older initial completion is bounded");
                assertEquals(null, initialFailure.get(), "initial push does not throw");
                assertNotNull(initialResult.get());
                assertFalse(initialResult.get().stale());
                assertEquals(0L, initialResult.get().currentGeneration(),
                        "the superseded ACK cannot report completed delivery");
                assertEquals("PENDING\n", heldStatus);
                assertEquals("PENDING\n", Files.readString(statusFile, StandardCharsets.US_ASCII),
                        "the older completion cannot overwrite the replay's pending status");
                StargateControlPlaneTest.StatusCommandResult pendingStatus =
                        StargateControlPlaneTest.statusCommandForFile(statusFile, tmp);
                assertEquals(30, pendingStatus.exitCode(), pendingStatus.output());
                assertTrue(pendingStatus.output().contains("PENDING"), pendingStatus.output());

                releaseFirstReplayFailure.countDown();
                assertTrue(retryArrived.await(10, TimeUnit.SECONDS),
                        "non-stale UNAVAILABLE leaves the replay queued for retry");
                assertEquals(2, restarted.requests.size(),
                        "the failed replay is followed by a separately dispatched retry");
                var failedReplay = restarted.requests.get(0);
                var retry = restarted.requests.get(1);
                assertEquals(4L, failedReplay.getGeneration());
                assertEquals(failedReplay.getGeneration(), retry.getGeneration(),
                        "retry preserves the queued generation");
                assertEquals(failedReplay.getDurable().getCommitment(), retry.getDurable().getCommitment(),
                        "retry preserves the exact durable candidate commitment");
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 4), state.deliveryMarker(),
                        "a non-stale transport failure keeps SQLite unresolved while retry is held");
                assertEquals("PENDING\n", Files.readString(statusFile, StandardCharsets.US_ASCII),
                        "a non-stale transport failure cannot publish completion");
                StargateControlPlaneTest.StatusCommandResult retryPendingStatus =
                        StargateControlPlaneTest.statusCommandForFile(statusFile, tmp);
                assertEquals(30, retryPendingStatus.exitCode(), retryPendingStatus.output());
                assertTrue(retryPendingStatus.output().contains("PENDING"), retryPendingStatus.output());

                releaseRetryAck.countDown();
                assertEquals("ACKNOWLEDGED(4)\n", awaitStatus(
                        statusFile, "ACKNOWLEDGED(4)\n", Duration.ofSeconds(10)),
                        "only the replay's exact ACK completes delivery");
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker(),
                        "the replay ACK commits CLEAR in production SQLite");
                StargateControlPlaneTest.StatusCommandResult acknowledgedStatus =
                        StargateControlPlaneTest.statusCommandForFile(statusFile, tmp);
                assertEquals(0, acknowledgedStatus.exitCode(), acknowledgedStatus.output());
                assertEquals(List.of(4L), restarted.completedGenerations,
                        "only the retry's exact ACK completes the replay");
            } finally {
                releaseFirstReplayFailure.countDown();
                releaseRetryAck.countDown();
                releaseOlderCompletion.countDown();
            }
        }
    }

    @Test
    void olderAckCannotClearReconnectReplayBeforeDurableClear() throws Exception {
        reconnectRacePriorRows = verifierRows(state.storedTokens());
        reconnectRacePriorGeneration = state.lastGeneration();
        restoreReconnectRaceState = true;
        Path keys = StargateControlPlaneTest.writeKeys(tmp);
        Path dpSock = tmp.resolve("dp-before-clear-reconnect-race.sock");
        Path statusFile = tmp.resolve("auth-delivery");
        Path tokensFile = tmp.resolve("tokens.yaml");
        Path pepperFile = tmp.resolve("pepper.key");
        Files.write(pepperFile, StargateControlPlaneTest.TEST_PEPPER);
        Files.writeString(tokensFile,
                "tokens:\n  - label: t201-reconnect-restart-marker\n    token: "
                        + StargateControlPlaneTest.EXAMPLE_HEX + "\n",
                StandardCharsets.UTF_8);
        Path runDir = Files.createDirectories(tmp.resolve("run"));
        var atBeforeClear = new java.util.concurrent.CountDownLatch(1);
        var releaseOlderCompletion = new java.util.concurrent.CountDownLatch(1);
        var pauseOlderClear = new java.util.concurrent.atomic.AtomicBoolean();
        var replayArrived = new java.util.concurrent.CountDownLatch(1);
        var releaseReplayStale = new java.util.concurrent.CountDownLatch(1);
        var olderResult = new AtomicReference<TokenLoaderContract.PushResult>();
        var olderFailure = new AtomicReference<Throwable>();
        assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker());

        try (StargateControlPlaneTest.RecordingDp first = StargateControlPlaneTest.RecordingDp.start(
                    dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"));
                ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            GrpcReloadChannel channel = new GrpcReloadChannel(client, state, statusFile, () -> {
                if (pauseOlderClear.compareAndSet(true, false)) {
                    atBeforeClear.countDown();
                    try {
                        if (!releaseOlderCompletion.await(10, TimeUnit.SECONDS)) {
                            throw new AssertionError("bounded pre-clear race boundary was not released");
                        }
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError("pre-clear race boundary interrupted", interrupted);
                    }
                }
            }, () -> { });
            byte[] verifier = StargateControlPlaneTest.repeat((byte) 0x2a, 32);
            assertEquals(4L, channel.push(4L, List.of(verifier)).currentGeneration());
            assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker(),
                    "the initial production SQLite ACK clear commits before the race");

            pauseOlderClear.set(true);
            Thread olderCompletion = new Thread(() -> {
                try {
                    olderResult.set(channel.push(4L, List.of(verifier)));
                } catch (Throwable failure) {
                    olderFailure.set(failure);
                }
            }, "t201-older-ack-before-clear");
            olderCompletion.start();
            assertTrue(atBeforeClear.await(10, TimeUnit.SECONDS),
                    "the older exact ACK is paused immediately before its durable clear");
            first.close();
            try (StargateControlPlaneTest.RecordingDp replay =
                    StargateControlPlaneTest.RecordingDp.startHeldStaleObserved(
                            dpSock, keys, keys.resolve("dp.pub"), keys.resolve("cp.pub"),
                            releaseReplayStale, replayArrived)) {
                assertTrue(replayArrived.await(10, TimeUnit.SECONDS),
                        "authenticated reconnect replay reaches the held DP before old clear resumes");
                var markerWithReplay = state.deliveryMarker();
                String statusWithReplay = Files.readString(statusFile, StandardCharsets.US_ASCII);
                StargateControlPlaneTest.StatusCommandResult cliWithReplay =
                        StargateControlPlaneTest.statusCommandForFile(statusFile, tmp);

                releaseOlderCompletion.countDown();
                olderCompletion.join(TimeUnit.SECONDS.toMillis(5));
                assertFalse(olderCompletion.isAlive(), "older exact-ACK completion is bounded");
                assertEquals(null, olderFailure.get(), "older push does not throw");
                assertNotNull(olderResult.get());
                assertEquals(0L, olderResult.get().currentGeneration(),
                        "the superseded initial ACK is not reported as completed");
                var markerAfterOlderCompletion = state.deliveryMarker();
                String statusAfterOlderCompletion = Files.readString(statusFile, StandardCharsets.US_ASCII);
                StargateControlPlaneTest.StatusCommandResult cliAfterOlderCompletion =
                        StargateControlPlaneTest.statusCommandForFile(statusFile, tmp);

                releaseReplayStale.countDown();
                String staleStatus = awaitStatus(statusFile, "STALE_CONFLICT\n", Duration.ofSeconds(10));
                var markerAfterStale = state.deliveryMarker();
                int replayRequestsBeforeRestart = replay.requests.size();
                client.close();

                long generationBeforeRestart = state.lastGeneration();
                Map<String, byte[]> rowsBeforeRestart = verifierRows(state.storedTokens());
                var cfg = new StargateControlPlane.BootConfig(tokensFile, pepperFile, keys,
                        runDir.resolve("control.sock"), dpSock, runDir.resolve("observer.sock"),
                        Duration.ofSeconds(10), statusFile);
                String restartStatus;
                try (StargateControlPlane.BootHandle ignored = StargateControlPlane.bootstrap(
                        cfg, (action, target, detail) -> { }, state, state)) {
                    restartStatus = Files.readString(statusFile, StandardCharsets.US_ASCII);
                }
                Map<String, byte[]> rowsAfterRestart = verifierRows(state.storedTokens());
                assertAll("older ACK cannot remove the authenticated replay's production SQLite barrier",
                        () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 4), markerWithReplay),
                        () -> assertEquals("PENDING\n", statusWithReplay),
                        () -> assertEquals(30, cliWithReplay.exitCode(), cliWithReplay.output()),
                        () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, 4),
                                markerAfterOlderCompletion,
                                "older ACK must not clear the replay's newly committed UNRESOLVED marker"),
                        () -> assertEquals("PENDING\n", statusAfterOlderCompletion),
                        () -> assertEquals(30, cliAfterOlderCompletion.exitCode(), cliAfterOlderCompletion.output()),
                        () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                TokenLoaderContract.GenerationStore.DeliveryState.STALE, 4), markerAfterStale,
                                "a stale replay persists over the unresolved restart barrier"),
                        () -> assertEquals("STALE_CONFLICT\n", staleStatus),
                        () -> assertEquals(replayRequestsBeforeRestart, replay.requests.size(),
                                "changed-YAML bootstrap behind STALE issues no reload RPC"),
                        () -> assertEquals(generationBeforeRestart, state.lastGeneration(),
                                "changed-YAML bootstrap does not reserve a generation behind STALE"),
                        () -> assertVerifierRowsEqual(rowsBeforeRestart, rowsAfterRestart),
                        () -> assertEquals("STALE_CONFLICT\n", restartStatus));
            } finally {
                releaseReplayStale.countDown();
                releaseOlderCompletion.countDown();
            }
        }
    }

    private static Map<String, byte[]> verifierRows(
            java.util.Collection<TokenLoaderContract.StoredToken> rows) {
        Map<String, byte[]> copy = new TreeMap<>();
        for (TokenLoaderContract.StoredToken row : rows) {
            copy.put(row.label(), row.verifier().clone());
        }
        return copy;
    }

    private static void assertVerifierRowsEqual(Map<String, byte[]> before, Map<String, byte[]> after) {
        assertEquals(before.keySet(), after.keySet(), "credential row labels remain unchanged");
        for (String label : before.keySet()) {
            assertTrue(MessageDigest.isEqual(before.get(label), after.get(label)),
                    "stored verifier row remains unchanged for " + label);
        }
    }

    private String awaitStatus(Path statusFile, String expected, Duration within) throws Exception {
        long deadline = System.nanoTime() + within.toNanos();
        String seen = Files.exists(statusFile) ? Files.readString(statusFile, StandardCharsets.US_ASCII) : null;
        while (!expected.equals(seen) && System.nanoTime() < deadline) {
            Thread.sleep(20);
            seen = Files.exists(statusFile) ? Files.readString(statusFile, StandardCharsets.US_ASCII) : null;
        }
        return seen;
    }

    private static final class ObservedGenerationStore implements TokenLoaderContract.GenerationStore {
        private final SqliteTokenState delegate;
        private final AtomicInteger prearmAttempts = new AtomicInteger();
        private final AtomicInteger prearmSuccesses = new AtomicInteger();

        ObservedGenerationStore(SqliteTokenState delegate) {
            this.delegate = delegate;
        }

        @Override
        public long lastGeneration() {
            return delegate.lastGeneration();
        }

        @Override
        public void record(long generation) {
            delegate.record(generation);
        }

        @Override
        public TokenLoaderContract.GenerationStore.DeliveryMarker deliveryMarker() {
            return delegate.deliveryMarker();
        }

        @Override
        public boolean prearmDelivery(long generation) {
            prearmAttempts.incrementAndGet();
            boolean accepted = delegate.prearmDelivery(generation);
            if (accepted) {
                prearmSuccesses.incrementAndGet();
            }
            return accepted;
        }

        @Override
        public boolean acknowledgeDelivery(long generation) {
            return delegate.acknowledgeDelivery(generation);
        }

        @Override
        public boolean recordStaleDelivery(long generation) {
            return delegate.recordStaleDelivery(generation);
        }
    }

    @Test
    void restoredProductionSqliteAuthorityCannotReauthorizeRevokedToken() throws Exception {
        assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0), state.deliveryMarker(),
                "the real production SQLite adapter starts with the migrated CLEAR marker");
        Path keys = StargateControlPlaneTest.writeKeys(tmp);
        Files.write(keys.resolve("pepper.key"), StargateControlPlaneTest.TEST_PEPPER);
        Path pepperFile = tmp.resolve("pepper.key");
        Files.write(pepperFile, StargateControlPlaneTest.TEST_PEPPER);
        Path tokensFile = tmp.resolve("tokens.yaml");
        Files.writeString(tokensFile,
                "tokens:\n  - label: restored-old\n    token: "
                        + StargateControlPlaneTest.EXAMPLE_HEX + "\n",
                StandardCharsets.UTF_8);

        byte[] revokedVerifier = StargateControlPlaneTest.referenceMint(
                StargateControlPlaneTest.TEST_PEPPER, StargateControlPlaneTest.EXAMPLE_HEX);
        state.record(1L);
        state.begin();
        state.upsert("restored-old", revokedVerifier);
        state.commit();

        // The injected production adapter represents the restored CP: its
        // durable DB/configuration still contains generation 1 and the
        // credential that the newer DP authority revoked at generation 2.
        SqliteTokenState restored = state;
        ObservedGenerationStore observed = new ObservedGenerationStore(restored);
        assertEquals(1L, restored.lastGeneration());
        assertEquals(List.of("restored-old"), restored.storedTokens().stream()
                .map(TokenLoaderContract.StoredToken::label).toList());

        Path stateDir = Files.createDirectories(tmp.resolve("dp-state"));
        Files.writeString(stateDir.resolve("dp-snapshot.json"),
                "{\"schemaVersion\":3,\"authSetVersion\":1,\"generation\":2,"
                        + "\"commitment\":\"0aTZNWoRBmJiQLlioYT3lCjwpLxp+uWWM7WZ35VBFnU=\","
                        + "\"loadedAt\":\"2026-09-24T00:00:00Z\",\"verifiers\":[]}",
                StandardCharsets.US_ASCII);
        Files.writeString(tmp.resolve("auth-probe"), StargateControlPlaneTest.EXAMPLE_HEX,
                StandardCharsets.US_ASCII);
        Path runDir = Files.createDirectories(tmp.resolve("run"));
        Path log = tmp.resolve("dp-run.log");
        ProcessBuilder fixture = new ProcessBuilder("go", "test", "./internal/controlclient",
                "-run", "^TestJavaReloadInteropFixture$", "-count=1", "-timeout=30s")
                .directory(Path.of("../../data-plane").toAbsolutePath().normalize().toFile())
                .redirectErrorStream(true)
                .redirectOutput(log.toFile());
        fixture.environment().put("T159_JAVA_INTEROP_DIR", tmp.toString());
        Process dp = fixture.start();
        try {
            long readyDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (!Files.exists(tmp.resolve("ready")) && dp.isAlive()
                    && System.nanoTime() < readyDeadline) {
                Thread.sleep(20);
            }
            assertTrue(Files.exists(tmp.resolve("ready")),
                    "real Go DP starts: " + Files.readString(log));

            var cfg = new StargateControlPlane.BootConfig(tokensFile, pepperFile, keys,
                    runDir.resolve("control.sock"), runDir.resolve("dp.sock"),
                    runDir.resolve("observer.sock"), Duration.ofSeconds(10), runDir.resolve("auth-delivery"));
            try (StargateControlPlane.BootHandle ignored = StargateControlPlane.bootstrap(
                    cfg, (action, target, detail) -> { }, restored, observed)) {
                assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                        TokenLoaderContract.GenerationStore.DeliveryState.STALE, 1), restored.deliveryMarker(),
                        "the real stale Go response is durably recorded by production SQLite");
                assertEquals("STALE_CONFLICT\n", Files.readString(runDir.resolve("auth-delivery"),
                        StandardCharsets.US_ASCII));
                assertEquals(1, observed.prearmAttempts.get(), "the initial production RPC is preceded by one prearm");
                assertEquals(1, observed.prearmSuccesses.get(), "the actual SQLite prearm succeeds");
                assertEquals(1L, restored.lastGeneration(),
                    "stale restored content is never relabeled above DP generation 2");
                String current = Files.readString(stateDir.resolve("dp-snapshot.json"));
                assertTrue(current.contains("\"generation\":2"));
                assertTrue(current.contains("\"verifiers\":[]"));
                assertFalse(current.contains(Base64.getEncoder().encodeToString(revokedVerifier)),
                        "the restored production CP must not reintroduce the revoked verifier");
            }

            // The process restart is the critical boundary: the old channel's
            // in-memory stale latch is gone, but this is the same production
            // SQLite authority with both the old row and generation restored.
            // Each startup receives a distinct valid edit retaining that
            // credential. On the current implementation, generation 3
            // overtakes the DP's generation 2 and the real Go process accepts
            // the restored credential.
            for (int edit = 1; edit <= 4; edit++) {
                String addedToken = String.format("%032x", edit);
                Files.writeString(tokensFile,
                        "tokens:\n  - label: restored-old\n    token: "
                                + StargateControlPlaneTest.EXAMPLE_HEX
                                + "\n  - label: changed-" + edit + "\n    token: " + addedToken + "\n",
                        StandardCharsets.UTF_8);
                try (StargateControlPlane.BootHandle restarted = StargateControlPlane.bootstrap(
                        cfg, (action, target, detail) -> { }, restored, observed)) {
                    // Preserve each real transition as data for the final
                    // assertion; do not stop at the first changed load.
                    String status = Files.readString(runDir.resolve("auth-delivery"), StandardCharsets.US_ASCII);
                    String snapshot = Files.readString(stateDir.resolve("dp-snapshot.json"));
                    assertAll("changed-YAML restart " + edit + " remains inhibited by durable SQLite STALE",
                            () -> assertEquals(1, observed.prearmAttempts.get(),
                                    "a changed-YAML restart does not dispatch after durable STALE"),
                            () -> assertEquals(1, observed.prearmSuccesses.get(),
                                    "no new candidate is durably armed after STALE"),
                            () -> assertEquals(new TokenLoaderContract.GenerationStore.DeliveryMarker(
                                    TokenLoaderContract.GenerationStore.DeliveryState.STALE, 1),
                                    restored.deliveryMarker()),
                            () -> assertEquals("STALE_CONFLICT\n", status),
                            () -> assertEquals(1L, restored.lastGeneration()),
                            () -> assertEquals(List.of("restored-old"), restored.storedTokens().stream()
                                    .map(TokenLoaderContract.StoredToken::label).toList()),
                            () -> assertTrue(snapshot.contains("\"generation\":2"), snapshot),
                            () -> assertTrue(snapshot.contains("\"verifiers\":[]"), snapshot));
                }
            }

            String afterChangedLoads = Files.readString(stateDir.resolve("dp-snapshot.json"));
            assertTrue(afterChangedLoads.contains("\"generation\":2"),
                    "restart after a stale refusal must not push a changed set that the DP accepts: "
                            + afterChangedLoads);
            assertTrue(afterChangedLoads.contains("\"verifiers\":[]"),
                    "the stale credential remains absent from actual DP authority");
            assertEquals(1L, restored.lastGeneration(),
                    "changed YAML after restart cannot promote the restored CP generation");
            assertEquals(List.of("restored-old"), restored.storedTokens().stream()
                    .map(TokenLoaderContract.StoredToken::label).toList(),
                    "blocked startup cannot mutate the durable credential rows");
        } finally {
            Files.write(tmp.resolve("stop"), new byte[0]);
            if (!dp.waitFor(5, TimeUnit.SECONDS)) {
                dp.destroyForcibly();
                dp.waitFor(5, TimeUnit.SECONDS);
            }
        }

        String authResult = Files.readString(tmp.resolve("auth-result"));
        assertTrue(authResult.contains("generation=2"));
        assertTrue(authResult.contains("authorized=false"),
                "the real Go verifier rejects the credential through all restarted CP attempts");
    }

    public static final class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "quarkus.datasource.jdbc.url", "jdbc:sqlite:target/t159-production-authority.db",
                    "quarkus.flyway.clean-at-start", "true",
                    "quarkus.flyway.clean-disabled", "false");
        }
    }
}
