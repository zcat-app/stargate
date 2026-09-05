// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.channel.unix.DomainSocketAddress;

import stargate.v1.ControlGrpc;
import stargate.v1.ControlOuterClass;
import stargate.v1.EventsGrpc;
import stargate.v1.EventsOuterClass;

/**
 * In-process contract tests for the control plane's inter-plane gRPC surface
 * (T038), driven over REAL unix-domain sockets with the REAL TLS stack — the
 * CP-side local tier of {@code contracts/control-grpc.md} §"Transport
 * invariants" and {@code contracts/wire-auth.md} §4/§5 (the compose-tier rows
 * R1–R9 in {@code tests/contract/compose/inter_plane_wire_test.sh} lift later
 * against a live stack):
 *
 * <ul>
 *   <li>§"Socket topology" — the CP binds control.sock, mode 0660, UDS-only
 *       (no TCP listener);</li>
 *   <li>§5.2 — an absent/unparseable/unequal {@code x-stargate-proto-major}
 *       is rejected with {@code FailedPrecondition} BEFORE any handler runs;
 *       equal major with any minor is accepted;</li>
 *   <li>§5.3/§5.1 — the client interceptor stamps the three metadata keys,
 *       from the single {@code StargateProtoVersion} constants class, on
 *       every call;</li>
 *   <li>§4 — mutual TLS: wrong-key peers rejected at the handshake in BOTH
 *       directions; the CP's {@code ReloadTokensClient} round-trips a token
 *       push against a DP-stand-in server over the same wire shape.</li>
 * </ul>
 *
 * <p>Roles per §"Socket topology": on control.sock the CP is the SERVER
 * (CP identity cert; client certs pinned against dp.pub) and the client is
 * the DP — the tests' client side therefore presents the DP identity, the
 * mirror of the Go fake-CP pattern in {@code tests/contract/control-grpc}.
 * On dp.sock (ReloadTokensClient) the roles flip: CP identity client, DP
 * identity server.
 */
class InterPlaneWireTest {

    @TempDir
    Path tmp;

    // --- fixture helpers ---------------------------------------------------------

    private static final String DP_CN = "stargate-dp";
    private static final String DP_SPIFFE = "spiffe://stargate.local/dp";

    /** Writes a PEM file (64-column Base64, standard RFC 7468 armour). */
    private static void writePem(Path path, String type, byte[] der) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                .encodeToString(der);
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + base64
                + "\n-----END " + type + "-----\n",
                java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static KeyPair ed25519() throws Exception {
        return java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static Path writePrivateKey(Path dir, String name, KeyPair kp) throws Exception {
        Path p = dir.resolve(name);
        writePem(p, "PRIVATE KEY", kp.getPrivate().getEncoded());
        return p;
    }

    private static Path writePublicKey(Path dir, String name, KeyPair kp) throws Exception {
        Path p = dir.resolve(name);
        writePem(p, "PUBLIC KEY", kp.getPublic().getEncoded());
        return p;
    }

    private static PrivateKey loadPriv(Path p) throws Exception {
        return CpTls.loadPkcs8Pem(p);
    }

    /** The §2.2 stargate-dp identity, derived through the production code path. */
    private static CpTls.Identity dpIdentity(PrivateKey dpPriv, PublicKey dpPub) throws Exception {
        return new CpTls.Identity(dpPriv, CpTls.deriveSelfSigned(dpPriv, dpPub,
                DP_CN, DP_SPIFFE, Instant.now().truncatedTo(ChronoUnit.SECONDS)));
    }

    /** Metadata.getAll returns a custom Iterable — collect it for equality. */
    private static List<String> all(Metadata md, Metadata.Key<String> key) {
        List<String> out = new java.util.ArrayList<>();
        md.getAll(key).forEach(out::add);
        return out;
    }

    /** Polls until the predicate holds; the final miss is the assertion failure. */
    private static void waitUntil(String what, Duration timeout, BooleanSupplier p) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (p.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted waiting for " + what, e);
            }
        }
        assertTrue(p.getAsBoolean(), "timed out waiting for " + what);
    }

    /** AutoCloseable bag for started servers/channels — one try-with-resources per test. */
    private static final class Stack implements AutoCloseable {
        private final List<AutoCloseable> resources = new java.util.ArrayList<>();

        <T extends AutoCloseable> T add(T resource) {
            resources.add(resource);
            return resource;
        }

        @Override
        public void close() throws Exception {
            for (int i = resources.size() - 1; i >= 0; i--) {
                resources.get(i).close();
            }
        }
    }

    /**
     * The test's mock server handle: server + its caller-owned Netty groups
     * (grpc does not stop builder-provided groups), one AutoCloseable.
     */
    private static final class MockServer implements AutoCloseable {
        final Server server;
        private final io.netty.channel.EventLoopGroup boss;
        private final io.netty.channel.EventLoopGroup workers;

        private MockServer(Server server, io.netty.channel.EventLoopGroup boss,
                io.netty.channel.EventLoopGroup workers) {
            this.server = server;
            this.boss = boss;
            this.workers = workers;
        }

        static MockServer start(NettyServerBuilder builder) throws java.io.IOException {
            var boss = new io.netty.channel.epoll.EpollEventLoopGroup(1);
            var workers = new io.netty.channel.epoll.EpollEventLoopGroup();
            try {
                return new MockServer(builder
                        .bossEventLoopGroup(boss)
                        .workerEventLoopGroup(workers)
                        .channelType(io.netty.channel.epoll.EpollServerDomainSocketChannel.class)
                        .build()
                        .start(), boss, workers);
            } catch (java.io.IOException | RuntimeException e) {
                boss.shutdownGracefully();
                workers.shutdownGracefully();
                throw e;
            }
        }

        @Override
        public void close() {
            server.shutdownNow();
            try {
                server.awaitTermination(5, SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            boss.shutdownGracefully();
            workers.shutdownGracefully();
        }
    }

    /** A DP-role channel onto control.sock plus its caller-owned group. */
    private static final class UdsChannel implements AutoCloseable {
        final ManagedChannel channel;
        private final io.netty.channel.EventLoopGroup group;

        private UdsChannel(ManagedChannel channel, io.netty.channel.EventLoopGroup group) {
            this.channel = channel;
            this.group = group;
        }

        static UdsChannel connect(String sockPath, java.security.PrivateKey dpPriv,
                java.security.PublicKey dpPub, Path pinnedPubPath) throws Exception {
            var group = new io.netty.channel.epoll.EpollEventLoopGroup(1);
            ManagedChannel ch = NettyChannelBuilder
                    .forAddress((java.net.SocketAddress) new DomainSocketAddress(sockPath))
                    .channelType(io.netty.channel.epoll.EpollDomainSocketChannel.class)
                    .eventLoopGroup(group)
                    .sslContext(io.grpc.netty.GrpcSslContexts.forClient()
                            .keyManager(dpPriv, dpIdentity(dpPriv, dpPub).certificate())
                            .trustManager(CpTls.peerPinTrustManager(pinnedPubPath))
                            .protocols("TLSv1.3")
                            .build())
                    .build();
            return new UdsChannel(ch, group);
        }

        @Override
        public void close() {
            channel.shutdownNow();
            try {
                channel.awaitTermination(5, SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            group.shutdownGracefully();
        }
    }

    /** A per-call metadata-injecting client interceptor (the NO-version raw channel). */
    private static ClientInterceptor injectMetadata(String major, String minor) {
        return new ClientInterceptor() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
                    MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
                return new io.grpc.ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
                    @Override
                    public void start(io.grpc.ClientCall.Listener<RespT> listener, Metadata headers) {
                        if (major != null) {
                            headers.put(StargateProtoVersion.META_MAJOR, major);
                        }
                        if (minor != null) {
                            headers.put(StargateProtoVersion.META_MINOR, minor);
                        }
                        super.start(listener, headers);
                    }
                };
            }
        };
    }

    /**
     * A DP-role channel onto a control.sock: presents the DP identity cert
     * (§"Socket topology": the DP dials control.sock) and pins the server
     * against the given cp.pub path.
     */
    private static ManagedChannel dpRoleChannel(Path sock, PrivateKey dpPriv, PublicKey dpPub,
            Path cpPubPath) throws Exception {
        return NettyChannelBuilder
                .forAddress((java.net.SocketAddress) new DomainSocketAddress(sock.toString()))
                .channelType(io.netty.channel.epoll.EpollDomainSocketChannel.class)
                .sslContext(io.grpc.netty.GrpcSslContexts.forClient()
                        .keyManager(dpPriv, dpIdentity(dpPriv, dpPub).certificate())
                        .trustManager(CpTls.peerPinTrustManager(cpPubPath))
                        .protocols("TLSv1.3")
                        .build())
                .build();
    }

    // --- §"Socket topology": bind, mode 0660, UDS-only ----------------------------

    @Test
    void serverBindsControlSock0660UdsOnly() throws Exception {
        Path keys = Files.createDirectories(tmp.resolve("keys-topology"));
        var cp = ed25519();
        var dp = ed25519();
        Path cpPriv = writePrivateKey(keys, "cp.priv", cp);
        Path cpPub = writePublicKey(keys, "cp.pub", cp);
        Path dpPub = writePublicKey(keys, "dp.pub", dp);

        Path sock = tmp.resolve("ipc-topology").resolve("control.sock");
        Files.createDirectories(sock.getParent());
        var service = new ControlGrpcService();
        try (Stack stack = new Stack()) {
            var bound = stack.add(service.startServer(sock, cpPriv, cpPub, dpPub));
            // The socket file exists, IS a socket, and carries exactly 0660 —
            // the kernel-enforced dial gate (peer can connect, out-of-group
            // cannot; R1/R3 lift against the live stack later).
            var attrs = Files.readAttributes(sock, PosixFileAttributes.class);
            assertEquals(PosixFilePermissions.fromString("rw-rw----"), attrs.permissions(),
                    "§\"Socket topology\": control.sock must be mode 0660");
            // No TCP transport: a UDS-hosted gRPC server has no listen port.
            assertEquals(-1, bound.server().getPort(),
                    "§4/arch §5.4: the inter-plane listener must not open a TCP port");
        }
    }

    // --- §5.2 rejection rule + §5.3 server interceptor -----------------------------

    @Test
    void unknownMajorRejectedBeforeHandler() throws Exception {
        Path keys = Files.createDirectories(tmp.resolve("keys-major"));
        var cp = ed25519();
        var dp = ed25519();
        Path cpPriv = writePrivateKey(keys, "cp.priv", cp);
        Path cpPub = writePublicKey(keys, "cp.pub", cp);
        Path dpPub = writePublicKey(keys, "dp.pub", dp);

        Path sock = tmp.resolve("ipc-major").resolve("control.sock");
        Files.createDirectories(sock.getParent());
        var service = new ControlGrpcService();
        try (Stack stack = new Stack()) {
            stack.add(service.startServer(sock, cpPriv, cpPub, dpPub));
            ManagedChannel ch = stack.add(
                    UdsChannel.connect(sock.toString(), dp.getPrivate(), dp.getPublic(), cpPub)).channel;

            // §5.2: absent, non-numeric, below, and above the receiver's major
            // are all rejected with FailedPrecondition (stiffer than arch §5.3
            // on the low side, on purpose — §5.2 blocks silent downgrade).
            for (String badMajor : new String[] { null, "abc", "0", "2", "99", "-1" }) {
                Iterator<EventsOuterClass.SidecarEvent> it = EventsGrpc
                        .newBlockingStub(ClientInterceptors.intercept(ch, injectMetadata(badMajor, "0")))
                        .withDeadlineAfter(5, SECONDS)
                        .watchEvents(EventsOuterClass.WatchEventsRequest.getDefaultInstance());
                StatusRuntimeException err = assertThrows(StatusRuntimeException.class, it::next,
                        "major=" + badMajor + " must be rejected by the §5.2 rule");
                assertEquals(Status.Code.FAILED_PRECONDITION, err.getStatus().getCode(),
                        "§5.2: unknown major must be FailedPrecondition");
            }
            // §5.3: none of the rejected calls reached the application handler.
            waitUntil("all rejected calls to have drained", Duration.ofSeconds(5),
                    () -> service.activeStreams() == 0);

            // §5.2 acceptance: equal major with an additive minor is accepted —
            // the handler runs (stream registered) and a published event is
            // delivered end-to-end.
            Iterator<EventsOuterClass.SidecarEvent> accepted = EventsGrpc
                    .newBlockingStub(ClientInterceptors.intercept(ch, injectMetadata("1", "7")))
                    .withDeadlineAfter(10, SECONDS)
                    .watchEvents(EventsOuterClass.WatchEventsRequest.getDefaultInstance());
            waitUntil("the accepted stream to reach the handler", Duration.ofSeconds(5),
                    () -> service.activeStreams() == 1);
            service.publish(EventsOuterClass.SidecarEvent.newBuilder()
                    .setSidecar("tor")
                    .setKind(EventsOuterClass.EventKind.EVENT_KIND_STARTED)
                    .setDetail("container_start")
                    .build());
            EventsOuterClass.SidecarEvent received = accepted.next();
            assertEquals("tor", received.getSidecar());
            assertEquals("container_start", received.getDetail());
        }
    }

    // --- §5.1/§5.3 client metadata + ReloadTokensClient push ------------------------

    @Test
    void reloadClientStampsVersionMetadataAndRoundTrips() throws Exception {
        Path keys = Files.createDirectories(tmp.resolve("keys-reload"));
        var cp = ed25519();
        var dp = ed25519();
        Path cpPriv = writePrivateKey(keys, "cp.priv", cp);
        Path cpPub = writePublicKey(keys, "cp.pub", cp);
        Path dpPriv = writePrivateKey(keys, "dp.priv", dp);
        Path dpPub = writePublicKey(keys, "dp.pub", dp);

        Path dpSock = tmp.resolve("ipc-reload").resolve("dp.sock");
        Files.createDirectories(dpSock.getParent());

        // Header-capture interceptor — installed FIRST on the DP-stand-in,
        // before anything else, so it sees the wire headers verbatim.
        AtomicReference<Metadata> captured = new AtomicReference<>();
        ServerInterceptor capture = new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                    ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                captured.set(headers);
                return next.startCall(call, headers);
            }
        };

        // DP-stand-in: the Control service on dp.sock with the DP identity
        // cert, client certs pinned against cp.pub — the mirror of the real
        // DP server (T045 server.go). The CP client is ReloadTokensClient.
        try (Stack stack = new Stack()) {
            stack.add(MockServer.start(NettyServerBuilder
                .forAddress((java.net.SocketAddress) new DomainSocketAddress(dpSock.toString()))
                .sslContext(CpTls.serverContext(dpIdentity(dp.getPrivate(), dp.getPublic()), cpPub))
                .intercept(capture)
                .addService(new ControlGrpc.ControlImplBase() {
                    @Override
                    public void reloadTokens(ControlOuterClass.ReloadTokensRequest request,
                            StreamObserver<ControlOuterClass.ReloadTokensResponse> response) {
                        response.onNext(ControlOuterClass.ReloadTokensResponse.newBuilder()
                                .setAppliedGeneration(request.getGeneration())
                                .setStatus(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK)
                                .build());
                        response.onCompleted();
                    }
                })));
            byte[] verifier = new byte[32];
            verifier[0] = 0x2a;
            try (ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
                var resp = client.reload(7, List.of(
                        ControlOuterClass.TokenVerifier.newBuilder()
                                .setVerifier(com.google.protobuf.ByteString.copyFrom(verifier))
                                .build()));
                assertEquals(ControlOuterClass.ApplyStatus.APPLY_STATUS_OK, resp.getStatus());
                assertEquals(7, resp.getAppliedGeneration());
            }
            // §5.1: the three metadata keys rode the call, lower-case, with
            // the §5.4 closed capability set — from the constants class.
            Metadata md = captured.get();
            assertNotNull(md, "the DP-stand-in must have captured headers");
            assertEquals(List.of("1"), all(md, StargateProtoVersion.META_MAJOR), "§5.1: major");
            assertEquals(List.of("0"), all(md, StargateProtoVersion.META_MINOR), "§5.1: minor");
            assertEquals(List.of("reload-tokens,watch-events,get-status-minimum"),
                    all(md, StargateProtoVersion.META_CAPABILITIES), "§5.4: closed capability set");
        }
    }

    // --- §4: wrong-key peers rejected at the handshake ------------------------------

    @Test
    void wrongKeyPeerRejectedBothDirections() throws Exception {
        Path keys = Files.createDirectories(tmp.resolve("keys-wrongkey"));
        var cp = ed25519();
        var dp = ed25519();
        Path cpPriv = writePrivateKey(keys, "cp.priv", cp);
        Path cpPub = writePublicKey(keys, "cp.pub", cp);
        Path dpPriv = writePrivateKey(keys, "dp.priv", dp);
        Path dpPub = writePublicKey(keys, "dp.pub", dp);

        // (a) CP client pins a WRONG peer key: the dp.sock handshake aborts.
        // The mock DP's cert key is legitimate, but the client's pin file has
        // been replaced with a rogue key (§6.2-style rotation gone wrong).
        Path dpSock = tmp.resolve("ipc-wrongkey").resolve("dp.sock");
        Files.createDirectories(dpSock.getParent());
        var rogueKey = ed25519();
        Path roguePub = writePublicKey(tmp, "rogue.pub", rogueKey);
        try (Stack stack = new Stack()) {
            stack.add(MockServer.start(NettyServerBuilder
                .forAddress((java.net.SocketAddress) new DomainSocketAddress(dpSock.toString()))
                .sslContext(CpTls.serverContext(dpIdentity(dp.getPrivate(), dp.getPublic()), cpPub))
                .addService(new ControlGrpc.ControlImplBase() {
                })));
            try (ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock, roguePub)) {
                StatusRuntimeException err = assertThrows(StatusRuntimeException.class,
                        () -> client.reload(1, List.of()),
                        "§3.3: a peer that does not present the pinned key must be rejected");
                assertEquals(Status.Code.UNAVAILABLE, err.getStatus().getCode(),
                        "the handshake abort surfaces as UNAVAILABLE");
            }
        }

        // (b) Rogue client against the CP server: the CP pins its clients
        // against dp.pub; a caller presenting any other identity cert is
        // aborted before the WatchEvents handler runs.
        Path sock = tmp.resolve("ipc-wrongkey-cp").resolve("control.sock");
        Files.createDirectories(sock.getParent());
        var service = new ControlGrpcService();
        try (Stack stack = new Stack()) {
            stack.add(service.startServer(sock, cpPriv, cpPub, dpPub));
            var rogue = ed25519();
            var rogueGroup = new io.netty.channel.epoll.EpollEventLoopGroup(1);
            stack.add(rogueGroup::shutdownGracefully);
            ManagedChannel rogueChannel = NettyChannelBuilder
                    .forAddress((java.net.SocketAddress) new DomainSocketAddress(sock.toString()))
                    .channelType(io.netty.channel.epoll.EpollDomainSocketChannel.class)
                    .eventLoopGroup(rogueGroup)
                    .sslContext(io.grpc.netty.GrpcSslContexts.forClient()
                            .keyManager(rogue.getPrivate(),
                                    CpTls.deriveSelfSigned(rogue.getPrivate(),
                                            rogue.getPublic(), DP_CN, DP_SPIFFE,
                                            Instant.now().truncatedTo(ChronoUnit.SECONDS)))
                            .trustManager(CpTls.peerPinTrustManager(cpPub))
                            .protocols("TLSv1.3")
                            .build())
                    .build();
            stack.add(() -> {
                rogueChannel.shutdownNow();
                rogueChannel.awaitTermination(5, SECONDS);
            });
            Iterator<EventsOuterClass.SidecarEvent> it = EventsGrpc
                    .newBlockingStub(rogueChannel)
                    .withDeadlineAfter(5, SECONDS)
                    .watchEvents(EventsOuterClass.WatchEventsRequest.getDefaultInstance());
            StatusRuntimeException err = assertThrows(StatusRuntimeException.class, it::next,
                    "§3.3: the CP server must abort a rogue client's handshake");
            assertEquals(Status.Code.UNAVAILABLE, err.getStatus().getCode());
            waitUntil("the rogue call to have drained", Duration.ofSeconds(5),
                    () -> service.activeStreams() == 0);
        }
    }

    // --- §5.2 newer-major journal record ------------------------------------------

    @Test
    void newerMajorRejectionJournaled() {
        // wire-auth.md §5.2 (arch §5.5 row 4): the newer-peer rejection is
        // logged to the journal — the record carries the peer major.
        List<String> records = new java.util.ArrayList<>();
        StargateProtoVersion.journalSinkForTests = records::add;
        try {
            Metadata headers = new Metadata();
            headers.put(StargateProtoVersion.META_MAJOR, "2");
            Status rejection = StargateProtoVersion.checkProtoVersion(headers);
            assertEquals(Status.Code.FAILED_PRECONDITION, rejection.getCode(),
                    "the newer-major rejection stays FailedPrecondition");
            assertEquals(1, records.size(), "exactly one journal record for the rejection");
            assertTrue(records.get(0).contains("peer major 2"),
                    "the journal record must carry the peer major");
        } finally {
            StargateProtoVersion.journalSinkForTests = null;
        }
    }

    // --- close() hygiene ------------------------------------------------------------

    @Test
    void closeLeavesNoPhantomInterrupt() throws Exception {
        // close() on a normally-terminating channel must not set the caller's
        // interrupt flag (the InterruptedException catch clause is the only
        // legitimate flag-setter).
        Path keys = Files.createDirectories(tmp.resolve("keys-close"));
        var cp = ed25519();
        writePrivateKey(keys, "cp.priv", cp);
        writePublicKey(keys, "cp.pub", cp);
        writePublicKey(keys, "dp.pub", ed25519());
        Path dpSock = tmp.resolve("ipc-close").resolve("dp.sock");
        Files.createDirectories(dpSock.getParent());
        try (ReloadTokensClient client = ReloadTokensClient.create(keys, dpSock)) {
            // no RPC: the lazy channel still terminates promptly on close
        }
        assertFalse(Thread.currentThread().isInterrupted(),
                "close() must leave no phantom interrupt on the caller's thread");
    }
}
