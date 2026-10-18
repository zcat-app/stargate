// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import app.zcat.stargate.auth.TokenLoaderContract;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;
import io.quarkus.stargate.control.grpc.ControlGrpcService;
import io.quarkus.stargate.control.grpc.CpTls;
import io.quarkus.stargate.control.grpc.StargateProtoVersion;
import stargate.v1.ControlGrpc;
import stargate.v1.ControlOuterClass.*;

/** Wire-auth §5.2: exercise production bootstrap through authenticated TLS/UDS. */
class PeerVersionStartupTest {
    @TempDir Path tmp;
    private final AtomicInteger intercepted = new AtomicInteger();
    private final AtomicInteger dispatched = new AtomicInteger();

    @ParameterizedTest
    @ValueSource(ints = {0, 2})
    void incompatiblePeerAbortsStartupWithRedactedError(int peerMajor) throws Exception {
        var cfg = config();
        try (var peer = peer(cfg, peerMajor, Status.FAILED_PRECONDITION)) {
            var error = assertThrows(IllegalStateException.class, () -> {
                try (var boot = boot(cfg)) {
                    // Close a mistakenly successful boot even when the regression fails.
                }
            });
            assertEquals("INCOMPATIBLE_PEER_VERSION", error.getMessage());
            assertNull(error.getCause(), "peer descriptions/trailers must not survive in a cause chain");
            assertEquals(0, error.getSuppressed().length);
            assertEquals(1, intercepted.get(), "no retry or downgrade after version rejection");
            assertEquals(0, dispatched.get(), "version rejection precedes application dispatch");
            // Startup failure must release the CP listener, not leave a partially running CP.
            assertFalse(Files.exists(cfg.controlSock()));
            try (var rebound = new ControlGrpcService().startServer(cfg.controlSock(),
                    tmp.resolve("cp.priv"), tmp.resolve("cp.pub"), tmp.resolve("dp.pub"))) {
                assertNotNull(rebound);
            }
        }
    }

    @Test
    void transientPeerOutageStillAllowsStartup() throws Exception {
        var cfg = config();
        try (var peer = peer(cfg, StargateProtoVersion.MAJOR, Status.UNAVAILABLE);
                var boot = boot(cfg)) {
            assertNotNull(boot);
            assertEquals(1, intercepted.get());
            assertEquals(0, dispatched.get());
        }
    }

    @Test
    void compatiblePeerStillDispatchesStartupPush() throws Exception {
        var cfg = config();
        try (var peer = peer(cfg, StargateProtoVersion.MAJOR, Status.OK);
                var boot = boot(cfg)) {
            assertNotNull(boot);
            assertEquals(1, intercepted.get());
            assertEquals(1, dispatched.get());
        }
    }

    private StargateControlPlane.BootHandle boot(StargateControlPlane.BootConfig cfg) throws Exception {
        var state = new State();
        return StargateControlPlane.bootstrap(cfg, (action, target, detail) -> {
            fail("valid empty input and version failures must not create operational detail records");
        }, state, state);
    }

    private StargateControlPlane.BootConfig config() throws Exception {
        for (String role : List.of("cp", "dp")) {
            var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            pem(tmp.resolve(role + ".priv"), "PRIVATE KEY", pair.getPrivate().getEncoded());
            pem(tmp.resolve(role + ".pub"), "PUBLIC KEY", pair.getPublic().getEncoded());
        }
        Files.write(tmp.resolve("pepper.key"), new byte[32]);
        Files.writeString(tmp.resolve("tokens.yaml"), "tokens: []\n");
        return new StargateControlPlane.BootConfig(tmp.resolve("tokens.yaml"), tmp.resolve("pepper.key"),
                tmp, tmp.resolve("control.sock"), tmp.resolve("dp.sock"), tmp.resolve("observer.sock"),
                Duration.ofSeconds(10));
    }

    private static void pem(Path path, String type, byte[] bytes) throws Exception {
        Files.writeString(path, "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(bytes)
                + "\n-----END " + type + "-----\n", StandardCharsets.US_ASCII);
    }

    private AutoCloseable peer(StargateControlPlane.BootConfig cfg, int major, Status status) throws Exception {
        var identity = CpTls.deriveCpIdentity(tmp.resolve("dp.priv"), tmp.resolve("dp.pub"));
        var group = new EpollEventLoopGroup(2);
        io.grpc.Server server;
        try {
            server = NettyServerBuilder.forAddress(new DomainSocketAddress(cfg.dpSock().toString()))
                    .bossEventLoopGroup(group).workerEventLoopGroup(group)
                    .channelType(EpollServerDomainSocketChannel.class)
                    .sslContext(CpTls.serverContext(identity, tmp.resolve("cp.pub")))
                    .addService(new ControlGrpc.ControlImplBase() {
                        @Override
                        public void reloadTokens(ReloadTokensRequest request,
                                StreamObserver<ReloadTokensResponse> observer) {
                            dispatched.incrementAndGet();
                            observer.onNext(ReloadTokensResponse.newBuilder()
                                    .setStatus(ApplyStatus.APPLY_STATUS_OK)
                                    .setAppliedGeneration(request.getGeneration()).build());
                            observer.onCompleted();
                        }
                    })
                    .intercept(new ServerInterceptor() {
                        @Override
                        public <Q, S> ServerCall.Listener<Q> interceptCall(ServerCall<Q, S> call,
                                Metadata headers, ServerCallHandler<Q, S> next) {
                            intercepted.incrementAndGet();
                            assertEquals(Integer.toString(StargateProtoVersion.MAJOR),
                                    headers.get(StargateProtoVersion.META_MAJOR));
                            assertEquals(Integer.toString(StargateProtoVersion.MINOR),
                                    headers.get(StargateProtoVersion.META_MINOR));
                            assertEquals(StargateProtoVersion.CAPABILITIES,
                                    headers.get(StargateProtoVersion.META_CAPABILITIES));
                            if (major != StargateProtoVersion.MAJOR || !status.isOk()) {
                                var trailers = new Metadata();
                                trailers.put(Metadata.Key.of("peer-detail", Metadata.ASCII_STRING_MARSHALLER),
                                        "private-peer-trailer");
                                call.close(status.withDescription("private-peer-detail\nforged log entry"), trailers);
                                return new ServerCall.Listener<>() {};
                            }
                            return StargateProtoVersion.serverVersionInterceptor().interceptCall(call, headers, next);
                        }
                    }).build().start();
        } catch (Exception failure) {
            group.shutdownGracefully().sync();
            throw failure;
        }
        return () -> {
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
            group.shutdownGracefully().sync();
        };
    }

    private static final class State implements TokenLoaderContract.ConfiguredTokenStore,
            TokenLoaderContract.GenerationStore {
        private TokenLoaderContract.GenerationStore.DeliveryMarker delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0);
        @Override public Collection<TokenLoaderContract.StoredToken> storedTokens() { return List.of(); }
        @Override public void begin() {}
        @Override public void upsert(String label, byte[] verifier) {}
        @Override public void delete(String label) {}
        @Override public void commit() {}
        @Override public long lastGeneration() { return 0; }
        @Override public void record(long generation) {}
        @Override public TokenLoaderContract.GenerationStore.DeliveryMarker deliveryMarker() { return delivery; }
        @Override public boolean prearmDelivery(long generation) {
            if (delivery.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE
                    || (delivery.state() == TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                            && delivery.generation() != generation)) return false;
            delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED, generation);
            return true;
        }
        @Override public boolean acknowledgeDelivery(long generation) {
            if (delivery.state() != TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                    || delivery.generation() != generation) return false;
            delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.CLEAR, 0);
            return true;
        }
        @Override public boolean recordStaleDelivery(long generation) {
            if (delivery.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE)
                return delivery.generation() == generation;
            if (delivery.state() != TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                    || delivery.generation() != generation) return false;
            delivery = new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.STALE, generation);
            return true;
        }
    }
}
