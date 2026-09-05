// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;

import io.grpc.Server;
import io.grpc.Status;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.EpollServerDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;
import io.netty.channel.epoll.EpollEventLoopGroup;

import stargate.v1.EventsGrpc;
import stargate.v1.EventsOuterClass.SidecarEvent;
import stargate.v1.EventsOuterClass.WatchEventsRequest;

/**
 * The control plane's WatchEvents gRPC server (T038) — the CP half of the
 * inter-plane wire contract, on the CP-owned {@code /run/stargate/control.sock}
 * (mode 0660, owner {@code stargate-cp:stargate-ipc}; the ownership comes from
 * the process's deployment uid/gid, the mode is forced past any umask below —
 * {@code contracts/control-grpc.md} §"Socket topology", verified by R1 in
 * {@code tests/contract/compose/inter_plane_wire_test.sh} against the live
 * stack).
 *
 * <p>Role separation is via {@code bind(2)}: this server never binds dp.sock,
 * and nothing here accepts ReloadTokens — that server lives in the data plane
 * (T045) because the RPC direction is CP→DP (§"ReloadTokens").
 *
 * <p>The stream is LONG-LIVED (§"WatchEvents"): the handler registers the
 * peer and returns; events flow through {@link #publish} as the sidecar
 * monitor emits them (T039 wires the emitter). Events are advisory
 * status/audit hints — nothing on this channel gates data-plane forwarding
 * (Constitution Principle II; data-model.md §2).
 */
public final class ControlGrpcService extends EventsGrpc.EventsImplBase {

    private final Set<StreamObserver<SidecarEvent>> streams = new CopyOnWriteArraySet<>();

    @Override
    public void watchEvents(WatchEventsRequest request, StreamObserver<SidecarEvent> response) {
        streams.add(response);
        // Unregister when the peer goes away (cancel surfaces via the
        // ServerCallStreamObserver cancel hook, not via onNext/onError here —
        // the handler returned long ago).
        if (response instanceof ServerCallStreamObserver<SidecarEvent> call) {
            call.setOnCancelHandler(() -> streams.remove(response));
        }
    }

    /**
     * Fans one event out to every live WatchEvents stream. A delivery failure
     * (peer vanished mid-write) drops that stream from the set; the peer
     * re-dials with the §"WatchEvents" backoff. Publishing is advisory —
     * callers must never gate admission on it (Principle II).
     */
    public void publish(SidecarEvent event) {
        for (StreamObserver<SidecarEvent> stream : streams) {
            try {
                stream.onNext(event);
            } catch (RuntimeException e) {
                streams.remove(stream);
                try {
                    stream.onError(Status.UNAVAILABLE.withDescription("event stream broken").asException());
                } catch (RuntimeException ignored) {
                    // the stream is gone either way; the peer re-dials
                }
            }
        }
    }

    /** Test seam: how many WatchEvents streams the handler has accepted. */
    int activeStreams() {
        return streams.size();
    }

    /**
     * Builds, binds, and starts the CP gRPC server on {@code controlSockPath}
     * (UDS ONLY — wire-auth.md §4; arch §5.4: no TCP surface exists). The
     * §5.3 version interceptor is installed on the ONLY server shape this
     * class can produce, so no handler can ever run un-gated (§5.3).
     *
     * @param controlSockPath the unix socket path to bind (deleted stale
     *                        sockets are the entrypoint's deployment concern,
     *                        mirroring the DP's {@code net.Listen} semantics)
     * @param cpPriv          the plane's private key (§6.1: {@code cp.priv})
     * @param cpPub           the matching public key (§6.1: {@code cp.pub})
     * @param dpPub           the pinned peer key (§6.1: {@code dp.pub})
     * @return the bound server; the caller owns {@link BoundServer#close()}
     */
    public BoundServer startServer(Path controlSockPath, Path cpPriv, Path cpPub, Path dpPub)
            throws IOException {
        CpTls.Identity identity = CpTls.deriveCpIdentity(cpPriv, cpPub);
        // grpc-netty requires all-or-nothing (boss, worker, channelType):
        // a domain-socket channel NEEDS the explicit groups, and
        // builder-provided groups are caller-owned (FixedObjectPool), so the
        // groups are shut down in BoundServer.close().
        EventLoopGroup boss = new EpollEventLoopGroup(1);
        EventLoopGroup workers = new EpollEventLoopGroup();
        Server server;
        try {
            server = NettyServerBuilder
                    .forAddress((SocketAddress) new DomainSocketAddress(controlSockPath.toString()))
                    // grpc-netty's default channel type is the INET epoll
                    // channel; a unix socket address NEEDS the domain variant
                    // (wire-auth §4 UDS authority) or bind fails EAFNOSUPPORT.
                    .channelType(EpollServerDomainSocketChannel.class)
                    .bossEventLoopGroup(boss)
                    .workerEventLoopGroup(workers)
                    .sslContext(CpTls.serverContext(identity, dpPub))
                    .intercept(StargateProtoVersion.serverVersionInterceptor())
                    .addService(this)
                    .build()
                    .start();
        } catch (IOException | RuntimeException e) {
            shutdownGracefully(boss, workers);
            throw e;
        }
        try {
            // §"Socket topology": mode 0660 — the shared stargate-ipc group
            // can dial; non-group same-host processes cannot (the kernel gate
            // R3 pins). Forced past the umask, mirroring the DP's os.Chmod.
            Files.setPosixFilePermissions(controlSockPath,
                    PosixFilePermissions.fromString("rw-rw----"));
        } catch (IOException e) {
            server.shutdownNow();
            shutdownGracefully(boss, workers);
            throw e;
        }
        return new BoundServer(server, boss, workers);
    }

    private static void shutdownGracefully(EventLoopGroup boss, EventLoopGroup workers) {
        boss.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
        workers.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
    }

    /** The started inter-plane listener plus the Netty groups it runs on —
     * one AutoCloseable so the caller's shutdown is total (the grpc Server
     * does not stop builder-provided event loop groups). */
    public static final class BoundServer implements AutoCloseable {
        private final Server server;
        private final EventLoopGroup boss;
        private final EventLoopGroup workers;

        private BoundServer(Server server, EventLoopGroup boss, EventLoopGroup workers) {
            this.server = server;
            this.boss = boss;
            this.workers = workers;
        }

        /** The underlying grpc Server (port introspection, awaitTermination). */
        public Server server() {
            return server;
        }

        @Override
        public void close() {
            server.shutdownNow();
            try {
                server.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            shutdownGracefully(boss, workers);
        }
    }
}
