// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Supplier;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;

import stargate.v1.ControlGrpc;
import stargate.v1.ControlOuterClass.ReloadTokensRequest;
import stargate.v1.ControlOuterClass.ReloadTokensResponse;
import stargate.v1.ControlOuterClass.TokenVerifier;

/**
 * The control plane's ReloadTokens gRPC client (T038) — the CP half of the
 * token push: it dials the DP-HOSTED Control service on
 * {@code /run/stargate/dp.sock} ({@code contracts/control-grpc.md}
 * §"ReloadTokens": direction CP→DP, so the DP is the server; T045 hosts it)
 * and pushes token generations. {@code StargateControlPlane} (T041) is the
 * production caller.
 *
 * <p>The CP does NOT host ReloadTokens — role separation via {@code bind(2)}
 * (§"Socket topology"); this class dials only dp.sock and invokes only
 * ReloadTokens (the CP has no production GetStatus caller in v1 — T022 row
 * 10 gates that). The §4 mutual-TLS configuration and the §5.3 client
 * interceptor are installed here on the ONLY channel this class can produce,
 * so no call can bypass them (wire-auth.md §4/§5.3).
 *
 * <p>Per-call semantics are the DP server's contract: atomic swap,
 * stale-generation rejection with the T092 {@code current_generation}
 * reconciliation field, {@code APPLY_STATUS_*} — this class passes requests
 * and responses through verbatim and never inspects verifier bytes (those
 * come from the T035 loader, already HMAC tags — this client treats them as
 * opaque 32-byte blobs).
 */
public final class ReloadTokensClient implements AutoCloseable {

    /** Push deadline: a hung inter-plane push must not block the CP's boot
     * sequence indefinitely (T041 pushes during startup). Transport policy,
     * not wire shape. */
    private static final long DEADLINE_SECONDS = 10;

    private ManagedChannel channel;
    private final Supplier<ManagedChannel> channelFactory;
    private final EventLoopGroup eventLoopGroup;
    private final Duration lifetime;
    private boolean closed;

    private ReloadTokensClient(Supplier<ManagedChannel> channelFactory, EventLoopGroup eventLoopGroup,
            Duration lifetime) {
        this.channelFactory = channelFactory;
        this.eventLoopGroup = eventLoopGroup;
        this.lifetime = lifetime;
        this.channel = openChannel();
    }

    private ManagedChannel openChannel() {
        ManagedChannel opened = channelFactory.get();
        // Local forced shutdown: an uncooperative server cannot retain an
        // authenticated connection indefinitely (wire-auth §2.4).
        var expiry = eventLoopGroup.next().schedule(opened::shutdownNow, lifetime.toNanos(), TimeUnit.NANOSECONDS);
        expiry.addListener(result -> {
            if (!result.isSuccess()) { opened.shutdownNow(); }
        });
        return opened;
    }

    private synchronized ManagedChannel currentChannel() {
        if (closed) { throw new IllegalStateException("reload client is closed"); }
        if (channel.isShutdown()) { channel = openChannel(); }
        return channel;
    }

    /**
     * Builds the client: derives the CP identity from the keyfile pair
     * (§2.1 startup errors propagate — the CP fails fast), pins the peer
     * against {@code keysDir/dp.pub} (§3), and installs the §5.3 client
     * interceptor (the three version metadata keys on every call). No I/O
     * happens until the first call — gRPC connects lazily.
     *
     * @param keysDir the stargate-keys volume ({@code /etc/stargate/keys})
     * @param dpSock  the DP-hosted socket ({@code /run/stargate/dp.sock})
     */
    public static ReloadTokensClient create(java.nio.file.Path keysDir, java.nio.file.Path dpSock) {
        return create(keysDir, dpSock, keysDir.resolve("dp.pub"));
    }

    /** Test seam: an overridden peer-pin path (the §3.3 wrong-key scenario). */
    static ReloadTokensClient create(java.nio.file.Path keysDir, java.nio.file.Path dpSock,
            java.nio.file.Path peerPinPath) {
        return create(keysDir, dpSock, peerPinPath, java.time.Duration.ofSeconds(55));
    }

    static ReloadTokensClient create(Path keysDir, Path dpSock, Path peerPinPath,
            java.time.Duration lifetime) {
        CpTls.Identity identity = CpTls.deriveCpIdentity(
                keysDir.resolve("cp.priv"), keysDir.resolve("cp.pub"));
        // grpc-netty requires all-or-nothing (group, channelType): a domain-
        // socket channel NEEDS the explicit group, and a builder-provided
        // group is caller-owned — closed in close().
        var tls = CpTls.clientContext(identity, peerPinPath);
        EventLoopGroup group = new EpollEventLoopGroup(1);
        Supplier<ManagedChannel> channelFactory = () -> NettyChannelBuilder
                .forAddress((SocketAddress) new DomainSocketAddress(dpSock.toString()))
                // grpc-netty's default channel type is the INET epoll channel;
                // a unix socket address NEEDS the domain variant (wire-auth §4
                // UDS authority) or connect fails EAFNOSUPPORT.
                .channelType(EpollDomainSocketChannel.class)
                .eventLoopGroup(group)
                .sslContext(tls)
                .intercept(StargateProtoVersion.clientVersionInterceptor())
                .build();
        return new ReloadTokensClient(channelFactory, group, lifetime);
    }

    /**
     * Pushes one token generation to the DP. Throws {@link StatusRuntimeException}
     * on transport/handshake failure (UNAVAILABLE) or deadline exhaustion —
     * callers (T041) decide the retry policy; no retry lives here.
     *
     * @param generation the CP's proposed generation (persisted last + 1)
     * @param tokens     the HMAC-SHA-256 verifiers, opaque to this client
     * @return the DP's response — {@code applied_generation}, {@code status},
     *         and the T092 {@code current_generation} reconciliation field
     */
    public ReloadTokensResponse reload(long generation, List<TokenVerifier> tokens) {
        ReloadTokensRequest request = ReloadTokensRequest.newBuilder()
                .setGeneration(generation)
                .addAllTokens(tokens)
                .build();
        return ControlGrpc.newBlockingStub(currentChannel()).withDeadlineAfter(DEADLINE_SECONDS, TimeUnit.SECONDS)
                .reloadTokens(request);
    }

    @Override
    public synchronized void close() {
        closed = true;
        channel.shutdownNow();
        try {
            // A stubborn channel must not plant a phantom interrupt on the
            // caller's thread — at close() time the process teardown makes it
            // moot; only a REAL interrupt (the catch below) sets the flag.
            channel.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        eventLoopGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                .awaitUninterruptibly(5, TimeUnit.SECONDS);
    }
}
