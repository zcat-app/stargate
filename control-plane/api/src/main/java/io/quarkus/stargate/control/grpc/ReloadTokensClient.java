// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;

import com.google.protobuf.ByteString;

import stargate.v1.ControlGrpc;
import stargate.v1.ControlOuterClass.DurableAuthSet;
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
 * <p>Per-call semantics are the DP server's T159 durable-authority contract.
 * This client commits the opaque verifier multiset in the mandatory
 * auth-set-v1 envelope and keeps the legacy token list empty.
 */
public final class ReloadTokensClient implements AutoCloseable {

    /** Push deadline: a hung inter-plane push must not block the CP's boot
     * sequence indefinitely (T041 pushes during startup). Transport policy,
     * not wire shape. */
    private static final long DEADLINE_SECONDS = 10;
    private static final int AUTH_SET_VERSION = 1;

    private ChannelEpoch channel;
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

    private ChannelEpoch openChannel() {
        ManagedChannel opened = channelFactory.get();
        ChannelEpoch epoch = new ChannelEpoch(opened);
        // Local forced shutdown: an uncooperative server cannot retain an
        // authenticated connection indefinitely (wire-auth §2.4).
        var expiry = eventLoopGroup.next().schedule(
                () -> retireLocally(epoch), lifetime.toNanos(), TimeUnit.NANOSECONDS);
        expiry.addListener(result -> {
            if (!result.isSuccess()) { retireLocally(epoch); }
        });
        return epoch;
    }

    private synchronized void retireLocally(ChannelEpoch epoch) {
        if (closed || epoch.value.isShutdown()) {
            return;
        }
        // Mark the exact epoch before shutdown so reconnect observation can
        // distinguish our credential-lifetime rotation from a peer outage.
        epoch.locallyRetired = true;
        epoch.value.shutdownNow();
    }

    private synchronized ChannelEpoch currentEpoch() {
        if (closed) { throw new IllegalStateException("reload client is closed"); }
        if (channel.value.isShutdown()) { channel = openChannel(); }
        return channel;
    }

    private ManagedChannel currentChannel() {
        return currentEpoch().value;
    }

    /**
     * Registers an event-driven callback for authenticated-channel recovery.
     * The initial READY edge and this client's scheduled channel retirement
     * are deliberately ignored; only READY after a peer-side disconnect
     * counts as a reconnect. Calling {@link ManagedChannel#getState(boolean)}
     * keeps the local UDS channel attempting recovery without application-
     * level polling traffic.
     */
    public void onReconnect(Runnable callback) {
        ChannelEpoch watched = currentEpoch();
        ConnectivityState state = watched.value.getState(true);
        watchConnectivity(watched, state, state == ConnectivityState.READY, false, callback);
    }

    private void watchConnectivity(ChannelEpoch watched, ConnectivityState observed,
            boolean sawReady, boolean reconnectPending, Runnable callback) {
        watched.value.notifyWhenStateChanged(observed, () -> {
            ChannelEpoch active;
            synchronized (this) {
                if (closed) {
                    return;
                }
                active = currentEpoch();
            }
            ConnectivityState next = active.value.getState(true);
            boolean channelChanged = !active.equals(watched);
            boolean localReplacement = channelChanged && watched.locallyRetired;
            boolean peerDisconnected = sawReady
                    && ((!channelChanged && next != ConnectivityState.READY)
                            || (channelChanged && !watched.locallyRetired));
            boolean nextReconnectPending = reconnectPending || peerDisconnected;
            // A locally rotated channel establishes its own READY baseline.
            // Preserve a real outage already latched in reconnectPending, but
            // do not manufacture one from the replacement's IDLE/CONNECTING
            // states.
            boolean nextSawReady = (!localReplacement && sawReady)
                    || next == ConnectivityState.READY;
            if (next == ConnectivityState.READY && nextReconnectPending) {
                callback.run();
                nextReconnectPending = false;
            }
            watchConnectivity(active, next, nextSawReady, nextReconnectPending, callback);
        });
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

    /** One response paired with the exact commitment placed on its request. */
    public record ReloadAttempt(ReloadTokensResponse response, ByteString commitment) {
    }

    /**
     * Pushes one token generation to the DP. Throws {@link StatusRuntimeException}
     * on transport/handshake failure (UNAVAILABLE) or deadline exhaustion —
     * callers (T041) decide the retry policy; no retry lives here.
     *
     * @param generation the CP's proposed generation
     * @param tokens     the HMAC-SHA-256 verifiers, opaque to this client
     * @return the DP's exact durable-authority response
     */
    public ReloadTokensResponse reload(long generation, List<TokenVerifier> tokens) {
        return reloadAttempt(generation, tokens).response();
    }

    public ReloadAttempt reloadAttempt(long generation, List<TokenVerifier> tokens) {
        ByteString commitment = authSetCommitment(tokens);
        ReloadTokensRequest request = ReloadTokensRequest.newBuilder()
                .setGeneration(generation)
                .setDurable(DurableAuthSet.newBuilder()
                        .setSemanticsVersion(AUTH_SET_VERSION)
                        .setGeneration(generation)
                        .addAllTokens(tokens)
                        .setCommitment(commitment))
                .build();
        ReloadTokensResponse response = ControlGrpc.newBlockingStub(currentChannel())
                .withDeadlineAfter(DEADLINE_SECONDS, TimeUnit.SECONDS)
                .reloadTokens(request);
        return new ReloadAttempt(response, commitment);
    }

    /** control-grpc.md auth-set-v1 commitment; duplicates are preserved. */
    static ByteString authSetCommitment(List<TokenVerifier> tokens) {
        List<byte[]> members = new ArrayList<>(tokens.size());
        for (TokenVerifier token : tokens) {
            members.add(token.getVerifier().toByteArray());
        }
        members.sort(Arrays::compareUnsigned);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("stargate-auth-set-v1".getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) 0);
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(members.size()).array());
            for (byte[] member : members) {
                digest.update(member);
            }
            return ByteString.copyFrom(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new AssertionError("SHA-256 unavailable", unavailable);
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        channel.value.shutdownNow();
        try {
            // A stubborn channel must not plant a phantom interrupt on the
            // caller's thread — at close() time the process teardown makes it
            // moot; only a REAL interrupt (the catch below) sets the flag.
            channel.value.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        eventLoopGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                .awaitUninterruptibly(5, TimeUnit.SECONDS);
    }

    /** One physical channel lifetime; local retirement is epoch-specific. */
    private static final class ChannelEpoch {
        private final ManagedChannel value;
        private boolean locallyRetired;

        private ChannelEpoch(ManagedChannel value) {
            this.value = value;
        }
    }
}
