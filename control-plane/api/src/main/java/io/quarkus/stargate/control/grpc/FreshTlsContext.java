// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import java.util.List;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolNegotiator;
import io.netty.handler.ssl.SslContext;

/**
 * wire-auth §2.4: grpc-netty constructs SslHandler directly from newEngine,
 * bypassing Netty's context-associated resumption controller. A separate JDK
 * context per engine prevents either role from reusing cached authorization.
 * Certificates remain renewable, in-memory identities; keys do not rotate.
 */
final class FreshTlsContext extends SslContext {
    private final Supplier<SslContext> factory;
    private final SslContext metadata;

    FreshTlsContext(Supplier<SslContext> factory) {
        this.factory = factory;
        this.metadata = factory.get();
    }

    @Override public boolean isClient() { return metadata.isClient(); }
    @Override public List<String> cipherSuites() { return metadata.cipherSuites(); }
    @Override public ApplicationProtocolNegotiator applicationProtocolNegotiator() {
        return metadata.applicationProtocolNegotiator();
    }
    @Override public SSLSessionContext sessionContext() { return metadata.sessionContext(); }
    @Override public SSLEngine newEngine(ByteBufAllocator allocator) {
        return factory.get().newEngine(allocator);
    }
    @Override public SSLEngine newEngine(ByteBufAllocator allocator, String host, int port) {
        return factory.get().newEngine(allocator, host, port);
    }
}
