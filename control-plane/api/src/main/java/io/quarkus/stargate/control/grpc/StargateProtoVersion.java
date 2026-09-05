// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.MethodDescriptor;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.Status;

import java.lang.System.Logger.Level;
import java.util.function.Consumer;

/**
 * The control plane's compiled-in wire version — the single source location
 * for the version metadata a future {@code stargate.v2} bump touches exactly
 * once per binary ({@code contracts/wire-auth.md} §5.3; arch §5.3; T095).
 * The Go-side mirror is the DP's {@code internal/protoversion} package.
 *
 * <p>Everything here is consumed VERBATIM from wire-auth.md; no wire-shape
 * detail originates in this class. The major is derived from the proto
 * package ({@code stargate.v1} → 1), the minor is additive-only, and the
 * capability set is the §5.4 closed v1 set.
 */
public final class StargateProtoVersion {

    /** The {@code stargate.v1} package's major (§5.1). */
    public static final int MAJOR = 1;

    /** Additive minor — bumped per additive proto change, never gated (§5.2). */
    public static final int MINOR = 0;

    /** The §5.4 closed v1 capability set (advisory in v1; sent for v2's cut). */
    public static final String CAPABILITIES = "reload-tokens,watch-events,get-status-minimum";

    /** §5.1 metadata key: caller's compiled-in proto major (lowercase per HTTP/2). */
    public static final Metadata.Key<String> META_MAJOR =
            Metadata.Key.of("x-stargate-proto-major", Metadata.ASCII_STRING_MARSHALLER);

    /** §5.1 metadata key: caller's compiled-in proto minor. */
    public static final Metadata.Key<String> META_MINOR =
            Metadata.Key.of("x-stargate-proto-minor", Metadata.ASCII_STRING_MARSHALLER);

    /** §5.1 metadata key: caller's closed capability tokens, comma-separated. */
    public static final Metadata.Key<String> META_CAPABILITIES =
            Metadata.Key.of("x-stargate-capabilities", Metadata.ASCII_STRING_MARSHALLER);

    private StargateProtoVersion() {
    }

    /** The CP journal channel for §5.2/§5.5 row-4 mismatch records (the CP is
     * allowed to log; Principle I's no-log rule binds only the data plane). */
    private static final System.Logger JOURNAL = System.getLogger(StargateProtoVersion.class.getName());

    /** Test seam (package-private): when set, §5.2 newer-major journal records
     * go here instead of the system logger. Null in production. */
    static volatile @org.jspecify.annotations.Nullable Consumer<String> journalSinkForTests;

    /**
     * The §5.3 server interceptor (unary AND streaming — one grpc-java
     * interceptor shape covers both): runs the §5.2 rejection rule BEFORE any
     * application handler. An RPC that bypasses this interceptor (a service
     * registered outside the chain) is a contract violation — the server
     * bootstrap ({@link ControlGrpcService#startServer}) is the only shape
     * production code may boot, and it installs this interceptor first.
     */
    public static ServerInterceptor serverVersionInterceptor() {
        return new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                    ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                Status rejection = checkProtoVersion(headers);
                if (rejection != null) {
                    call.close(rejection, new Metadata());
                    // No handler runs; an empty listener closes nothing else.
                    return new ServerCall.Listener<>() {
                    };
                }
                return next.startCall(call, headers);
            }
        };
    }

    /**
     * The §5.2 rejection rule. Equal major accepts any minor (additive minors
     * are compatible, arch §5.3); the minor is not gated. Messages match the
     * DP's Go interceptor so both planes' journals carry the same shape.
     *
     * @return the rejection status, or {@code null} when the RPC is accepted
     */
    static @org.jspecify.annotations.Nullable Status checkProtoVersion(Metadata headers) {
        String value = headers.get(META_MAJOR);
        if (value == null) {
            return Status.FAILED_PRECONDITION
                    .withDescription("stargate: missing x-stargate-proto-major metadata");
        }
        long peerMajor;
        try {
            peerMajor = Long.parseLong(value);
        } catch (NumberFormatException e) {
            return Status.FAILED_PRECONDITION
                    .withDescription("stargate: x-stargate-proto-major is not parseable as uint");
        }
        if (peerMajor < MAJOR) {
            return Status.FAILED_PRECONDITION
                    .withDescription("stargate: peer major " + peerMajor + " < server major " + MAJOR);
        }
        if (peerMajor > MAJOR) {
            // arch §5.5 row 4: a newer peer is rejected, logged to the journal,
            // and never downgraded to. On the CP-as-client this rejection
            // surfaces as a startup error (T041's boot path).
            journal("stargate: rejected newer peer major " + peerMajor + " > server major " + MAJOR
                    + " (wire-auth.md §5.2 / arch §5.5 row 4)");
            return Status.FAILED_PRECONDITION
                    .withDescription("stargate: peer major " + peerMajor + " > server major " + MAJOR);
        }
        return null;
    }

    /** One journal record for the §5.2 newer-major rejection path. */
    private static void journal(String record) {
        Consumer<String> sink = journalSinkForTests;
        if (sink != null) {
            sink.accept(record);
        } else {
            JOURNAL.log(Level.WARNING, record);
        }
    }

    /**
     * The §5.3 client interceptor: sets the three §5.1 metadata keys on EVERY
     * call (unary AND streaming — the start() hook is shape-independent),
     * from the compiled-in constants above.
     */
    public static ClientInterceptor clientVersionInterceptor() {
        return new ClientInterceptor() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
                    MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
                return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
                    @Override
                    public void start(ClientCall.Listener<RespT> listener, Metadata headers) {
                        headers.put(META_MAJOR, Integer.toString(MAJOR));
                        headers.put(META_MINOR, Integer.toString(MINOR));
                        headers.put(META_CAPABILITIES, CAPABILITIES);
                        super.start(listener, headers);
                    }
                };
            }
        };
    }
}
