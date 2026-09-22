// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

/** Real Go/Java TLS + RPC contracts over UDS, with synthetic local identities. */
class CrossPlaneTlsTest {
    @TempDir static Path build;
    @TempDir Path tmp;
    static Path peer;

    @BeforeAll static void buildGoPeer() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (!Files.exists(root.resolve("go.work"))) { root = root.getParent(); }
        peer = build.resolve("tlspeer");
        var process = new ProcessBuilder("go", "build", "-o", peer.toString(),
                "./data-plane/internal/controlclient/testdata/tlspeer")
                .directory(root.toFile()).redirectErrorStream(true)
                .redirectOutput(build.resolve("build.log").toFile()).start();
        try {
            assertTrue(process.waitFor(120, TimeUnit.SECONDS), "Go peer build timed out");
            assertEquals(0, process.exitValue(), Files.readString(build.resolve("build.log")));
        } finally { process.destroyForcibly(); }
    }

    void seed() throws Exception {
        for (String role : List.of("cp", "dp")) {
            var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            pem(tmp.resolve(role + ".priv"), "PRIVATE KEY", key.getPrivate().getEncoded());
            pem(tmp.resolve(role + ".pub"), "PUBLIC KEY", key.getPublic().getEncoded());
        }
    }
    static void pem(Path path, String type, byte[] bytes) throws Exception {
        Files.writeString(path, "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder().encodeToString(bytes) + "\n-----END " + type + "-----\n");
    }
    Process go(String mode, Path socket, String date, Path output) throws Exception {
        return new ProcessBuilder(peer.toString(), mode, tmp.toString(), socket.toString(), date)
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
    }
    void ready(Process process, Path socket) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!Files.exists(socket) && process.isAlive() && System.nanoTime() < deadline) { Thread.sleep(10); }
        assertTrue(Files.exists(socket), "Go server must bind socket");
    }
    void stop(Process process) throws Exception {
        process.getOutputStream().write('\n'); process.getOutputStream().flush();
        if (!process.waitFor(3, TimeUnit.SECONDS)) { process.destroyForcibly(); }
    }

    @Test void javaServerRejectsInvalidAndReplacedPinsIncludingTicketOffers() throws Exception {
        seed(); Path socket = tmp.resolve("cp.sock"); Path output = tmp.resolve("probe.log");
        var service = new ControlGrpcService();
        try (var server = service.startServer(socket, tmp.resolve("cp.priv"), tmp.resolve("cp.pub"), tmp.resolve("dp.pub"))) {
            var probe = go("probe", socket, "current", output);
            try {
                assertTrue(probe.waitFor(20, TimeUnit.SECONDS), "Go probe timed out");
                assertEquals(0, probe.exitValue(), Files.readString(output));
                assertTrue(Files.readString(output).contains("PASS"));
                assertEquals(0, service.activeStreams());
            } finally { probe.destroyForcibly(); }
        }
    }

    @Test void serverClosesGoPeerThatIgnoresGoAwayPing() throws Exception {
        seed(); Path socket = tmp.resolve("stubborn.sock"); Path output = tmp.resolve("stubborn.log");
        try (var server = new ControlGrpcService().startServer(socket, tmp.resolve("cp.priv"),
                tmp.resolve("cp.pub"), tmp.resolve("dp.pub"), Duration.ofSeconds(1))) {
            var probe = go("hold", socket, "current", output);
            try {
                assertTrue(probe.waitFor(20, TimeUnit.SECONDS), "uncooperative peer probe timed out");
                assertEquals(0, probe.exitValue(), Files.readString(output));
                assertTrue(Files.readString(output).contains("PASS"));
            } finally { probe.destroyForcibly(); }
        }
    }

    @Test void javaClientRejectsDatedGoServersAndReconnectsWithFreshAuthorization() throws Exception {
        seed();
        for (String date : List.of("expired", "future", "current")) {
            Path socket = tmp.resolve(date + ".sock");
            var server = go("serve", socket, date, tmp.resolve(date + ".log"));
            try {
                ready(server, socket);
                try (var client = ReloadTokensClient.create(tmp, socket)) {
                    if (!date.equals("current")) {
                        assertThrows(io.grpc.StatusRuntimeException.class, () -> client.reload(1, List.of()));
                    } else {
                        for (int generation = 1; generation <= 3; generation++) {
                            assertEquals(generation, client.reload(generation, List.of()).getAppliedGeneration());
                            Thread.sleep(800); // Go server forces reconnect on the SAME Java ManagedChannel.
                        }
                    }
                }
            } finally { stop(server); }
        }
        var handshakes = Files.readAllLines(tmp.resolve("handshakes"));
        assertTrue(handshakes.size() >= 3, "must exercise multiple real handshakes");
        assertTrue(handshakes.stream().noneMatch("true"::equals), "Java must not reuse sessions across engines");
    }
    @Test void finalizedCountersDecodeAcrossJavaGoTransition() throws Exception {
        seed();
        Path socket = tmp.resolve("counters.sock");
        var server = new ProcessBuilder(peer.toString(), "counters", tmp.toString(), socket.toString(), "current")
                .redirectError(tmp.resolve("counter-error.log").toFile()).start();
        var group = new io.netty.channel.epoll.EpollEventLoopGroup(1);
        io.grpc.ManagedChannel channel = null;
        try {
            var output = server.inputReader();
            assertEquals("READY", peerLine(server, output));
            var identity = CpTls.deriveCpIdentity(tmp.resolve("cp.priv"), tmp.resolve("cp.pub"));
            channel = io.grpc.netty.NettyChannelBuilder
                    .forAddress(new io.netty.channel.unix.DomainSocketAddress(socket.toString()))
                    .channelType(io.netty.channel.epoll.EpollDomainSocketChannel.class)
                    .eventLoopGroup(group).sslContext(CpTls.clientContext(identity, tmp.resolve("dp.pub")))
                    .intercept(StargateProtoVersion.clientVersionInterceptor()).build();
            var client = stargate.v1.ControlGrpc.newBlockingStub(channel);
            var request = stargate.v1.ControlOuterClass.StatusRequest.getDefaultInstance();
            for (int i = 0; i < 8; i++) {
                counterCommand(server, output, "traffic");
                assertEquals(0, client.withDeadlineAfter(3, TimeUnit.SECONDS).getStatus(request).getCountersCount());
            }
            counterCommand(server, output, "advance");
            var completed = client.withDeadlineAfter(3, TimeUnit.SECONDS).getStatus(request);
            assertEquals(1, completed.getCountersCount());
            var row = completed.getCounters(0);
            assertEquals("TOR", row.getRoute());
            assertEquals(496810, row.getHourBucket());
            assertEquals(8, row.getRequestCount());
            assertEquals(104, row.getByteCount());
            counterCommand(server, output, "rollback");
            counterCommand(server, output, "traffic");
            for (int i = 0; i < 8; i++) {
                assertEquals(completed, client.withDeadlineAfter(3, TimeUnit.SECONDS).getStatus(request));
            }
            counterCommand(server, output, "expire");
            assertEquals(0, client.withDeadlineAfter(3, TimeUnit.SECONDS).getStatus(request).getCountersCount());
            assertEquals(1, stargate.v1.ControlOuterClass.StatusResponse.getDescriptor().getFields().size());
            assertEquals(4, stargate.v1.ControlOuterClass.RouteCounter.getDescriptor().getFields().size());
        } finally {
            if (channel != null) { channel.shutdownNow().awaitTermination(3, TimeUnit.SECONDS); }
            group.shutdownGracefully().syncUninterruptibly();
            server.destroyForcibly(); server.waitFor(3, TimeUnit.SECONDS);
        }
    }

    static String peerLine(Process peer, java.io.BufferedReader output) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!output.ready() && peer.isAlive() && System.nanoTime() < deadline) { Thread.sleep(10); }
        assertTrue(output.ready(), "Go peer did not acknowledge command");
        return output.readLine();
    }

    static void counterCommand(Process peer, java.io.BufferedReader output, String command) throws Exception {
        peer.getOutputStream().write((command + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        peer.getOutputStream().flush();
        assertEquals("OK", peerLine(peer, output));
    }

}
