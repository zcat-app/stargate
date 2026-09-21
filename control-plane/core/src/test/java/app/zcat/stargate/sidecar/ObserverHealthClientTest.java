// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.sidecar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Socket-level refusals for CP's authenticated, finite-token health edge. */
class ObserverHealthClientTest {

    @TempDir Path dir;

    private enum Reply {
        READY, WRONG_PIN, FORGED_PROOF, WRONG_HELLO_VERSION, WRONG_PROOF_VERSION,
        CLOSE_MID_HELLO, CLOSE_MID_PROOF, BAD_TOKEN, OVERSIZED_TOKEN,
        TRUNCATED_TOKEN, MISSING_EOF, STALL_HELLO, STALL_REPLY
    }

    @Test
    void rejectsInvalidObserverIdentityVersionsAndFramesThenRecovers() throws Exception {
        for (Reply reply : Reply.values()) {
            if (reply == Reply.READY || reply == Reply.MISSING_EOF
                    || reply == Reply.STALL_HELLO || reply == Reply.STALL_REPLY) {
                continue;
            }
            assertSample(reply, SidecarMonitor.Health.UNAVAILABLE);
        }
        assertSample(Reply.READY, SidecarMonitor.Health.READY);
    }

    @Test
    void absentReplyEofAndStalledPeersRespectSixSecondBudget() throws Exception {
        for (Reply reply : new Reply[] {Reply.MISSING_EOF, Reply.STALL_HELLO, Reply.STALL_REPLY}) {
            long start = System.nanoTime();
            assertSample(reply, SidecarMonitor.Health.UNAVAILABLE);
            assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(7)) < 0,
                    reply + " exceeded the six-second client call budget");
        }
        assertSample(Reply.READY, SidecarMonitor.Health.READY);
    }

    private void assertSample(Reply reply, SidecarMonitor.Health expected) throws Exception {
        Path socket = dir.resolve(reply.name() + ".sock");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair cp = generator.generateKeyPair();
        KeyPair observer = generator.generateKeyPair();
        KeyPair other = generator.generateKeyPair();
        Path cpPrivate = dir.resolve(reply.name() + "-cp.priv");
        Path observerPublic = dir.resolve(reply.name() + "-observer.pub");
        writePem(cpPrivate, "PRIVATE KEY", cp.getPrivate().getEncoded());
        writePem(observerPublic, "PUBLIC KEY",
                (reply == Reply.WRONG_PIN ? other : observer).getPublic().getEncoded());

        try (FakeObserver fake = new FakeObserver(socket, reply, observer, other)) {
            ObserverHealthClient client = new ObserverHealthClient(socket, cpPrivate, observerPublic);
            assertEquals(expected, client.sample(), reply.name());
        }
    }

    private static void writePem(Path path, String type, byte[] der) throws IOException {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + body + "\n-----END "
                + type + "-----\n", StandardCharsets.US_ASCII);
    }

    private static final class FakeObserver implements AutoCloseable {
        private final ServerSocketChannel listener;
        private final Thread worker;
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicReference<SocketChannel> peer = new AtomicReference<>();
        private final AtomicReference<Throwable> failure = new AtomicReference<>();

        FakeObserver(Path socket, Reply reply, KeyPair observer, KeyPair other) throws IOException {
            listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            listener.bind(UnixDomainSocketAddress.of(socket));
            worker = new Thread(() -> {
                try (SocketChannel accepted = listener.accept()) {
                    peer.set(accepted);
                    exchange(accepted, reply, observer, other);
                } catch (Throwable t) {
                    failure.set(t);
                }
            }, "fake-observer-" + reply);
            worker.start();
        }

        private void exchange(SocketChannel channel, Reply reply, KeyPair observer, KeyPair other)
                throws Exception {
            if (reply == Reply.STALL_HELLO) {
                release.await(8, TimeUnit.SECONDS);
                return;
            }
            byte[] serverNonce = new byte[32];
            Arrays.fill(serverNonce, (byte) 0x42);
            if (reply == Reply.CLOSE_MID_HELLO) {
                write(channel, "OBS/1\n".getBytes(StandardCharsets.US_ASCII));
                return;
            }
            write(channel, concat((reply == Reply.WRONG_HELLO_VERSION ? "OBS/2\n" : "OBS/1\n")
                    .getBytes(StandardCharsets.US_ASCII), serverNonce));
            byte[] client = read(channel, 5 + 32 + 64);
            byte[] transcript = concat(serverNonce, Arrays.copyOfRange(client, 5, 37));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign((reply == Reply.FORGED_PROOF ? other : observer).getPrivate());
            signer.update("stargate-observer/1 server\n".getBytes(StandardCharsets.US_ASCII));
            signer.update(transcript);
            if (reply == Reply.CLOSE_MID_PROOF) {
                write(channel, "OK/1\n".getBytes(StandardCharsets.US_ASCII));
                return;
            }
            write(channel, concat((reply == Reply.WRONG_PROOF_VERSION ? "OK/2\n" : "OK/1\n")
                    .getBytes(StandardCharsets.US_ASCII), signer.sign()));
            if (reply == Reply.STALL_REPLY) {
                read(channel, 9);
                release.await(8, TimeUnit.SECONDS);
                return;
            }
            read(channel, 9);
            switch (reply) {
                case BAD_TOKEN -> write(channel, "GARBAGE/1\n".getBytes(StandardCharsets.US_ASCII));
                case OVERSIZED_TOKEN -> write(channel, new byte[100]);
                case TRUNCATED_TOKEN -> write(channel, "READY/1".getBytes(StandardCharsets.US_ASCII));
                case MISSING_EOF -> {
                    write(channel, "READY/1\n".getBytes(StandardCharsets.US_ASCII));
                    release.await(8, TimeUnit.SECONDS);
                }
                default -> write(channel, "READY/1\n".getBytes(StandardCharsets.US_ASCII));
            }
        }

        private static byte[] read(SocketChannel channel, int count) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(count);
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw new IOException("client closed mid-frame");
                }
            }
            return buffer.array();
        }

        private static void write(SocketChannel channel, byte[] data) throws IOException {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
        }

        private static byte[] concat(byte[] first, byte[] second) {
            byte[] joined = Arrays.copyOf(first, first.length + second.length);
            System.arraycopy(second, 0, joined, first.length, second.length);
            return joined;
        }

        @Override
        public void close() throws Exception {
            release.countDown();
            SocketChannel accepted = peer.get();
            if (accepted != null) {
                accepted.close();
            }
            listener.close();
            worker.join(1000);
            Throwable error = failure.get();
            if (error != null && !(error instanceof IOException)) {
                throw new AssertionError("fake observer failed", error);
            }
        }
    }
}
