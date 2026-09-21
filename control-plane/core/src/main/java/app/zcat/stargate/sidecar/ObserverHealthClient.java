// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.sidecar;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

/**
 * CP's sole Tor health transport. The signed two-nonce exchange authenticates
 * both peers before the exact T138 HEALTH/1 request. A failed socket, pin,
 * version or deadline is only an UNAVAILABLE advisory sample (Principle II).
 */
public final class ObserverHealthClient implements SidecarMonitor.HealthProbe {

    private static final byte[] SERVER_HELLO = "OBS/1\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CLIENT_HELLO = "CP/1\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SERVER_PROOF = "OK/1\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CLIENT_DOMAIN =
            "stargate-observer/1 client\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SERVER_DOMAIN =
            "stargate-observer/1 server\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] REQUEST = "HEALTH/1\n".getBytes(StandardCharsets.US_ASCII);
    private static final Duration CALL_LIMIT = Duration.ofSeconds(6);

    private final Path socket;
    private final Path privateKey;
    private final Path observerPublicKey;
    private final SecureRandom random = new SecureRandom();

    public ObserverHealthClient(Path socket, Path privateKey, Path observerPublicKey) {
        this.socket = socket;
        this.privateKey = privateKey;
        this.observerPublicKey = observerPublicKey;
    }

    @Override
    public SidecarMonitor.Health sample() {
        try {
            return call();
        } catch (IOException | GeneralSecurityException | RuntimeException failure) {
            // Never expose path, key or raw upstream detail to logs or events.
            return SidecarMonitor.Health.UNAVAILABLE;
        }
    }

    private SidecarMonitor.Health call() throws IOException, GeneralSecurityException {
        long deadline = System.nanoTime() + CALL_LIMIT.toNanos();
        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX);
                Selector selector = Selector.open()) {
            channel.configureBlocking(false);
            channel.register(selector, SelectionKey.OP_CONNECT);
            channel.connect(UnixDomainSocketAddress.of(socket));
            while (!channel.finishConnect()) {
                await(selector, SelectionKey.OP_CONNECT, deadline);
            }

            byte[] hello = readExactly(channel, selector, SERVER_HELLO.length + 32, deadline);
            if (!Arrays.equals(Arrays.copyOfRange(hello, 0, SERVER_HELLO.length), SERVER_HELLO)) {
                throw new IOException("observer version mismatch");
            }
            byte[] clientNonce = new byte[32];
            random.nextBytes(clientNonce);
            byte[] transcript = concat(Arrays.copyOfRange(hello, SERVER_HELLO.length, hello.length), clientNonce);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(readPrivateKey(privateKey));
            signer.update(CLIENT_DOMAIN);
            signer.update(transcript);
            writeAll(channel, selector, concat(CLIENT_HELLO, clientNonce, signer.sign()), deadline);

            byte[] proof = readExactly(channel, selector, SERVER_PROOF.length + 64, deadline);
            if (!Arrays.equals(Arrays.copyOfRange(proof, 0, SERVER_PROOF.length), SERVER_PROOF)) {
                throw new IOException("observer proof version mismatch");
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(readPublicKey(observerPublicKey)); // fresh pin each call
            verifier.update(SERVER_DOMAIN);
            verifier.update(transcript);
            if (!verifier.verify(Arrays.copyOfRange(proof, SERVER_PROOF.length, proof.length))) {
                throw new IOException("observer authentication failed");
            }

            writeAll(channel, selector, REQUEST, deadline);
            channel.shutdownOutput();
            ByteBuffer response = ByteBuffer.allocate(15); // largest allowed reply is 14 bytes
            while (true) {
                int n = channel.read(response);
                if (n < 0) {
                    break;
                }
                if (!response.hasRemaining()) {
                    throw new IOException("observer reply too long");
                }
                if (n == 0) {
                    await(selector, SelectionKey.OP_READ, deadline);
                }
            }
            String token = new String(response.array(), 0, response.position(), StandardCharsets.US_ASCII);
            return switch (token) {
                case "READY/1\n" -> SidecarMonitor.Health.READY;
                case "NOT_READY/1\n" -> SidecarMonitor.Health.NOT_READY;
                case "UNAVAILABLE/1\n" -> SidecarMonitor.Health.UNAVAILABLE;
                default -> throw new IOException("invalid observer token");
            };
        }
    }

    private static byte[] readExactly(SocketChannel channel, Selector selector, int count, long deadline)
            throws IOException {
        ByteBuffer target = ByteBuffer.allocate(count);
        while (target.hasRemaining()) {
            int n = channel.read(target);
            if (n < 0) {
                throw new IOException("observer closed mid-frame");
            }
            if (n == 0) {
                await(selector, SelectionKey.OP_READ, deadline);
            }
        }
        return target.array();
    }

    private static void writeAll(SocketChannel channel, Selector selector, byte[] data, long deadline)
            throws IOException {
        ByteBuffer source = ByteBuffer.wrap(data);
        while (source.hasRemaining()) {
            if (channel.write(source) == 0) {
                await(selector, SelectionKey.OP_WRITE, deadline);
            }
        }
    }

    private static void await(Selector selector, int operation, long deadline) throws IOException {
        int remainingMillis = (int) Math.min(Integer.MAX_VALUE,
                Math.max(0, (deadline - System.nanoTime()) / 1_000_000));
        if (remainingMillis == 0) {
            throw new IOException("observer deadline");
        }
        selector.keys().iterator().next().interestOps(operation);
        if (selector.select(remainingMillis) == 0) {
            throw new IOException("observer deadline");
        }
        selector.selectedKeys().clear();
    }

    private static PrivateKey readPrivateKey(Path path) throws IOException, GeneralSecurityException {
        byte[] der = pem(Files.readString(path), "PRIVATE KEY");
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static PublicKey readPublicKey(Path path) throws IOException, GeneralSecurityException {
        byte[] der = pem(Files.readString(path), "PUBLIC KEY");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] pem(String text, String type) throws IOException {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int a = text.indexOf(begin);
        int b = text.indexOf(end);
        if (a < 0 || b <= a) {
            throw new IOException("invalid observer key");
        }
        return Base64.getMimeDecoder().decode(text.substring(a + begin.length(), b));
    }

    private static byte[] concat(byte[]... parts) {
        int n = Arrays.stream(parts).mapToInt(p -> p.length).sum();
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }
}
