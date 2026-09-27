// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Clock;
import org.jspecify.annotations.Nullable;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import javax.net.ssl.X509ExtendedTrustManager;

import io.grpc.netty.GrpcSslContexts;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
/**
 * The control plane's inter-plane TLS material, consuming
 * {@code specs/001-tor-route/contracts/wire-auth.md} VERBATIM (T095 §Acceptance
 * #5; the Java mirror of the DP's {@code controlclient/tls.go}): self-signed
 * Ed25519 X.509 derivation from cp.priv (§2), peer public-key pinning against
 * the peer's dp.pub (§3), and the TLS-config invariants (§4). No wire-shape
 * detail originates here — a gap in the contract lands as a wire-auth.md fix
 * (T095 rework), never an invention in this file.
 */
public final class CpTls {

    /** §2.2 identity. The CN is informational; the URI SAN is defence-in-depth
     * behind the §3 peer-pin, which remains the sole trust decision (§4.1). */
    public static final String COMMON_NAME = "stargate-cp";
    public static final String SPIFFE_ID = "spiffe://stargate.local/cp";

    /** §2.2 validity windows — fixed values so any change lands in a
     * wire-auth.md review, not silently (SECURITY-DECISIONS.md T095 entry). */
    static final Duration NOT_BEFORE_SKEW = Duration.ofMinutes(-5);
    static final Duration VALIDITY = Duration.ofDays(30);

    /** §1: Ed25519 is the only signature algorithm on this channel (RFC 8410). */
    static final String ED25519_OID = "1.3.101.112";

    // wire-auth.md §4: both CP TLS roles must offer exactly h2. Pin this
    // independently of GrpcSslContexts' library defaults (T130/T132).
    private static final ApplicationProtocolConfig H2_ALPN = new ApplicationProtocolConfig(
            ApplicationProtocolConfig.Protocol.ALPN,
            ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
            ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
            "h2");

    private static final DateTimeFormatter UTC_TIME =
            DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final byte[] DER_TAG_BOOLEAN_TRUE = { 0x01, 0x01, (byte) 0xFF };
    private static final int KEY_LENGTH = 32;

    /** The plane's TLS identity: the long-lived private key plus the transient
     * self-signed cert derived from it (in memory only, never persisted — §2.1). */
    public static final class Identity {
        private final PrivateKey privateKey;
        private X509Certificate certificate;
        private final @Nullable Clock clock;

        // Static synthetic identities let negative tests present expired certificates;
        // production derives an identity with a clock via deriveCpIdentity below.
        public Identity(
                PrivateKey privateKey,
                X509Certificate certificate) {
            this(privateKey, certificate, null);
        }

        Identity(
                PrivateKey privateKey,
                X509Certificate certificate,
                @Nullable Clock clock) {
            this.privateKey = privateKey;
            this.certificate = certificate;
            this.clock = clock;
        }

        public PrivateKey privateKey() { return privateKey; }
        public synchronized X509Certificate certificate() {
            if (clock != null) {
                Instant now = clock.instant();
                if (now.isBefore(certificate.getNotBefore().toInstant())
                        || !now.isBefore(certificate.getNotAfter().toInstant().minus(Duration.ofDays(1)))) {
                    certificate = deriveSelfSigned(privateKey, certificate.getPublicKey(),
                            COMMON_NAME, SPIFFE_ID, now);
                }
            }
            return certificate;
        }
    }

    private CpTls() {
    }

    /**
     * The §2.1 boot-time derivation: load cp.priv, build the self-signed §2.2
     * cert, return the in-memory identity. Errors are startup errors (the CP
     * fails fast per §2.2/§3.3 — never degraded into an unauthenticated
     * socket).
     *
     * <p>The JDK cannot derive an Ed25519 public key from its private scalar,
     * so the SPKI comes from the plane's OWN cp.pub (§6.1 — same keyfile pair,
     * same volume, operator-installed atomically). A mismatched pair cannot
     * slip through: the derived cert's signature is verified at derivation
     * time, which fails closed here rather than at first handshake.
     */
    public static Identity deriveCpIdentity(Path cpPriv, Path cpPub) {
        try {
            PrivateKey priv = loadPkcs8Pem(cpPriv);
            PublicKey pub = loadSpkiPem(cpPub);
            return new Identity(priv, deriveSelfSigned(priv, pub, COMMON_NAME, SPIFFE_ID,
                    Instant.now()), Clock.systemUTC());
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException(
                    "cp TLS material derivation failed (wire-auth.md §2.1 startup error): " + e.getMessage(),
                    e);
        }
    }

    /**
     * Builds the self-signed X.509 v3 leaf (§2.2): Ed25519 signature, serial 0,
     * {@code CN=<cn>}, NotBefore − 5 min, NotAfter + 30 days,
     * DigitalSignature-only KeyUsage (critical), ServerAuth+ClientAuth
     * ExtKeyUsage, no DNS names, the §2.2 SPIFFE URI SAN. Deterministic
     * modulo the validity window (§2.3). Parsed back through the JDK's
     * independent X.509 parser before returning — a malformed encoding fails
     * here, never on the wire.
     */
    static X509Certificate deriveSelfSigned(PrivateKey key, PublicKey pub,
            String cn, String spiffeId, Instant now) {
        try {
            Instant notBefore = now.plus(NOT_BEFORE_SKEW);
            Instant notAfter = now.plus(VALIDITY);
            byte[] spki = pub.getEncoded();
            byte[] rawKey = extractRawEd25519(spki);

            byte[] signatureAlg = seq(oid(ED25519_OID));
            byte[] name = name(cn);
            byte[] tbs = seq(
                    explicit(0, integer(2)), // version v3
                    integer(0), // serialNumber (§2.2: fixed 0)
                    signatureAlg,
                    name, // issuer (self-signed ⇒ Issuer == Subject)
                    seq(utcTime(notBefore), utcTime(notAfter)),
                    name, // subject
                    seq(signatureAlg, bitString(rawKey, 0)), // SPKI
                    explicit(3, seq(
                            extension("2.5.29.15", true, bitString(new byte[] { (byte) 0x80 }, 7)), // keyUsage digitalSignature
                            extension("2.5.29.37", false, seq(
                                    oid("1.3.6.1.5.5.7.3.1"), // serverAuth
                                    oid("1.3.6.1.5.5.7.3.2"))), // clientAuth
                            extension("2.5.29.19", false, seq()), // basicConstraints CA:FALSE
                            extension("2.5.29.17", false, seq(
                                    tlv(0x86, spiffeId.getBytes(StandardCharsets.US_ASCII)))) // [6] IMPLICIT IA5String: URI
                    )));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(tbs);
            byte[] der = seq(tbs, signatureAlg, bitString(signer.sign(), 0));

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            cert.verify(pub); // fail closed on a cp.priv/cp.pub mismatch (§2.2 startup error)
            return cert;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cp self-signed derivation failed (§2.2): " + e.getMessage(), e);
        }
    }

    /**
     * The §3.1 trust decision as a trust manager: peer authentication is
     * public-key pinning — NOT CA-chain validation, NOT hostname verification
     * (§3). The verifier extracts the raw 32-byte Ed25519 key from the peer
     * cert, re-reads the pinned key from {@code peerPubPath} FRESH ON EVERY
     * CHECK (§3.1 step 3 — what makes §6.2 key rotation live without a
     * peer-plane restart), and accepts iff the two raw keys are byte-equal
     * (constant-time compare). A chain of more than one cert is a contract
     * violation (§1: chain length is exactly 1). The comparison is on the raw
     * keys, never on PEM text or SPKI wrappers (§3.1 encoding pin).
     */
    public static X509ExtendedTrustManager peerPinTrustManager(Path peerPubPath) {
        return new X509ExtendedTrustManager() {
            private void pin(X509Certificate[] chain) throws CertificateException {
                if (chain == null || chain.length != 1) {
                    throw new CertificateException(
                            "peer presented " + (chain == null ? 0 : chain.length)
                                    + " certs, want exactly 1 (wire-auth.md §1)");
                }
                chain[0].checkValidity(); // §2.4: issuance backdate is the only skew allowance
                byte[] peerKey = extractRawEd25519(chain[0].getPublicKey().getEncoded());
                byte[] pinned = readPinnedRawKey(peerPubPath); // fresh from disk, every handshake (§3.1 step 3)
                if (!MessageDigest.isEqual(peerKey, pinned)) {
                    // §3.3: the handshake aborts; no application RPC is dispatched.
                    throw new CertificateException(
                            "peer public key does not match the pinned key (wire-auth.md §3.1)");
                }
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                pin(chain);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                pin(chain);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType,
                    java.net.Socket socket) throws CertificateException {
                pin(chain);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType,
                    java.net.Socket socket) throws CertificateException {
                pin(chain);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType,
                    javax.net.ssl.SSLEngine engine) throws CertificateException {
                pin(chain);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType,
                    javax.net.ssl.SSLEngine engine) throws CertificateException {
                pin(chain);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0]; // §3: no CA chain to build
            }
        };
    }

    /**
     * The §4 server configuration (control.sock listener): the derived cert
     * as the server identity, client auth REQUIRED (mTLS; a server that does
     * not request a client cert is a contract violation), client certs pinned
     * against dp.pub — the DP is the only legitimate dialer of control.sock.
     * TLS 1.3 only (§4: pinning to 1.3 removes the 1.2 downgrade surface).
     *
     * <p>wire-auth.md §4 (cited verbatim per T038 §Acceptance #3): in Go's
     * crypto/tls, {@code InsecureSkipVerify=true} disables normal CA-chain +
     * hostname verification but STILL invokes {@code VerifyPeerCertificate};
     * a config with the skip flag and no custom verifier is a silent auth
     * bypass. Java has no such knob to misuse — verification is wholly
     * determined by the supplied TrustManager, and the peer-pin manager above
     * is the sole trust decision; system roots are never consulted.
     */
    public static SslContext serverContext(Identity id, Path peerPubPath) {
        readPinnedRawKey(peerPubPath);
        return new FreshTlsContext(() -> buildServerContext(id, peerPubPath));
    }

    private static SslContext buildServerContext(Identity id, Path peerPubPath) {
        // §3.3: a missing/unreadable/unparseable pin is a CP STARTUP error —
        // fail fast here rather than at the DP's first dial. This governs
        // PRESENCE only; the per-handshake re-read (§3.1 step 3) still governs
        // every trust decision (mirror of the Go DeriveDPTLS fail-fast).
        readPinnedRawKey(peerPubPath);
        try {
            SslContextBuilder builder = GrpcSslContexts.configure(
                    SslContextBuilder.forServer(id.privateKey(), id.certificate()));
            builder.sslProvider(io.netty.handler.ssl.SslProvider.JDK)
                    .trustManager(peerPinTrustManager(peerPubPath))
                    .clientAuth(ClientAuth.REQUIRE) // §4: client auth REQUIRED
                    .applicationProtocolConfig(H2_ALPN)
                    .protocols("TLSv1.3");
            return builder.build();
        } catch (javax.net.ssl.SSLException e) {
            throw new IllegalStateException("cp server TLS context failed (§4): " + e.getMessage(), e);
        }
    }

    /**
     * The §4 client configuration (the dp.sock dial): the same cert as the
     * client identity (§2.2 ExtKeyUsage covers both roles), the peer-pin hook
     * as the sole trust decision against dp.pub, TLS 1.3 only. See the §4
     * citation on {@link #serverContext} for the InsecureSkipVerify analogy.
     */
    public static SslContext clientContext(Identity id, Path peerPubPath) {
        readPinnedRawKey(peerPubPath);
        return new FreshTlsContext(() -> buildClientContext(id, peerPubPath));
    }

    private static SslContext buildClientContext(Identity id, Path peerPubPath) {
        readPinnedRawKey(peerPubPath); // §3.3 startup fail-fast (see serverContext)
        try {
            SslContextBuilder builder = GrpcSslContexts.configure(SslContextBuilder.forClient());
            builder.sslProvider(io.netty.handler.ssl.SslProvider.JDK)
                    .keyManager(id.privateKey(), id.certificate())
                    .trustManager(peerPinTrustManager(peerPubPath))
                    .applicationProtocolConfig(H2_ALPN)
                    .protocols("TLSv1.3");
            return builder.build();
        } catch (javax.net.ssl.SSLException e) {
            throw new IllegalStateException("cp client TLS context failed (§4): " + e.getMessage(), e);
        }
    }

    // --- keyfile loading (§6.1) ---------------------------------------------------

    /** Reads and parses a PKCS#8 PEM private key (§1 keyfile format, per
     * {@code scripts/subcommands/init}). Errors name the path, never key
     * bytes (Constitution Principle III). */
    static PrivateKey loadPkcs8Pem(Path path) throws GeneralSecurityException, java.io.IOException {
        byte[] der = pemDer(path, "PRIVATE KEY");
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /** Reads and parses an SPKI PEM public key (the pinned *.pub shape). */
    static PublicKey loadSpkiPem(Path path) throws GeneralSecurityException, java.io.IOException {
        byte[] der = pemDer(path, "PUBLIC KEY");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Reads the pinned peer key and normalises it to the raw 32-byte Ed25519
     * form (§3.1 step 4). Called through {@link #peerPinTrustManager} on every
     * check — callers must not cache its result (§3.1 step 3).
     */
    static byte[] readPinnedRawKey(Path path) {
        try {
            return extractRawEd25519(loadSpkiPem(path).getEncoded());
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException(
                    "reading peer pin " + path + " (§3.3 startup error): " + e.getMessage(), e);
        }
    }

    private static byte[] pemDer(Path path, String type) throws java.io.IOException {
        String pem = Files.readString(path, StandardCharsets.US_ASCII);
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start < 0 || stop < 0 || stop < start) {
            throw new java.io.IOException(path + " contains no " + type + " PEM block");
        }
        String base64 = pem.substring(start + begin.length(), stop).replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new java.io.IOException(path + ": PEM body is not valid base64");
        }
    }

    // --- §3.1 encoding pin: SPKI → raw 32-byte key -----------------------------------

    /**
     * Extracts the raw 32-byte Ed25519 public key from a DER
     * {@code SubjectPublicKeyInfo} — the normalisation both pin sides go
     * through before the byte-equal comparison (§3.1: a comparison of SPKI
     * wrappers that differ in tag/length encoding would false-mismatch).
     * Non-Ed25519 SPKIs are rejected (§1: Ed25519 only).
     */
    static byte[] extractRawEd25519(byte[] spki) throws CertificateException {
        DerCursor cur = new DerCursor(spki);
        cur.enterSequence();
        cur.enterSequence(); // AlgorithmIdentifier
        byte[] algOid = cur.readOid();
        if (!ED25519_OID.equals(decodeOid(algOid))) {
            throw new CertificateException("key is not Ed25519 (wire-auth.md §1), alg OID "
                    + decodeOid(algOid));
        }
        cur.leave();
        byte[] key = cur.readBitString();
        if (key.length != KEY_LENGTH) {
            throw new CertificateException(
                    "Ed25519 SPKI carries " + key.length + " key bytes, want " + KEY_LENGTH);
        }
        return key;
    }

    // --- minimal DER encoding (§2.2 fixed cert shape; the JDK has no public
    // X.509 builder, and the privacy-critical control plane takes no new
    // third-party crypto dependency for one fixed-shape certificate) ----------

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static byte[] tlv(int tag, byte[] content) {
        int len = content.length;
        if (len < 0x80) {
            return concat(new byte[] { (byte) tag, (byte) len }, content);
        }
        int n = 32 - Integer.numberOfLeadingZeros(len);
        int lenBytes = (n + 7) / 8;
        byte[] header = new byte[2 + lenBytes];
        header[0] = (byte) tag;
        header[1] = (byte) (0x80 | lenBytes);
        for (int i = 0; i < lenBytes; i++) {
            header[2 + i] = (byte) (len >>> (8 * (lenBytes - 1 - i)));
        }
        return concat(header, content);
    }

    private static byte[] seq(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    private static byte[] set(byte[]... parts) {
        return tlv(0x31, concat(parts));
    }

    private static byte[] explicit(int number, byte[] content) {
        return tlv(0xA0 | number, content);
    }

    private static byte[] integer(long value) {
        if (value == 0) {
            return tlv(0x02, new byte[] { 0x00 });
        }
        int len = (64 - Long.numberOfLeadingZeros(value) + 8) / 8;
        byte[] content = new byte[len];
        for (int i = 0; i < len; i++) {
            content[i] = (byte) (value >>> (8 * (len - 1 - i)));
        }
        if ((content[0] & 0x80) != 0) { // DER: positive numbers need a sign-clearing leading zero
            byte[] padded = new byte[len + 1];
            System.arraycopy(content, 0, padded, 1, len);
            content = padded;
        }
        return tlv(0x02, content);
    }

    private static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        byte[] first = { (byte) (40 * Integer.parseInt(parts[0]) + Integer.parseInt(parts[1])) };
        byte[] rest = new byte[0];
        for (int i = 2; i < parts.length; i++) {
            rest = concat(rest, base128(Long.parseLong(parts[i])));
        }
        return tlv(0x06, concat(first, rest));
    }

    private static byte[] base128(long value) {
        int n = 1;
        long v = value;
        while (v >= 0x80) {
            v >>= 7;
            n++;
        }
        byte[] out = new byte[n];
        for (int i = n - 1; i >= 0; i--) {
            out[i] = (byte) ((value & 0x7F) | (i == n - 1 ? 0 : 0x80));
            value >>= 7;
        }
        return out;
    }

    private static byte[] utf8String(String s) {
        return tlv(0x0C, s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] bitString(byte[] payload, int unusedBits) {
        return tlv(0x03, concat(new byte[] { (byte) unusedBits }, payload));
    }

    private static byte[] utcTime(Instant t) {
        return tlv(0x17, UTC_TIME.format(t).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] name(String cn) {
        return seq(set(seq(oid("2.5.4.3"), utf8String(cn)))); // CN (2.5.4.3)
    }

    private static byte[] extension(String oidText, boolean critical, byte[] value) {
        return critical
                ? seq(oid(oidText), DER_TAG_BOOLEAN_TRUE, tlv(0x04, value))
                : seq(oid(oidText), tlv(0x04, value));
    }

    // --- minimal DER reading (only the fixed SPKI shape) -----------------------------

    /** A tiny cursor over one DER structure — enough for the fixed Ed25519
     * SPKI shape and nothing else. */
    private static final class DerCursor {
        private final byte[] der;
        private int pos;
        private int end;

        DerCursor(byte[] der) {
            this.der = der;
        }

        void enterSequence() throws CertificateException {
            int tag = readTag();
            int len = readLength();
            if (tag != 0x30) {
                throw new CertificateException("expected DER SEQUENCE, got tag " + tag);
            }
            end = pos + len;
            if (end > der.length) {
                throw new CertificateException("DER SEQUENCE overruns the buffer");
            }
        }

        void leave() {
            pos = end;
        }

        byte[] readOid() throws CertificateException {
            int tag = readTag();
            if (tag != 0x06) {
                throw new CertificateException("expected DER OID, got tag " + tag);
            }
            return readContent(readLength());
        }

        byte[] readBitString() throws CertificateException {
            int tag = readTag();
            if (tag != 0x03) {
                throw new CertificateException("expected DER BIT STRING, got tag " + tag);
            }
            byte[] content = readContent(readLength());
            if (content.length < 1 || content[0] != 0) {
                throw new CertificateException("BIT STRING with unused bits is not an Ed25519 key");
            }
            byte[] out = new byte[content.length - 1];
            System.arraycopy(content, 1, out, 0, out.length);
            return out;
        }

        private int readTag() {
            return der[pos++] & 0xFF;
        }

        private int readLength() throws CertificateException {
            int first = der[pos++] & 0xFF;
            if (first < 0x80) {
                return first;
            }
            int n = first & 0x7F;
            int len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | (der[pos++] & 0xFF);
            }
            return len;
        }

        private byte[] readContent(int len) {
            byte[] out = new byte[len];
            System.arraycopy(der, pos, out, 0, len);
            pos += len;
            return out;
        }
    }

    private static String decodeOid(byte[] der) {
        // content bytes → dotted; first byte packs (first*40 + second).
        long first = (der[0] & 0xFF) / 40;
        long second = (der[0] & 0xFF) % 40;
        StringBuilder sb = new StringBuilder().append(first).append('.').append(second);
        long value = 0;
        for (int i = 1; i < der.length; i++) {
            value = (value << 7) | (der[i] & 0x7F);
            if ((der[i] & 0x80) == 0) {
                sb.append('.').append(value);
                value = 0;
            }
        }
        return sb.toString();
    }
}
