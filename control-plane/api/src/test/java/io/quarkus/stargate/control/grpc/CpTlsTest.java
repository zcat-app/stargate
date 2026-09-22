// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package io.quarkus.stargate.control.grpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Contract tests for the control plane's inter-plane TLS material (T038) —
 * the Java mirror of the DP's {@code controlclient/tls.go} derivation, pinned
 * field-by-field against
 * {@code specs/001-tor-route/contracts/wire-auth.md} (T095):
 *
 * <ul>
 *   <li>§2.2 — every certificate field value, verified by PARSE-BACK through
 *       the JDK's independent X.509 parser (never through the code that
 *       produced the bytes);</li>
 *   <li>§2.3 — byte-determinism modulo the validity window;</li>
 *   <li>§3.1 — byte-equal pin on the RAW 32-byte Ed25519 key, re-read fresh
 *       from disk on every check (never cached);</li>
 *   <li>§1 — chain length exactly 1, Ed25519 the only algorithm.</li>
 * </ul>
 */
class CpTlsTest {

    @TempDir
    Path tmp;

    @Test
    void rejectsExpiredAndFuturePeersInBothRoles() throws Exception {
        KeyPair peer = ed25519KeyPair();
        Path pin = writePublicKey(tmp, "peer.pub", peer);
        var trust = CpTls.peerPinTrustManager(pin);
        for (Instant issued : List.of(Instant.now().minus(Duration.ofDays(31)),
                Instant.now().plus(Duration.ofHours(1)))) {
            X509Certificate cert = CpTls.deriveSelfSigned(peer.getPrivate(), peer.getPublic(),
                    "stargate-dp", "spiffe://stargate.local/dp", issued);
            assertThrows(CertificateException.class,
                    () -> trust.checkClientTrusted(new X509Certificate[] { cert }, "Ed25519"));
            assertThrows(CertificateException.class,
                    () -> trust.checkServerTrusted(new X509Certificate[] { cert }, "Ed25519"));
        }
    }

    @Test
    void renewsIdentityWithoutPeerOrDiskAccess() throws Exception {
        KeyPair own = ed25519KeyPair();
        Instant issued = Instant.now().minus(Duration.ofDays(31));
        var initial = CpTls.deriveSelfSigned(own.getPrivate(), own.getPublic(),
                "stargate-cp", "spiffe://stargate.local/cp", issued);
        var id = new CpTls.Identity(own.getPrivate(), initial,
                java.time.Clock.fixed(issued.plus(Duration.ofDays(31)), java.time.ZoneOffset.UTC));
        assertTrue(id.certificate().getNotAfter().toInstant().isAfter(Instant.now().plus(Duration.ofDays(29))),
                "renewal must happen before using an identity after a long outage");
        assertEquals(own.getPublic(), id.certificate().getPublicKey());
        var beforeExpiry = new CpTls.Identity(own.getPrivate(), initial,
                java.time.Clock.fixed(issued.plus(Duration.ofDays(29)).plus(Duration.ofHours(1)), java.time.ZoneOffset.UTC));
        assertTrue(beforeExpiry.certificate().getNotAfter().after(initial.getNotAfter()),
                "renewal must start before the old certificate expires");
    }

    // --- fixtures -------------------------------------------------------------

    /** Writes a PEM file (64-column Base64, standard RFC 7468 armour). */
    private static void writePem(Path path, String type, byte[] der) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        String pem = "-----BEGIN " + type + "-----\n" + base64
                + "\n-----END " + type + "-----\n";
        Files.writeString(path, pem, StandardCharsets.US_ASCII);
    }

    /** Writes a PKCS#8 private key PEM — the {@code stargate init} keyfile shape (§6.1). */
    private static Path writePrivateKey(Path dir, String name, KeyPair kp) throws Exception {
        Path p = dir.resolve(name);
        writePem(p, "PRIVATE KEY", kp.getPrivate().getEncoded());
        return p;
    }

    /** Writes an SPKI public key PEM — the {@code stargate init} keyfile shape (§6.1). */
    private static Path writePublicKey(Path dir, String name, KeyPair kp) throws Exception {
        Path p = dir.resolve(name);
        writePem(p, "PUBLIC KEY", kp.getPublic().getEncoded());
        return p;
    }

    private static KeyPair ed25519KeyPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    // --- §2.2 certificate fields ----------------------------------------------

    @Test
    void derivedCertFieldValuesPerWireAuth22() throws Exception {
        KeyPair kp = ed25519KeyPair();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        // The returned cert was decoded from the produced DER by the JDK's
        // independent CertificateFactory (inside the implementation) — the
        // field assertions below therefore pin the ENCODING, not intentions.
        X509Certificate cert = CpTls.deriveSelfSigned(kp.getPrivate(), kp.getPublic(),
                "stargate-cp", "spiffe://stargate.local/cp", now);

        // Version 3 (required for the SAN extension).
        assertEquals(3, cert.getVersion(), "§2.2: X.509 v3");
        // SerialNumber 0 (not load-bearing; fixed for determinism auditing).
        assertEquals(BigInteger.ZERO, cert.getSerialNumber(), "§2.2: serial 0");
        // Ed25519 is the only signature algorithm on this channel (§1).
        assertTrue(cert.getSigAlgName().contains("Ed25519"),
                "§1: signature algorithm must be Ed25519, got " + cert.getSigAlgName());
        // Self-signed: Issuer == Subject == CN=stargate-cp, and nothing else.
        X500Principal expected = new X500Principal("CN=stargate-cp");
        assertEquals(expected, cert.getSubjectX500Principal(), "§2.2: Subject CN=stargate-cp");
        assertEquals(expected, cert.getIssuerX500Principal(), "§2.2: self-signed ⇒ Issuer == Subject");
        // Validity: NotBefore = now − 5 min, NotAfter = now + 30 days (second
        // encoding granularity tolerated).
        assertTrue(Duration.between(now.minus(Duration.ofMinutes(5)), cert.getNotBefore().toInstant())
                .abs().compareTo(Duration.ofSeconds(1)) <= 0,
                "§2.2: NotBefore = now − 5 min (±1s encoding granularity)");
        assertTrue(Duration.between(now, cert.getNotAfter().toInstant())
                .minus(Duration.ofDays(30)).abs().compareTo(Duration.ofSeconds(1)) <= 0,
                "§2.2: NotAfter = now + 30 days (±1s encoding granularity)");
        // KeyUsage: DigitalSignature only (critical, per Go mirror / RFC 5280).
        boolean[] ku = cert.getKeyUsage();
        assertNotNull(ku, "§2.2: KeyUsage present");
        assertTrue(ku[0], "§2.2: digitalSignature set");
        for (int i = 1; i < ku.length; i++) {
            assertFalse(ku[i], "§2.2: KeyUsage bit " + i + " must be clear (DigitalSignature only)");
        }
        // ExtKeyUsage: both roles — each plane is TLS client AND server (§2.2).
        assertEquals(List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"),
                cert.getExtendedKeyUsage(), "§2.2: ServerAuth + ClientAuth");
        // SAN: exactly the SPIFFE URI, no DNS names (§2.2: UDS has no DNS).
        java.util.Collection<java.util.List<?>> sans = cert.getSubjectAlternativeNames();
        assertNotNull(sans, "§2.2: SAN extension present");
        assertEquals(1, sans.size(), "§2.2: exactly one SAN entry");
        java.util.List<?> san = sans.iterator().next();
        assertEquals(6, san.get(0), "§2.2: SAN type uniformResourceIdentifier (6)");
        assertEquals("spiffe://stargate.local/cp", san.get(1), "§2.2: SPIFFE URI SAN");
        // Not a CA.
        assertEquals(-1, cert.getBasicConstraints(), "§2.2: leaf, not a CA");
        // Signature verifies with the subject public key (self-signature).
        cert.verify(kp.getPublic());
        // Extension criticality: only keyUsage is critical (Go mirror parity).
        assertEquals(List.of("2.5.29.15"), List.copyOf(cert.getCriticalExtensionOIDs()),
                "keyUsage critical; everything else non-critical (Go DeriveCert parity)");
    }

    @Test
    void derivationIsByteDeterministicForFixedClock() throws Exception {
        KeyPair kp = ed25519KeyPair();
        Instant now = Instant.parse("2026-09-05T12:00:00Z");
        byte[] first = CpTls.deriveSelfSigned(kp.getPrivate(), kp.getPublic(),
                "stargate-cp", "spiffe://stargate.local/cp", now).getEncoded();
        byte[] second = CpTls.deriveSelfSigned(kp.getPrivate(), kp.getPublic(),
                "stargate-cp", "spiffe://stargate.local/cp", now).getEncoded();
        // §2.3: byte-identical across derivations against the same key + clock.
        assertArrayEquals(first, second,
                "§2.3: derived cert must be byte-deterministic modulo validity");
    }

    // --- §3.1 peer pinning ------------------------------------------------------

    @Test
    void pinTrustManagerAcceptsPinnedPeerKey() throws Exception {
        KeyPair dp = ed25519KeyPair();
        Path dpPub = writePublicKey(tmp, "dp.pub", dp);
        X509Certificate dpCert = CpTls.deriveSelfSigned(dp.getPrivate(), dp.getPublic(),
                "stargate-dp", "spiffe://stargate.local/dp", Instant.now());
        var tm = CpTls.peerPinTrustManager(dpPub);
        // Both roles: every plane is TLS client AND server (§2.2 ExtKeyUsage).
        tm.checkServerTrusted(new X509Certificate[] { dpCert }, "ECDHE_RSA");
        tm.checkClientTrusted(new X509Certificate[] { dpCert }, "ECDHE_RSA");
    }

    @Test
    void pinTrustManagerRejectsRoguePeerKey() throws Exception {
        KeyPair dp = ed25519KeyPair();
        KeyPair rogue = ed25519KeyPair();
        Path dpPub = writePublicKey(tmp, "dp.pub", dp);
        X509Certificate rogueCert = CpTls.deriveSelfSigned(rogue.getPrivate(), rogue.getPublic(),
                "stargate-dp", "spiffe://stargate.local/dp", Instant.now());
        var tm = CpTls.peerPinTrustManager(dpPub);
        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[] { rogueCert }, "ECDHE_RSA"),
                "§3.3: a peer key that does not byte-equal the pin must abort the handshake");
    }

    @Test
    void pinIsRereadFreshFromDiskPerHandshake() throws Exception {
        // §3.1 step 3: the verifier MUST NOT cache the pinned key — after the
        // operator replaces dp.pub (the §6.2 rotation event), the SAME trust
        // manager must accept the new key and reject the old one.
        KeyPair keyA = ed25519KeyPair();
        KeyPair keyB = ed25519KeyPair();
        Path dpPub = writePublicKey(tmp, "dp.pub", keyA);
        X509Certificate certA = CpTls.deriveSelfSigned(keyA.getPrivate(), keyA.getPublic(),
                "stargate-dp", "spiffe://stargate.local/dp", Instant.now());
        X509Certificate certB = CpTls.deriveSelfSigned(keyB.getPrivate(), keyB.getPublic(),
                "stargate-dp", "spiffe://stargate.local/dp", Instant.now());
        var tm = CpTls.peerPinTrustManager(dpPub);
        tm.checkServerTrusted(new X509Certificate[] { certA }, "ECDHE_RSA");
        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[] { certB }, "ECDHE_RSA"));

        // Rotate: overwrite the pin file with key B (write-tmp + rename, §6.2 —
        // simplified to a same-file write here; the property under test is the
        // absence of caching, not the atomicity of the rename).
        writePublicKey(tmp, "dp.pub", keyB);
        tm.checkServerTrusted(new X509Certificate[] { certB }, "ECDHE_RSA");
        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[] { certA }, "ECDHE_RSA"),
                "§3.1 step 3: stale pin must be rejected after rotation without a new verifier");
    }

    @Test
    void pinRejectsMultiCertChain() throws Exception {
        KeyPair dp = ed25519KeyPair();
        Path dpPub = writePublicKey(tmp, "dp.pub", dp);
        X509Certificate cert = CpTls.deriveSelfSigned(dp.getPrivate(), dp.getPublic(),
                "stargate-dp", "spiffe://stargate.local/dp", Instant.now());
        var tm = CpTls.peerPinTrustManager(dpPub);
        // §1: chain length is exactly 1 — a chain (even one whose leaf matches)
        // is a contract violation, not a pin candidate.
        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[] { cert, cert }, "ECDHE_RSA"));
    }

    // --- §1 encoding pin: raw 32-byte key normalisation --------------------------

    @Test
    void rawKeyExtractionNormalisesToRaw32Bytes() throws Exception {
        KeyPair kp = ed25519KeyPair();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] raw = CpTls.extractRawEd25519(spki);
        assertEquals(32, raw.length, "§3.1: the pin comparison is on the raw 32-byte key");
        // For an Ed25519 SPKI the raw key is the BIT STRING payload at the tail
        // of the DER (alg SEQ + BIT STRING follow the outer header).
        assertArrayEquals(java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length), raw,
                "extraction must normalise to the raw key, not the SPKI wrapper");
    }

    @Test
    void rawKeyExtractionRejectsNonEd25519Spki() throws Exception {
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPublicKey ignored = (RSAPublicKey) rsa.getPublic();
        assertThrows(CertificateException.class, () -> CpTls.extractRawEd25519(ignored.getEncoded()),
                "§1: Ed25519 is the only signature algorithm on this channel");
    }

    // --- §6.1 keyfile loading -----------------------------------------------------

    @Test
    void loadPkcs8PemRoundTripsTheKey() throws Exception {
        KeyPair kp = ed25519KeyPair();
        Path cpPriv = writePrivateKey(tmp, "cp.priv", kp);
        PrivateKey loaded = CpTls.loadPkcs8Pem(cpPriv);
        assertArrayEquals(kp.getPrivate().getEncoded(), loaded.getEncoded(),
                "PKCS#8 PEM round-trip must preserve the key");
    }

    @Test
    void loadPkcs8PemRejectsGarbage() throws Exception {
        Path bad = tmp.resolve("cp.priv");
        Files.writeString(bad, "-----BEGIN PRIVATE KEY-----\nnot base64!!\n-----END PRIVATE KEY-----\n");
        assertThrows(Exception.class, () -> CpTls.loadPkcs8Pem(bad),
                "a corrupt keyfile is a startup error (§2.2/§3.3 CP fail-fast)");
    }

    @Test
    void pinnedPubRoundTripsToRawKey() throws Exception {
        KeyPair kp = ed25519KeyPair();
        Path dpPub = writePublicKey(tmp, "dp.pub", kp);
        byte[] raw = CpTls.readPinnedRawKey(dpPub);
        assertEquals(32, raw.length);
        assertArrayEquals(
                CpTls.extractRawEd25519(kp.getPublic().getEncoded()),
                raw,
                "the pinned file must decode to the same raw 32-byte key for the §3.1 comparison");
    }

    // --- §3.3 / §4 context-construction invariants -------------------------------

    @Test
    void missingPeerPinFailsFastAtStartup() throws Exception {
        // §3.3: a missing/unreadable <peer>.pub is a CP STARTUP error — the
        // context constructors must abort before anything binds, while the
        // per-handshake re-read (§3.1 step 3, pinIsRereadFreshFromDiskPerHandshake)
        // continues to govern every trust decision.
        KeyPair cp = ed25519KeyPair();
        var identity = new CpTls.Identity(cp.getPrivate(), CpTls.deriveSelfSigned(
                cp.getPrivate(), cp.getPublic(), "stargate-cp", "spiffe://stargate.local/cp",
                Instant.now()));
        Path absent = tmp.resolve("absent.pub");
        var clientError = assertThrows(IllegalStateException.class,
                () -> CpTls.clientContext(identity, absent));
        assertTrue(clientError.getMessage().contains(absent.toString()),
                "the startup error must name the pin path (never key bytes)");
        var serverError = assertThrows(IllegalStateException.class,
                () -> CpTls.serverContext(identity, absent));
        assertTrue(serverError.getMessage().contains(absent.toString()),
                "the startup error must name the pin path (never key bytes)");
    }

    @Test
    void contextsEnableTls13Only() throws Exception {
        // wire-auth.md §4 min-TLS row: pinning to 1.3 removes the TLS 1.2
        // downgrade surface — the PRODUCTION contexts must offer exactly
        // TLSv1.3, nothing older.
        KeyPair cp = ed25519KeyPair();
        KeyPair dp = ed25519KeyPair();
        Path dpPub = writePublicKey(tmp, "dp.pub", dp);
        var identity = new CpTls.Identity(cp.getPrivate(), CpTls.deriveSelfSigned(
                cp.getPrivate(), cp.getPublic(), "stargate-cp", "spiffe://stargate.local/cp",
                Instant.now()));
        javax.net.ssl.SSLEngine clientEngine = CpTls.clientContext(identity, dpPub).newEngine(io.netty.buffer.ByteBufAllocator.DEFAULT);
        javax.net.ssl.SSLEngine serverEngine = CpTls.serverContext(identity, dpPub).newEngine(io.netty.buffer.ByteBufAllocator.DEFAULT);
        for (javax.net.ssl.SSLEngine engine : new javax.net.ssl.SSLEngine[] { clientEngine, serverEngine }) {
            List<String> enabled = List.of(engine.getEnabledProtocols());
            assertTrue(enabled.contains("TLSv1.3"), "§4: TLS 1.3 must be enabled");
            for (String protocol : enabled) {
                assertEquals("TLSv1.3", protocol,
                        "§4: nothing older than TLS 1.3 may be negotiable");
            }
        }
    }
}
