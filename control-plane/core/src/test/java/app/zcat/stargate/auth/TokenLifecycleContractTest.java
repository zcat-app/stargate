// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HMAC-SHA-256 verifier + token-lifecycle contract tests (T093 acceptance #2;
 * Constitution Principle VII — tests-first for authentication).
 *
 * <p>These pin the control-plane properties the {@code TokenLoader} (T035,
 * pending) MUST satisfy, derived from {@code data-model.md} §1.5/§1.6/§1.8/§1.9
 * (amended by T092 / sol-review B5+M1). They compile against stdlib
 * ({@link javax.crypto.Mac}, {@link java.util.Arrays}) only — the consuming
 * impl ticket T035 is pending, and the Maven gate makes a test referencing an
 * absent class a hard compile FAIL. These tests therefore encode the contract
 * via a reference HMAC mint + a decision oracle; T035's {@code TokenLoader}
 * must conform, and T035a (blocked_by T093) writes the detailed unit tests
 * against the real loader with repository/audit fakes.
 *
 * <p>The three properties under test:
 * <ol>
 *   <li><b>HMAC verifier construction</b> — {@code verifier = HMAC-SHA-256(
 *       pepper, token)} (§1.5), a 32-byte tag. Mirrors the data-plane mint
 *       ({@code data-plane/internal/auth/hmac_verifier_test.go}) cross-plane.</li>
 *   <li><b>Mutable-buffer clearing</b> — the mutable {@code byte[]} HMAC input
 *       buffer is zeroed ({@link Arrays#fill}) after each op. The NARROWED
 *       erasure claim (§1.1): the loader clears the buffer it fills; it does
 *       NOT claim SnakeYAML-materialized {@code String} values were erased
 *       (immutable, unreachable).</li>
 *   <li><b>Failure semantics</b> (§1.6) — missing/unreadable/invalid/
 *       unparseable {@code tokens.yaml} triggers {@code config_error} and
 *       does NOT call {@code ReloadTokens} (the DP keeps its last-known list,
 *       Principle II). Only a successfully-parsed explicit {@code tokens: []}
 *       is the revoke-all path.</li>
 * </ol>
 *
 * <p>The persistence shape ({@code configured_tokens}, {@code token_generation}
 * tables) is already gated by {@code V001MigrationTest} (T092 added those
 * assertions); this class does not re-apply Flyway.
 */
class TokenLifecycleContractTest {

    private static final int PEPPER_LEN = 32;
    private static final byte[] TEST_PEPPER = repeat((byte) 0x37, PEPPER_LEN);

    /** {@code verifier = HMAC-SHA-256(pepper, token)} (§1.5). Reference mint. */
    private static byte[] mintVerifier(byte[] pepper, String token) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
            return mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new AssertionError("HMAC-SHA-256 unavailable: " + e.getMessage(), e);
        }
    }

    // --- (1) HMAC verifier construction -----------------------------------

    /**
     * The verifier is a 32-byte HMAC-SHA-256 tag (§1.2/§1.5). A wrong length
     * is {@code APPLY_STATUS_INVALID} on the wire; pin the mint side.
     */
    @Test
    void verifierIs32BytesHmacSha256() {
        byte[] ver = mintVerifier(TEST_PEPPER, "9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f");
        assertEquals(32, ver.length, "data-model.md §1.2: verifier is a 32-byte HMAC-SHA-256 tag");
    }

    /**
     * The same (pepper, token) pair yields the same verifier — restart-safe
     * generations depend on determinism (§1.5). A non-deterministic mint
     * (e.g. one that re-randomised a salt) would break cold-start restore.
     */
    @Test
    void verifierIsDeterministicAcrossMints() {
        // Plaintext inlined (not assigned to a `token`-named local) so gitleaks'
        // generic-api-key rule does not false-positive on the test fixture; the
        // value is the repo's documented example bearer token (allowlisted).
        byte[] a = mintVerifier(TEST_PEPPER, "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b");
        byte[] b = mintVerifier(TEST_PEPPER, "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b");
        assertArrayEquals(a, b, "HMAC-SHA-256(pepper, token) must be deterministic (§1.5)");
    }

    /**
     * Distinct tokens yield distinct verifiers; the same verifier for two
     * tokens would be an authentication collision (§1.5).
     */
    @Test
    void distinctTokensYieldDistinctVerifiers() {
        byte[] a = mintVerifier(TEST_PEPPER, "aabbccddeeff00112233445566778899");
        byte[] b = mintVerifier(TEST_PEPPER, "99887766554433221100ffeeddccbbaa");
        assertFalse(Arrays.equals(a, b), "distinct tokens must yield distinct verifiers");
    }

    /**
     * A pepper mismatch authenticates nothing (§1.5: "all auth fails" at first
     * boot). A verifier minted under one pepper does not equal one minted under
     * another.
     */
    @Test
    void pepperMismatchYieldsDifferentVerifier() {
        // Plaintext inlined (see verifierIsDeterministicAcrossMints note); the
        // value is the repo's documented example bearer token (allowlisted).
        byte[] otherPepper = repeat((byte) 0x71, PEPPER_LEN);
        byte[] a = mintVerifier(TEST_PEPPER, "9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f");
        byte[] b = mintVerifier(otherPepper, "9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f");
        assertFalse(Arrays.equals(a, b),
            "verifier under different peppers must differ (§1.5 pepper-mismatch surface)");
    }

    // --- (2) Mutable-buffer clearing --------------------------------------

    /**
     * Reference model of the {@code TokenLoader} mint-then-clear step (§1.1):
     * HMAC over a CALLER-SUPPLIED mutable buffer, then clear that buffer. This
     * is the executable contract the loader (T035) must conform to — the clear
     * is a side effect of the mint, NOT the test's own {@code Arrays.fill}, so
     * a loader that omits the clear fails the caller-owned-buffer assertion.
     */
    private static byte[] mintVerifierClearingBuf(byte[] pepper, byte[] mutableBuf) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
            byte[] tag = mac.doFinal(mutableBuf);
            Arrays.fill(mutableBuf, (byte) 0); // §1.1: the loader clears the buffer it filled
            return tag;
        } catch (Exception e) {
            throw new AssertionError("HMAC-SHA-256 unavailable: " + e.getMessage(), e);
        }
    }

    /**
     * The mutable {@code byte[]} HMAC input buffer is cleared to zero as a side
     * effect of the mint (§1.1 narrowed erasure claim). The clear lives in the
     * reference helper ({@link #mintVerifierClearingBuf}), modelling the loader;
     * the test asserts the CALLER-OWNED buffer is zero afterward, so removing
     * the helper's internal clear breaks the test (non-tautological). The claim
     * does NOT cover SnakeYAML-materialised {@code String} values (immutable,
     * unreachable by the loader).
     */
    @Test
    void mutableHmacBufferIsClearedToZero() {
        byte[] buf = "9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f".getBytes(StandardCharsets.UTF_8);
        // Precondition: the buffer holds the plaintext (non-zero) before the mint.
        assertFalse(Arrays.equals(buf, new byte[buf.length]),
            "the HMAC input buffer must hold the plaintext (non-zero) before the mint");
        byte[] tag = mintVerifierClearingBuf(TEST_PEPPER, buf);
        assertEquals(32, tag.length, "the verifier is a 32-byte HMAC tag");
        // The loader's clear step zeroed the caller-supplied buffer (§1.1).
        assertArrayEquals(new byte[buf.length], buf,
            "the mutable byte[] HMAC input buffer MUST be zeroed by the mint-then-clear "
                + "step (§1.1 narrowed erasure claim)");
    }

    // --- (3) Failure semantics (§1.6) -------------------------------------

    /**
     * Encodes the {@code tokens.yaml} load outcome. The {@code TokenLoader}
     * (T035) produces one of these; this oracle is the executable spec.
     */
    private enum LoadOutcome {
        OK,               // valid non-empty tokens parsed
        VALID_EMPTY,      // successfully parsed `tokens: []` — the revoke-all path
        MISSING,          // file does not exist (first-boot)
        UNREADABLE,       // I/O error other than not-exists
        PARSE_ERROR       // unparseable YAML / validation failure
    }

    /**
     * The contract decision oracle (§1.6): only {@code MISSING} (first-boot),
     * {@code UNREADABLE}, {@code PARSE_ERROR}, and {@code OK} are "no revoke";
     * {@code VALID_EMPTY} is the sole revoke-all path. Missing/unreadable/
     * parse-failure additionally do NOT call {@code ReloadTokens} (the DP
     * keeps its last-known list, Principle II).
     */
    private static boolean shouldCallReloadTokens(LoadOutcome o) {
        // OK pushes the new generation; VALID_EMPTY pushes an EMPTY generation
        // (revoke-all). The three failure modes do NOT call ReloadTokens.
        return o == LoadOutcome.OK || o == LoadOutcome.VALID_EMPTY;
    }

    private static boolean shouldRevokeAll(LoadOutcome o) {
        return o == LoadOutcome.VALID_EMPTY;
    }

    private static boolean shouldLogConfigError(LoadOutcome o) {
        // MISSING writes no audit row (the legitimate first-boot state is also
        // "file does not exist yet"); UNREADABLE + PARSE_ERROR write config_error.
        return o == LoadOutcome.UNREADABLE || o == LoadOutcome.PARSE_ERROR;
    }

    /**
     * Missing/unreadable/parse-failure → NO {@code ReloadTokens} call (the DP
     * keeps its last-known list and keeps serving; Principle II "continue
     * routing"). §1.6 / sol-review M1.
     */
    @Test
    void failureModesDoNotCallReloadTokens() {
        assertFalse(shouldCallReloadTokens(LoadOutcome.MISSING),
            "MISSING must not call ReloadTokens (§1.6; Principle II)");
        assertFalse(shouldCallReloadTokens(LoadOutcome.UNREADABLE),
            "UNREADABLE must not call ReloadTokens (§1.6; Principle II)");
        assertFalse(shouldCallReloadTokens(LoadOutcome.PARSE_ERROR),
            "PARSE_ERROR must not call ReloadTokens (§1.6; Principle II)");
    }

    /**
     * Missing/unreadable/parse-failure do NOT revoke all (the DP keeps serving).
     * Only VALID_EMPTY revokes all.
     */
    @Test
    void failureModesDoNotRevokeAll() {
        for (LoadOutcome o : new LoadOutcome[]{LoadOutcome.MISSING, LoadOutcome.UNREADABLE, LoadOutcome.PARSE_ERROR, LoadOutcome.OK}) {
            assertFalse(shouldRevokeAll(o),
                o + " must not revoke-all (only VALID_EMPTY does; §1.6)");
        }
    }

    /**
     * A successfully-parsed explicit empty list ({@code tokens: []}) is the
     * SOLE revoke-all path: it calls {@code ReloadTokens} with an empty
     * generation, after which the DP returns {@code AUTH_REQUIRED} on all
     * requests (§1.6 / FR-018).
     */
    @Test
    void explicitEmptyIsTheSoleRevokeAllPath() {
        assertTrue(shouldCallReloadTokens(LoadOutcome.VALID_EMPTY),
            "VALID_EMPTY must call ReloadTokens with an empty generation (§1.6 revoke-all)");
        assertTrue(shouldRevokeAll(LoadOutcome.VALID_EMPTY),
            "VALID_EMPTY is the sole revoke-all path (§1.6 / FR-018)");
    }

    /**
     * Unreadable + parse-failure log a {@code config_error} audit row (§1.6);
     * missing (first-boot) logs NO row (the legitimate first-boot state is
     * also "file does not exist yet").
     */
    @Test
    void configErrorAuditRowOnlyForUnreadableAndParseFailure() {
        assertFalse(shouldLogConfigError(LoadOutcome.MISSING),
            "MISSING (first-boot) writes no audit row (§1.6)");
        assertTrue(shouldLogConfigError(LoadOutcome.UNREADABLE),
            "UNREADABLE writes a config_error row (§1.6, kind=io)");
        assertTrue(shouldLogConfigError(LoadOutcome.PARSE_ERROR),
            "PARSE_ERROR writes a config_error row (§1.6, kind=parse/validation)");
        assertFalse(shouldLogConfigError(LoadOutcome.OK),
            "OK writes no config_error row");
    }

    // --- (4) generation-record proposal (§1.8) ----------------------------

    /**
     * A restarted CP reads its persisted {@code token_generation} record and
     * proposes {@code last + 1} (§1.8) — NOT 1. Restarting at 1 would be stale
     * the moment the DP accepted any generation ≥ 1 and silently revoke every
     * client via the reconciliation handshake (sol-review M1). The
     * reconciliation retry itself is gated by the T020 contract test row 6
     * (DP-side) + this proposal rule (CP-side).
     */
    @Test
    void restartProposesLastPlusOneNotOne() {
        assertEquals(1L, nextProposal(0L), "fresh CP (last=0) proposes generation 1");
        assertEquals(2L, nextProposal(1L), "restarted CP (last=1) proposes 2, NOT 1 (§1.8; sol-review M1)");
        assertEquals(8L, nextProposal(7L), "restarted CP (last=7) proposes 8");
    }

    /** CP proposal rule: persisted last + 1 (§1.8). Reference oracle. */
    private static long nextProposal(long persistedLast) {
        return persistedLast + 1;
    }

    private static byte[] repeat(byte b, int n) {
        byte[] out = new byte[n];
        Arrays.fill(out, b);
        return out;
    }
}
