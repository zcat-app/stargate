// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The production {@link TokenLoaderContract.VerifierMinter} (data-model.md
 * §1.5, T092): {@code verifier = HMAC-SHA-256(pepper, tokenUtf8)} — one
 * 32-byte tag, no per-token salt (single shared install-time pepper). The
 * wiring that reads {@code /etc/stargate/keys/pepper.key} and constructs this
 * minter is T041's; the loader (T035) is pepper-agnostic by construction.
 *
 * <p><strong>The minter does NOT clear or retain its input buffer.</strong>
 * The contract (T035a) reserves the mint-then-clear step for the CALLER —
 * the loader fills a mutable {@code byte[]} with one record's UTF-8 bytes,
 * mints, and zeroes that buffer before the next record (§1.1 narrowed
 * erasure claim). A clearing minter would make that caller-side clear
 * unobservable and TokenLoaderTest's buffer assertion tautological. The
 * pepper lives for the process lifetime here; §1.6 makes no zeroing claim
 * for it (THREAT-MODEL §2.8 scopes process-memory attackers out), and it is
 * never logged (the class carries no logging at all).
 *
 * <p>Determinism is load-bearing: the same (pepper, token) pair must mint
 * the same verifier across boots and across the CP/DP pepper share, or
 * cold-start restore and restart-safe generations break (§1.5; pinned by
 * {@code TokenLifecycleContractTest}).
 */
public final class HmacVerifierMinter implements TokenLoaderContract.VerifierMinter {

    /** §1.7: the install-time pepper is exactly 32 random bytes. */
    public static final int PEPPER_LEN = 32;

    private static final String HMAC_ALGO = "HmacSHA256";

    private final SecretKeySpec key;

    /**
     * @param pepper the 32-byte install-time pepper (edge-validated here:
     *               a wrong-length pepper is a provisioning error and must
     *               fail at construction, not mint every record garbage)
     */
    public HmacVerifierMinter(byte[] pepper) {
        if (pepper == null || pepper.length != PEPPER_LEN) {
            throw new IllegalArgumentException(
                "pepper must be exactly " + PEPPER_LEN + " bytes (data-model.md §1.7), got "
                    + (pepper == null ? "null" : pepper.length));
        }
        this.key = new SecretKeySpec(Arrays.copyOf(pepper, pepper.length), HMAC_ALGO);
    }

    @Override
    public byte[] mint(byte[] tokenUtf8) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(key);
            return mac.doFinal(tokenUtf8);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable: " + e.getMessage(), e);
        }
    }
}
