// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pins each {@link Argon2idParams} constant to its value from
 * {@code specs/001-tor-route/data-model.md} §1.5. Drift on either plane
 * surfaces as a test failure here; the cross-plane mirror test lives in
 * the data plane at {@code data-plane/internal/auth/params_test.go}.
 * Constitution Principle VII: the auth parameter path is privacy-critical,
 * so the test lands before / alongside the constants.
 */
class Argon2idParamsTest {

    @Test
    void timeMatchesSpec() {
        assertEquals(3, Argon2idParams.TIME, "data-model.md §1.5: time = 3");
    }

    @Test
    void memoryKiBMatchesSpec64MiB() {
        assertEquals(64 * 1024, Argon2idParams.MEMORY_KIB, "data-model.md §1.5: memory = 64 MiB");
    }

    @Test
    void memoryKiBMatchesSpecLiteral65536() {
        assertEquals(65536, Argon2idParams.MEMORY_KIB, "data-model.md §1.5: memory = 65 536 KiB");
    }

    @Test
    void parallelismMatchesSpec() {
        assertEquals(4, Argon2idParams.PARALLELISM, "data-model.md §1.5: parallelism = 4");
    }

    @Test
    void hashLenMatchesSpec() {
        assertEquals(32, Argon2idParams.HASH_LEN, "data-model.md §1.5: hashLen = 32 bytes");
    }

    @Test
    void saltLenMatchesSpec() {
        assertEquals(16, Argon2idParams.SALT_LEN, "data-model.md §1.5: saltLen = 16 bytes");
    }
}
