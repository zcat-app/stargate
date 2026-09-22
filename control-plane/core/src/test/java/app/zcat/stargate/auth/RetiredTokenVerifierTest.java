// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Guards T092's retirement of the token KDF (data-model.md §1.5; T143). */
class RetiredTokenVerifierTest {

    @Test
    void retiredArgon2idParametersAreNotAvailable() throws ClassNotFoundException {
        // Positive control: inspect the same classpath that contains the active minter.
        assertSame(HmacVerifierMinter.class,
            Class.forName("app.zcat.stargate.auth.HmacVerifierMinter"));
        assertThrows(ClassNotFoundException.class,
            () -> Class.forName("app.zcat.stargate.auth.Argon2idParams"),
            "T092 retired the bearer-token KDF; its parameters must not remain available");
    }
}
