// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

/**
 * Argon2id parameters — the v1 design point from
 * {@code specs/001-tor-route/data-model.md} §1.5.
 *
 * <p>Both planes (this Java control plane and the Go data plane at
 * {@code data-plane/internal/auth/params.go}) MUST declare the same values;
 * mismatch is a contract violation surfaced at handshake (data-model.md
 * §1.5).
 *
 * <p><b>Units.</b> Argon2id memory is expressed in KiB by every common
 * implementation (argon2-jvm, BouncyCastle, {@code golang.org/x/crypto/argon2}).
 * 64 MiB is therefore {@code 64 * 1024 = 65536} KiB — the explicit
 * {@code * 1024} factor below is the load-bearing unit disambiguation that
 * prevents the 64-vs-65536-confusion class of bug.
 *
 * <p>These are compile-time constants; the hashing code that consumes them
 * lands in a later task.
 */
public final class Argon2idParams {

    private Argon2idParams() {
        // Constants only — no instances.
    }

    /** Number of passes over the memory array. */
    public static final int TIME = 3;

    /** Memory cost in KiB (64 MiB). */
    public static final int MEMORY_KIB = 64 * 1024;

    /** Number of threads / lanes. */
    public static final int PARALLELISM = 4;

    /** Output hash length in bytes. */
    public static final int HASH_LEN = 32;

    /** Per-token salt length in bytes (data-model.md §1.2). */
    public static final int SALT_LEN = 16;
}
