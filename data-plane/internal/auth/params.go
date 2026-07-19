// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package auth holds the data-plane authentication primitives. The Argon2id
// parameter constants below are the v1 design point from
// specs/001-tor-route/data-model.md §1.5 — both planes (Go data plane and
// Java control plane) MUST declare the same values; mismatch is a contract
// violation surfaced at handshake (data-model.md §1.5).
package auth

// Argon2id parameters — see specs/001-tor-route/data-model.md §1.5.
//
// These are the v1 design point: fast enough that per-request overhead is
// negligible (the .onion connect latency dominates by two orders of
// magnitude), slow enough that brute-forcing a leaked snapshot file is
// non-trivial. The same values are mirrored in the control plane at
// control-plane/core/src/main/java/app/zcat/stargate/auth/Argon2idParams.java.
//
// Units: Argon2id memory is expressed in KiB by every common implementation
// (golang.org/x/crypto/argon2.IDKey, argon2-jvm, BouncyCastle). 64 MiB is
// therefore 64 * 1024 = 65536 KiB — the explicit *1024 factor below is the
// load-bearing unit disambiguation that prevents the 64-vs-65536-confusion
// class of bug.
const (
	// Argon2idTime is the number of passes over the memory array.
	Argon2idTime uint32 = 3
	// Argon2idMemoryKiB is the memory cost in KiB (64 MiB).
	Argon2idMemoryKiB uint32 = 64 * 1024
	// Argon2idParallelism is the number of threads / lanes.
	Argon2idParallelism uint8 = 4
	// Argon2idHashLen is the output hash length in bytes.
	Argon2idHashLen uint32 = 32
	// Argon2idSaltLen is the per-token salt length in bytes
	// (data-model.md §1.2: each stored token has its own salt).
	Argon2idSaltLen uint32 = 16
)
