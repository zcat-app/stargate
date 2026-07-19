// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

// TestArgon2idParamsMatchSpec pins each Argon2id constant to its value from
// specs/001-tor-route/data-model.md §1.5. Drift on either plane surfaces as
// a test failure here; the cross-plane mirror test lives in the control
// plane at Argon2idParamsTest. Constitution Principle VII: the auth
// parameter path is privacy-critical, so the test lands before / alongside
// the constants.
func TestArgon2idParamsMatchSpec(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"time (iterations)", Argon2idTime, uint32(3)},
		{"memory (KiB) — 64 MiB", Argon2idMemoryKiB, uint32(64 * 1024)},
		{"memory (KiB) — literal 65536", Argon2idMemoryKiB, uint32(65536)},
		{"parallelism (lanes)", Argon2idParallelism, uint8(4)},
		{"hash length (bytes)", Argon2idHashLen, uint32(32)},
		{"salt length (bytes)", Argon2idSaltLen, uint32(16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s: got %v, want %v (data-model.md §1.5)", tt.name, tt.got, tt.want)
			}
		})
	}
}
