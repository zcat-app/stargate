// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

// TestSharedVerifierConstantsMatchSpec pins the shared verifier-construction
// constants to specs/001-tor-route/data-model.md §1.5/§1.7 (amended by T092:
// HMAC-SHA-256 over the install-time pepper — the retired slow-KDF parameter
// set is gone). Both planes MUST agree on these values; the CP-side mirror
// lands with T035's TokenLoader path, and a mismatch is surfaced as "all
// auth fails" (§1.5). Constitution Principle VII: the auth parameter path is
// privacy-critical, so the test lands before / alongside the constants.
func TestSharedVerifierConstantsMatchSpec(t *testing.T) {
	if PepperLen != 32 {
		t.Errorf("PepperLen = %d, want 32 (data-model.md §1.5/§1.7: 32 random bytes, openssl rand -bytes 32)", PepperLen)
	}
	if VerifierAlgo != "HMAC-SHA-256" {
		t.Errorf("VerifierAlgo = %q, want %q (data-model.md §1.5)", VerifierAlgo, "HMAC-SHA-256")
	}
}
