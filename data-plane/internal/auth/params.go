// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package auth holds the data-plane authentication primitives: the shared
// verifier-construction constants and the candidate-side token verifier.
//
// The constants below are the amended v1 design point from
// specs/001-tor-route/data-model.md §1.5 (T092 / sol-review B5+M1): the
// verifier is HMAC-SHA-256 over the install-time pepper — the retired
// slow-KDF + per-token-salt design is gone (a bearer token is a uniformly
// random 128-bit value, so a slow KDF bought nothing while its 64 MiB
// allocation was an unauthenticated memory-DoS vector). Both planes MUST
// agree on these values; the CP-side mirror lands with T035's TokenLoader
// path, and a mismatch is surfaced as "all auth fails" (§1.5).
package auth

const (
	// PepperLen is the install-time pepper length in bytes
	// (data-model.md §1.5/§1.7: openssl rand -bytes 32, generated once
	// at init, shared by both planes via /etc/stargate/keys/pepper.key).
	PepperLen = 32
	// VerifierAlgo is the verifier-construction algorithm identifier
	// both planes agree on (data-model.md §1.5).
	VerifierAlgo = "HMAC-SHA-256"
)
