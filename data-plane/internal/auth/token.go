// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package auth

// token.go — the candidate-side token verifier (T044) and the token
// generation store (data-model.md §1.3). Contract:
// specs/001-tor-route/data-model.md §1.2/§1.3/§1.5/§1.7, amended by T092;
// the algorithm-level executable spec is the T093 test set in
// hmac_verifier_test.go (same package). The listener-facing seam is
// listener.Verifier (T042), satisfied structurally — auth imports stdlib
// only; T050 wires the concrete type into Deps.Auth / ConnectDeps.Auth.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// PepperFile is the pepper's file name inside the keys dir
// (data-model.md §1.7; dpharness writes its TestPepper here — the
// test-defined contract surface this loader conforms to).
const PepperFile = "pepper.key"

// DefaultKeysDir is the production location of the stargate-keys volume
// mount (data-model.md §1.7). Alternative deployments override the
// directory via STARGATE_KEYS_DIR — resolved by the startup sequence
// (T050), not here.
const DefaultKeysDir = "/etc/stargate/keys"

// Generation is one complete, atomically-replaced verifier set
// (data-model.md §1.3).
type Generation struct {
	// Generation is the monotonic counter the control plane assigns
	// (§1.8); T045's token-reload handler rejects stale proposals
	// against it (APPLY_STATUS_STALE_GENERATION).
	Generation uint64
	// Verifiers is the complete current set — each entry a 32-byte
	// HMAC-SHA-256 tag under the install-time pepper (§1.2). The set
	// swaps as a unit; a stored verifier is never mutated in place.
	Verifiers [][]byte
	// LoadedAt is wall-clock when the generation was received — used
	// only for restart journal logs (§1.3), never per-request.
	LoadedAt time.Time
}

// TokenStore holds the single current generation under one atomic pointer
// (data-model.md §1.3): readers load the pointer per request; writers
// (T045's token-reload handler, T046's snapshot restore, T050's boot)
// swap it. In-flight requests complete against the generation they
// loaded; the replaced one is garbage once the last reader drops it.
type TokenStore struct {
	cur atomic.Pointer[Generation]
}

// NewTokenStore returns a store at the empty generation — the revoke-all
// state: nothing authenticates until a generation is installed (FR-018).
// It is never nil, so consumers need no nil check inside the trust
// boundary (CONTRIBUTING doctrine).
func NewTokenStore() *TokenStore {
	s := &TokenStore{}
	s.Swap(&Generation{})
	return s
}

// Current returns the live generation pointer.
func (s *TokenStore) Current() *Generation { return s.cur.Load() }

// Swap atomically replaces the current generation (data-model.md §1.3).
func (s *TokenStore) Swap(g *Generation) { s.cur.Store(g) }

// TokenVerifier authenticates inbound bearer-token candidates against the
// current generation — the listener.Verifier seam (T042). It holds the
// install-time pepper for the process lifetime: the same pepper the
// control plane used to mint the stored verifiers (§1.5). A same-length
// different pepper boots and authenticates nothing — the §1.5 "all auth
// fails" misconfiguration surface, by design.
type TokenVerifier struct {
	pepper [PepperLen]byte
	tokens *TokenStore
}

// NewTokenVerifier wires the candidate-side verifier. The pepper arrives
// fixed-size ([PepperLen]byte): a wrong-length pepper cannot compile —
// the loud-failure path for a corrupt install lives in LoadPepper.
func NewTokenVerifier(pepper [PepperLen]byte, tokens *TokenStore) *TokenVerifier {
	return &TokenVerifier{pepper: pepper, tokens: tokens}
}

// VerifyPassword reports whether candidate matches any verifier in the
// current generation. Per data-model.md §1.5 (and the T093 contract):
//
//   - the ^[0-9a-f]{32}$ format gate runs FIRST: the candidate arrives as
//     raw RFC 1929 PASSWD bytes (1–255 opaque bytes), and a malformed one
//     costs zero hash work and zero allocations (§1.1; T093 must-hold);
//   - the candidate's tag is computed exactly ONCE — per-request hash
//     work and allocation are O(1) in the set size (sol-review B5; the
//     retired slow-KDF path allocated 64 MiB per hash);
//   - the tag is compared with subtle.ConstantTimeCompare against EVERY
//     verifier, NO short-circuit on first match — loop timing is
//     independent of which slot (if any) matched.
//
// Nothing about the candidate, the pepper, or the verifiers is logged or
// returned (Principle III; §1.6) — there is no log or error path at all.
func (v *TokenVerifier) VerifyPassword(candidate []byte) bool {
	if !isWellFormedToken(candidate) {
		return false
	}
	mac := hmac.New(sha256.New, v.pepper[:])
	mac.Write(candidate)
	tag := mac.Sum(nil)

	matched := false
	for _, verifier := range v.tokens.Current().Verifiers {
		if subtle.ConstantTimeCompare(tag, verifier) == 1 {
			matched = true // no break — every verifier is compared, every request
		}
	}
	return matched
}

// isWellFormedToken is the §1.1/FR-017 format rule ^[0-9a-f]{32}$,
// allocation-free. (hmac_verifier_test.go carries an independent reference
// copy — tests pin the spec, not the implementation's helper.)
func isWellFormedToken(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// LoadPepper reads the install-time pepper from keysDir/pepper.key
// (data-model.md §1.7). A file of any length other than PepperLen is a
// corrupt install and fails loudly at boot: HMAC accepts any key length,
// so a silently-truncated pepper would run forever authenticating
// nothing. The §1.5 pepper-MISMATCH surface (same length, different
// bytes) is different: it boots and authenticates nothing by design.
// Errors carry the path and byte count only — never file bytes
// (Principle III; §1.6). The loader zeroes the buffer it allocated after
// copying into the returned value; the deliberately-narrow erasure claim
// covers only this buffer (§1.1's honesty note).
func LoadPepper(keysDir string) ([PepperLen]byte, error) {
	var pepper [PepperLen]byte
	path := filepath.Join(keysDir, PepperFile)
	buf, err := os.ReadFile(path)
	if err != nil {
		return pepper, fmt.Errorf("reading pepper %s: %w", path, err)
	}
	if len(buf) != PepperLen {
		return pepper, fmt.Errorf("pepper %s is %d bytes, want %d — corrupt install; provision per data-model.md §1.7",
			path, len(buf), PepperLen)
	}
	copy(pepper[:], buf)
	clear(buf)
	return pepper, nil
}
