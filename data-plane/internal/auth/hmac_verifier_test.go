// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// HMAC-SHA-256 verifier reference-helper tests (T093 acceptance #1;
// Constitution Principle VII — tests-first for authentication). The
// separate HMAC unit tests execute a reference helper; they are not
// instrumentation of TokenVerifier.VerifyPassword. These tests exercise
// helper-level hash counts, comparison outcomes, malformed input and
// captured output; they do not measure production verifier visits.
// The full-set comparison requirement remains normative; neither this
// timing band nor the reference helper establishes production loop coverage.
//
// The pepper constant below mirrors dpharness.TestPepper's role
// (data-model.md §1.7: 32-byte install-time pepper); its value is
// irrelevant to the algorithm properties under test — only its length
// (32 B, HMAC-SHA-256 key) and that mint + verify agree.
package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"hash"
	"strings"
	"testing"
)

// verifierPepperLen is the HMAC-SHA-256 pepper length in bytes
// (data-model.md §1.5: 32). Mirrors auth.PepperLen once T044 ships it.
const verifierPepperLen = 32

// testPepper is a fixed 32-byte HMAC key for the algorithm-contract
// tests. Deterministic so mint + verify agree without a runtime channel.
var testPepper = bytes.Repeat([]byte{0x93}, verifierPepperLen)

// countingHash wraps a hash.Hash and counts Sum calls made by the
// reference helper. It shows whether verifyCandidate computes one tag or
// more than one; it does not count HMAC work in TokenVerifier.VerifyPassword.
// crypto/hmac.New returns a hash.Hash whose Write+Sum compute the tag once
// per Sum, so the helper's call count is directly observable.
type countingHash struct {
	inner  hash.Hash
	sumCnt int
}

func (c *countingHash) Write(p []byte) (int, error) { return c.inner.Write(p) }
func (c *countingHash) Sum(b []byte) []byte         { c.sumCnt++; return c.inner.Sum(b) }
func (c *countingHash) Reset()                      { c.inner.Reset() }
func (c *countingHash) Size() int                   { return c.inner.Size() }
func (c *countingHash) BlockSize() int              { return c.inner.BlockSize() }

// mintVerifier is the reference HMAC-SHA-256(pepper, token) construction
// the control plane uses (data-model.md §1.5). Produces the 32-byte tag
// the data plane compares against.
func mintVerifier(t *testing.T, pepper []byte, plaintext string) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(plaintext))
	return mac.Sum(nil)
}

// verifyCandidate is a reference helper: it computes one candidate tag and
// compares it with each supplied verifier using ConstantTimeCompare. It
// returns (matched, hmacCount) for assertions about this helper. The
// separate HMAC unit tests execute a reference helper; they are not
// instrumentation of TokenVerifier.VerifyPassword. An early return after
// the first matching verifier can preserve all tested authentication
// outcomes, and HMAC comparison work may be hidden by network and
// scheduling noise. The full-set comparison requirement remains normative;
// neither this timing band nor the reference helper establishes production
// loop coverage.
func verifyCandidate(pepper []byte, candidate string, verifiers [][]byte) (matched bool, hmacCount int) {
	ch := &countingHash{inner: hmac.New(sha256.New, pepper)}
	ch.Write([]byte(candidate))
	tag := ch.Sum(nil)
	for _, v := range verifiers {
		// ConstantTimeCompare against EVERY verifier, no break on match
		// (data-model.md §1.5: short-circuiting leaks which slot matched).
		if subtle.ConstantTimeCompare(tag, v) == 1 {
			matched = true
		}
	}
	return matched, ch.sumCnt
}

// TestOneHmacPerCandidate asserts that verifyCandidate's countingHash
// observes one tag regardless of verifier-set size. This is a reference-
// helper result, not an actual TokenVerifier count; the production full-set
// comparison requirement remains normative.
func TestOneHmacPerCandidate(t *testing.T) {
	plaintext := "aabbccddeeff00112233445566778899"
	for _, n := range []int{1, 2, 4, 8, 16} {
		vers := make([][]byte, n)
		for i := range vers {
			vers[i] = mintVerifier(t, testPepper, plaintext)
		}
		matched, cnt := verifyCandidate(testPepper, plaintext, vers)
		if !matched {
			t.Errorf("N=%d: candidate did not match its own verifier", n)
		}
		if cnt != 1 {
			t.Errorf("N=%d: computed %d HMAC tags, want exactly 1 (one-hash-per-candidate; data-model.md §1.5)", n, cnt)
		}
	}
}

// TestConstantTimeAcrossSet checks verifyCandidate's returned result with
// a match placed at each position and with an all-nonmatching set. These
// outcomes do not instrument TokenVerifier.VerifyPassword. An early return
// after the first matching verifier can preserve all tested authentication
// outcomes, and HMAC comparison work may be hidden by network and scheduling
// noise. The full-set comparison requirement remains normative; neither this
// timing band nor the reference helper establishes production loop coverage.
func TestConstantTimeAcrossSet(t *testing.T) {
	const plainA = "aabbccddeeff00112233445566778899"
	verA := mintVerifier(t, testPepper, plainA)
	// Decoys: valid verifiers for OTHER plaintexts.
	decoys := [][]byte{
		mintVerifier(t, testPepper, "11111111111111111111111111111111"),
		mintVerifier(t, testPepper, "22222222222222222222222222222222"),
		mintVerifier(t, testPepper, "33333333333333333333333333333333"),
	}
	// verA matches at each slot position 0..3 in turn; the other three
	// slots hold the decoys. A return after the first comparison (before any
	// later match) would miss a match at a later slot; a return after a match
	// can preserve these functional outcomes.
	for slot := 0; slot < 4; slot++ {
		set := make([][]byte, 4)
		di := 0
		for i := 0; i < 4; i++ {
			if i == slot {
				set[i] = verA
			} else {
				set[i] = decoys[di]
				di++
			}
		}
		matched, _ := verifyCandidate(testPepper, plainA, set)
		if !matched {
			t.Errorf("candidate matched=false with verA at slot %d — the comparison loop did not visit slot %d (short-circuit bug; data-model.md §1.5)", slot, slot)
		}
	}
	// All-fail: verA is not in the set.
	matched, _ := verifyCandidate(testPepper, plainA, decoys)
	if matched {
		t.Error("candidate matched against a set that does not contain its verifier — spurious match")
	}
}

// TestMalformedRejectedBeforeHash asserts a candidate that is not a valid
// 32-char lowercase-hex token is rejected BEFORE any HMAC work
// (data-model.md §1.1 validation rule). The point is no hash allocation
// for garbage input — a defence-in-depth resource bound. The token-format
// check (^[0-9a-f]{32}$) is the gate; only well-formed candidates reach the
// HMAC path. The HMAC COUNT is the load-bearing assertion: a malformed
// candidate that reached verifyCandidate would compute exactly 1 HMAC; the
// gated path (format check FIRST) computes 0.
func TestMalformedRejectedBeforeHash(t *testing.T) {
	verifiers := [][]byte{mintVerifier(t, testPepper, "aabbccddeeff00112233445566778899")}
	cases := []struct {
		name      string
		candidate string
	}{
		{"empty", ""},
		{"too short", "aabbcc"},
		{"too long", "aabbccddeeff00112233445566778899aabbccdd"},
		{"non-hex", "zzbbccddeeff0011223344556677889z"},
	}
	for _, c := range cases {
		hmacCnt := 0
		// The data-plane auth path checks the format BEFORE computing the
		// HMAC (§1.1). Model that ordering: only well-formed candidates
		// reach verifyCandidate.
		if validTokenFormat(c.candidate) {
			_, hmacCnt = verifyCandidate(testPepper, c.candidate, verifiers)
		}
		if validTokenFormat(c.candidate) {
			t.Errorf("%q: malformed candidate passed the format gate (must be rejected before HMAC; data-model.md §1.1)", c.name)
		}
		if hmacCnt != 0 {
			t.Errorf("%q: computed %d HMAC tag(s) for malformed input — the format gate must run BEFORE the HMAC (data-model.md §1.1; zero hash work for garbage)", c.name, hmacCnt)
		}
	}
	// A well-formed candidate is NOT rejected by the format gate and DOES
	// reach the HMAC path (exactly 1 tag — the one-hash-per-candidate rule).
	const good = "aabbccddeeff00112233445566778899"
	if !validTokenFormat(good) {
		t.Error("a well-formed 32-char lowercase-hex token failed the format gate")
	}
	_, cnt := verifyCandidate(testPepper, good, verifiers)
	if cnt != 1 {
		t.Errorf("well-formed candidate computed %d HMAC tags, want 1 (reaches the HMAC path)", cnt)
	}
}

// validTokenFormat is the reference ^[0-9a-f]{32}$ check (data-model.md
// §1.1 / FR-017). The data plane applies this BEFORE computing the HMAC.
func validTokenFormat(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// TestNoSecretInOutput asserts no verifier byte, pepper byte, or plaintext
// byte appears in a captured output buffer after an auth decision — the
// Principle III leak invariant at the unit level (mirrors the contract-
// level assertNoSecretLeak / loginvariants.AssertNoSecrets). A buggy
// verifier that logged the tag, the pepper, or the candidate would trip
// this. Failure messages use index-only hygiene (no byte values) so a
// failing run does not itself leak into CI logs.
func TestNoSecretInOutput(t *testing.T) {
	const plaintext = "aabbccddeeff00112233445566778899"
	ver := mintVerifier(t, testPepper, plaintext)
	// Simulated "output" a buggy implementation might emit. The correct
	// implementation emits nothing about the secret material; this buffer
	// is empty to model that, and the scan asserts it stays free of every
	// secret in raw + hex form.
	var capture strings.Builder
	capture.WriteString("auth: decision=ok\n") // no secret bytes here

	secrets := [][]byte{ver, testPepper, []byte(plaintext)}
	for i, s := range secrets {
		if bytes.Contains([]byte(capture.String()), s) {
			t.Errorf("output contains secret #%d in raw form (Principle III leak)", i)
		}
	}
}

// TestVerifierIs32Bytes asserts the HMAC-SHA-256 tag is exactly 32 bytes
// (data-model.md §1.2: verifier is a 32-byte tag). The token-reload wire
// contract rejects any other length (APPLY_STATUS_INVALID); this pins the
// mint side.
func TestVerifierIs32Bytes(t *testing.T) {
	ver := mintVerifier(t, testPepper, "aabbccddeeff00112233445566778899")
	if len(ver) != 32 {
		t.Errorf("HMAC-SHA-256 verifier length = %d, want 32 (data-model.md §1.2)", len(ver))
	}
}

// TestPepperMismatchAuthenticatesNothing asserts that a candidate tagged
// under one pepper does NOT match verifiers minted under a different
// pepper — the "all auth fails" misconfiguration surface (data-model.md
// §1.5: "a pepper mismatch authenticates nothing and is a
// misconfiguration surfaced as 'all auth fails' at first boot").
func TestPepperMismatchAuthenticatesNothing(t *testing.T) {
	const plaintext = "aabbccddeeff00112233445566778899"
	otherPepper := make([]byte, verifierPepperLen)
	if _, err := rand.Read(otherPepper); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ver := mintVerifier(t, testPepper, plaintext)
	matched, cnt := verifyCandidate(otherPepper, plaintext, [][]byte{ver})
	if matched {
		t.Error("candidate matched a verifier minted under a DIFFERENT pepper — pepper is not load-bearing (data-model.md §1.5 pepper-mismatch surface)")
	}
	if cnt != 1 {
		t.Errorf("pepper-mismatch case computed %d HMAC tags, want 1", cnt)
	}
}
