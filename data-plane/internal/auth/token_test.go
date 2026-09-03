// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// API-level unit tests for the candidate-side token verifier (T044) —
// authored BEFORE token.go existed (Constitution Principle VII:
// authentication is tests-first, no AI exception). The initial red state is
// the compile failure against the not-yet-written symbols; the green state
// is token.go conforming to the algorithm contract T093 pinned in
// hmac_verifier_test.go — this file deliberately reuses that file's
// reference helpers (testPepper) so the implementation under test agrees
// with the reference construction, data-model.md §1.5.
//
// Failure messages carry indexes and lengths only — never candidate,
// pepper, or verifier bytes (Principle III; T093 residue note).
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// verifierSeam mirrors listener.Verifier (T042) without importing the
// listener package (auth stays stdlib-only): if TokenVerifier's method
// set drifts, this assertion breaks the build here instead of surfacing
// at T050 wiring time.
var _ verifierSeam = (*TokenVerifier)(nil)

type verifierSeam interface {
	VerifyPassword(candidate []byte) bool
}

const unitPlaintext = "aabbccddeeff00112233445566778899"

// unitPepper converts the T093 reference testPepper ([]byte) into the
// fixed-size array the pepper API traffics in — a wrong-length pepper is
// a compile error at NewTokenVerifier, not a runtime surprise.
func unitPepper() [PepperLen]byte {
	var p [PepperLen]byte
	copy(p[:], testPepper)
	return p
}

// unitPepperOther is a same-length, different pepper — the §1.5 "all auth
// fails" misconfiguration surface.
func unitPepperOther() [PepperLen]byte {
	var p [PepperLen]byte
	for i := range p {
		p[i] = 0x11
	}
	return p
}

// refVerifier mints the reference HMAC-SHA-256 tag of plaintext under the
// shared testPepper (what the control plane would store, §1.2/§1.5).
func refVerifier(plaintext string) []byte {
	return refVerifierUnder(testPepper, plaintext)
}

func refVerifierUnder(pepper []byte, plaintext string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(plaintext))
	return mac.Sum(nil)
}

// decoyToken renders distinct well-formed token plaintexts, so a decoy
// can never accidentally match the token under test.
func decoyToken(i int) string { return fmt.Sprintf("%032x", i+1) }

// newUnitVerifier returns a verifier over a fresh (revoke-all) store.
func newUnitVerifier() (*TokenVerifier, *TokenStore) {
	store := NewTokenStore()
	return NewTokenVerifier(unitPepper(), store), store
}

// TestVerifyPasswordAcceptsFirstAndLastSlot pins slot-invariance: a match
// at the FIRST and at the LAST slot of an 8-verifier set both authenticate
// (data-model.md §1.5 — the comparison visits EVERY verifier, no
// short-circuit on first match; T093's TestConstantTimeAcrossSet pins the
// same property at algorithm level, this one at the shipped API).
func TestVerifyPasswordAcceptsFirstAndLastSlot(t *testing.T) {
	const set = 8
	for _, slot := range []int{0, set - 1} {
		v, store := newUnitVerifier()
		verifiers := make([][]byte, set)
		for i := range verifiers {
			verifiers[i] = refVerifier(decoyToken(i))
		}
		verifiers[slot] = refVerifier(unitPlaintext)
		store.Swap(&Generation{Generation: 7, Verifiers: verifiers})

		if !v.VerifyPassword([]byte(unitPlaintext)) {
			t.Errorf("slot %d: the matching candidate did not authenticate — the comparison loop did not reach slot %d (short-circuit bug; data-model.md §1.5)", slot, slot)
		}
	}
}

// TestVerifyPasswordRejectsFailureFamily pins the whole rejection surface:
// well-formed-but-wrong, malformed shapes, the pepper mismatch, and the
// empty (revoke-all) generation must all fail. The failure REPLIES are the
// listener's contract (byte-identical `01 FF`); this pins the seam's
// boolean, which is the only signal the listener gets.
func TestVerifyPasswordRejectsFailureFamily(t *testing.T) {
	v, store := newUnitVerifier()
	store.Swap(&Generation{Generation: 1, Verifiers: [][]byte{refVerifier(unitPlaintext)}})

	cases := []struct {
		name string
		cand []byte
	}{
		{"wrong but well-formed", []byte(decoyToken(99))},
		{"empty", []byte("")},
		{"nil", nil},
		{"too short", []byte("aabbcc")},
		{"too long", []byte(unitPlaintext + "aabb")},
		{"non-hex", []byte("zzbbccddeeff0011223344556677889z")},
		{"uppercase hex (format is lowercase-only)", []byte("AABBCCDDEEFF00112233445566778899")},
		{"high-bit byte (31 bytes: exercises the length half)", []byte("aabbccddeeff001122334455667788\x80")},
	}
	for i, c := range cases {
		if v.VerifyPassword(c.cand) {
			t.Errorf("case %d (%s): candidate authenticated — must be rejected (FR-006)", i, c.name)
		}
	}

	// Pepper mismatch (§1.5): verifiers minted under a different pepper
	// authenticate nothing — "all auth fails" is the honest surface.
	mismatch := NewTokenVerifier(unitPepperOther(), store)
	if mismatch.VerifyPassword([]byte(unitPlaintext)) {
		t.Error("pepper mismatch: candidate authenticated — the pepper is not load-bearing (data-model.md §1.5)")
	}

	// Revoke-all (FR-018): swapping to an empty generation authenticates
	// nothing immediately.
	store.Swap(&Generation{Generation: 2})
	if v.VerifyPassword([]byte(unitPlaintext)) {
		t.Error("empty generation: candidate authenticated — revoke-all must hold (FR-018)")
	}
}

// TestVerifyPasswordAllocsO1 pins the sol-review B5 fix at the API level:
// per-request allocations are O(1) in the verifier-set size, and the
// malformed path costs ZERO allocations — the format gate precedes any
// HMAC work (data-model.md §1.1; T093 must-hold "no hash allocated for
// garbage"). The N-independence assertion is load-bearing; the absolute
// bound is generous slack for stdlib-internal allocation drift.
func TestVerifyPasswordAllocsO1(t *testing.T) {
	v, store := newUnitVerifier()

	swap := func(n int) {
		verifiers := make([][]byte, n)
		for i := range verifiers {
			verifiers[i] = refVerifier(decoyToken(i))
		}
		store.Swap(&Generation{Generation: 1, Verifiers: verifiers})
	}

	good := []byte(unitPlaintext)
	allocsFor := func(n int) float64 {
		swap(n)
		probe := func() { v.VerifyPassword(good) }
		probe() // warm-up outside the counter
		return testing.AllocsPerRun(200, probe)
	}
	a1, a64 := allocsFor(1), allocsFor(64)
	if a1 != a64 {
		t.Errorf("allocs per auth: N=1 → %v vs N=64 → %v — must be O(1) in the set size (data-model.md §1.5; sol-review B5)", a1, a64)
	}
	if a1 > 16 {
		t.Errorf("allocs per auth = %v, want a small fixed bound (≤16)", a1)
	}

	// The malformed path costs ZERO allocations — the format gate precedes
	// any HMAC work (data-model.md §1.1; T093 must-hold). BOTH halves of
	// the gate are probed: a wrong-LENGTH candidate and a wrong-CHARSET
	// one (32 bytes, non-hex). The charset probe is load-bearing: with
	// only the length check, a 32-byte non-hex candidate would reach the
	// HMAC and allocate.
	for i, malformed := range [][]byte{
		[]byte("zz"), // length half
		[]byte("zzbbccddeeff0011223344556677889z"), // charset half (len 32)
	} {
		swap(4)
		probe := func() { v.VerifyPassword(malformed) }
		probe()
		if got := testing.AllocsPerRun(200, probe); got != 0 {
			t.Errorf("malformed candidate #%d allocated %v times — the format gate must precede any HMAC work (data-model.md §1.1; T093 must-hold)", i, got)
		}
	}
}

// TestTokenStoreSwapSemantics pins the §1.3 store contract: the zero store
// is a valid empty generation (revoke-all, never nil); Swap replaces the
// whole set atomically; the monotonic generation number stays readable for
// T045's stale-rejection check.
func TestTokenStoreSwapSemantics(t *testing.T) {
	store := NewTokenStore()
	cur := store.Current()
	if cur == nil {
		t.Fatal("fresh store: Current() = nil — the store must start at a valid empty generation, never nil")
	}
	if len(cur.Verifiers) != 0 {
		t.Errorf("fresh store: %d verifier(s) — the zero state is the revoke-all state (FR-018)", len(cur.Verifiers))
	}
	v := NewTokenVerifier(unitPepper(), store)
	if v.VerifyPassword([]byte(unitPlaintext)) {
		t.Error("fresh store: candidate authenticated — an empty generation must authenticate nothing")
	}

	gen7 := &Generation{Generation: 7, Verifiers: [][]byte{refVerifier(unitPlaintext)}, LoadedAt: time.Now()}
	store.Swap(gen7)
	if store.Current() != gen7 {
		t.Error("Swap did not replace the current generation pointer")
	}
	if !v.VerifyPassword([]byte(unitPlaintext)) {
		t.Error("generation 7: the stored token did not authenticate")
	}

	// §1.3: the new generation's verifiers are the COMPLETE current set —
	// the old set does not survive the swap.
	gen8 := &Generation{Generation: 8, Verifiers: [][]byte{refVerifier(decoyToken(0))}}
	store.Swap(gen8)
	if v.VerifyPassword([]byte(unitPlaintext)) {
		t.Error("generation 8: a generation-7 verifier still authenticates — Swap must replace the whole set")
	}
	if got := store.Current().Generation; got != 8 {
		t.Errorf("current generation = %d, want 8 (the number T045's stale-rejection reads)", got)
	}
}

// TestSwapUnderVerifyRace exercises the §1.3 in-flight contract under
// concurrency: every request loads one generation pointer and completes
// against it while another goroutine swaps. Both boolean outcomes are
// valid per-request answers; the assertion is no data race and no panic
// (the real detector is the standalone `cd data-plane && go test -race
// ./internal/auth/ -count=1`; the green gate carries no -race — ticket
// acceptance 3, gate-flag work routed to T114).
func TestSwapUnderVerifyRace(t *testing.T) {
	v, store := newUnitVerifier()
	genA := &Generation{Generation: 1, Verifiers: [][]byte{refVerifier(unitPlaintext)}}
	genB := &Generation{Generation: 2, Verifiers: [][]byte{refVerifier(decoyToken(0))}}
	store.Swap(genA)

	cand := []byte(unitPlaintext)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			store.Swap(genA)
			store.Swap(genB)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = v.VerifyPassword(cand)
		}
	}()
	wg.Wait()
}

// TestLoadPepper pins the §1.7 loader contract: exactly PepperLen bytes
// load; missing / short / long files error at boot with messages that
// carry path and byte count only — never file bytes (§1.6: violations
// never log the offending bytes).
func TestLoadPepper(t *testing.T) {
	dir := t.TempDir()
	var want [PepperLen]byte
	for i := range want {
		want[i] = 0xC7
	}
	if err := os.WriteFile(filepath.Join(dir, PepperFile), want[:], 0o600); err != nil {
		t.Fatalf("writing pepper file: %v", err)
	}
	got, err := LoadPepper(dir)
	if err != nil {
		t.Fatalf("LoadPepper: %v", err)
	}
	if got != want {
		t.Error("LoadPepper returned bytes that do not match the file")
	}

	cases := []struct {
		name    string
		content []byte
	}{
		{"missing", nil},
		{"short (31 bytes)", []byte(strings.Repeat("p", PepperLen-1))},
		{"long (33 bytes)", []byte(strings.Repeat("p", PepperLen+1))},
	}
	for i, c := range cases {
		cdir := t.TempDir()
		if c.content != nil {
			if err := os.WriteFile(filepath.Join(cdir, PepperFile), c.content, 0o600); err != nil {
				t.Fatalf("case %d: writing pepper file: %v", i, err)
			}
		}
		got, err := LoadPepper(cdir)
		if err == nil {
			t.Errorf("case %d (%s): LoadPepper succeeded — a corrupt pepper install must fail loudly at boot", i, c.name)
			continue
		}
		if got != ([PepperLen]byte{}) {
			t.Errorf("case %d (%s): error path returned a non-zero pepper value", i, c.name)
		}
		// Error hygiene: path and length are fine; file bytes are not.
		if c.content != nil && strings.Contains(err.Error(), string(c.content)) {
			t.Errorf("case %d (%s): the error message carries file bytes (Principle III / §1.6)", i, c.name)
		}
		// Only the shape errors (short/long) carry the required length;
		// the missing-file case is a wrapped fs.ErrNotExist — there is no
		// length to report.
		if c.content != nil && !strings.Contains(err.Error(), fmt.Sprint(PepperLen)) {
			t.Errorf("case %d (%s): the error message should state the required %d-byte length", i, c.name, PepperLen)
		}
	}
}
