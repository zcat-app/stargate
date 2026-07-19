// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the SOCKS5 AUTH_REQUIRED failure surface — the
// 2-byte RFC 1929 reply `0x01 0xFF` then close, with no further bytes
// and no distinguishing substring across the AUTH_REQUIRED family.
// Specs/contracts:
//   - specs/001-tor-route/contracts/socks5-auth.md §"Auth failure
//     response" (the byte sequence + close + "no distinguishing
//     substring across missing/malformed/empty cases"; FR-006/FR-009).
//   - specs/001-tor-route/research.md §9 — the two-framing split: the
//     SOCKS5 failure is a fixed 2-byte binary response, NOT the HTML
//     template (which is CONNECT-only). SOCKS5 has no syntactic gate
//     on PASSWD, so malformed candidates funnel through hash+compare-
//     fail to the same `0x01 0xFF`.
//
// This is the SOCKS5-path analogue of T027 (HTTP CONNECT
// AUTH_REQUIRED template shape) and the AUTH_REQUIRED-family
// complement to T025 (a), which gates the byte-exact `0x01 0xFF` +
// close + no-trailing-bytes shape for the valid-format-but-wrong
// (near-miss password against a populated generation) case. T028
// does NOT re-assert that case; its distinct contribution is:
//
//	(a) the empty-generation case (no tokens loaded — the canonical
//	    AUTH_REQUIRED scenario; T025 always loads a valid token first),
//	(b) syntactically malformed PASSWD (wrong length, non-hex) against
//	    a populated generation,
//	(c) the cross-case byte-identity invariant no other test asserts —
//	    the full response captures across all AUTH_REQUIRED cases are
//	    byte-for-byte identical to each other AND equal to [0x01, 0xFF]
//	    exactly.
//
// Tests-first (Constitution Principle VII) for T042
// (listener RFC 1929 framing) and T044 (auth/token.go HMAC-SHA-256
// verification, including the empty-generation fail path). The test
// self-skips until T042/T044/T045/T050 land; once they do, a byte-
// shape or cross-case identity regression is FAIL, not SKIP.
package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
)

// wellFormedPasswd is a syntactically-valid 32-char hex bearer-token
// plaintext used as the PASSWD for the empty-generation capture in
// sub-test (c). When the generation is empty ANY offer fails, so a
// well-formed offer is the canonical AUTH_REQUIRED shape: the client
// did everything right, the server simply has no token provisioned.
// Distinct from the sibling tests' plaintexts so a corpus-scan hit
// (none expected on the SOCKS5 path — there is no body) is
// attributable to this test.
const wellFormedPasswd = "11223344556677889900aabbccddeeff"

// malformedPasswdCases enumerates the syntactic-malformation modes a
// buggy implementation could special-case with a distinct response.
// SOCKS5 has no syntactic gate (research.md §9), so each candidate is
// hashed + compared against the populated generation and fails the
// comparison — yielding the same `0x01 0xFF` as any other failure.
// All entries are within RFC 1929's 1–255 PASSWD length range (they
// are malformed as TOKENS, not as SOCKS5 framing); doSubnegotiation's
// length guard therefore accepts them.
var malformedPasswdCases = []struct {
	label  string
	passwd string
}{
	// 8 chars — well under the 32-char token width.
	{"WrongLength_Short", "tooshort"},
	// 33 chars — one over the 32-char token width; still valid SOCKS5
	// PASSWD (≤255 bytes).
	{"WrongLength_Long", "0011223344556677889900aabbccddeeff00"},
	// 32 chars containing non-hex letters — length matches the token
	// width but the charset does not.
	{"NonHex_32chars", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
}

// TestAUTHRequiredSOCKS5Path pins the SOCKS5 AUTH_REQUIRED byte
// contract and the cross-case no-distinguishing-substring invariant.
// Sub-tests are independent (each boots its own DP via
// dpharness.Start) so a failure in one does not cascade.
func TestAUTHRequiredSOCKS5Path(t *testing.T) {
	// Per-sub-test gate beyond the boot minimum inside dpharness.Start
	// (T042/T045/T050): the AUTH_REQUIRED failure path lives in
	// auth/token.go (T044) — both the empty-generation fail (nothing
	// to compare) and the hash+compare-fail for malformed candidates.
	authGate := filepath.Join(dpharness.FindRepoRoot(t), "data-plane", "internal", "auth", "token.go")
	requireAuth := func(t *testing.T) {
		t.Helper()
		dpharness.RequireFile(t, authGate,
			"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	}

	// (a) EmptyGeneration_ReplyIsExact_01FF_ThenClose: boot the DP and
	// do NOT call ReloadTokens — the token generation is empty, the
	// canonical AUTH_REQUIRED state. Send a well-formed RFC 1929
	// sub-negotiation; assert the reply is byte-exactly `01 FF` and
	// the connection closes with no further bytes.
	//
	// contracts/socks5-auth.md §"Auth failure response": "OR the
	// generation is empty" → `0x01 0xFF` then close.
	t.Run("EmptyGeneration_ReplyIsExact_01FF_ThenClose", func(t *testing.T) {
		requireAuth(t)
		h := dpharness.Start(t)
		// Deliberately NO ReloadTokens: the generation is empty.

		conn := dialProxy(t, h)
		defer conn.Close()
		// 30 s covers HMAC auth on a populated path; the empty-
		// generation fail is faster, but the same deadline shape as
		// the auth-success siblings avoids a per-test surprise when
		// T044 lands.
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		doMethodNegotiation(t, conn)
		reply := doSubnegotiation(t, conn, "t028-empty-gen", wellFormedPasswd)
		if want := []byte{0x01, 0xFF}; !bytes.Equal(reply, want) {
			t.Fatalf("empty-generation sub-negotiation reply = %x, want %x — "+
				"contracts/socks5-auth.md §\"Auth failure response\": an "+
				"empty token generation MUST fail auth with 0x01 0xFF "+
				"(AUTH_REQUIRED — no token was provisioned to compare "+
				"against; the well-formed offer is irrelevant when the "+
				"generation is empty)", reply, want)
		}
		expectEOF(t, conn, "after 01 FF reply (empty-generation AUTH_REQUIRED)")
	})

	// (b) MalformedPasswd_ReplyIsExact_01FF_ThenClose: with one valid
	// token loaded (a populated generation — the realistic case where
	// a malformed offer is rejected against real state, mirroring
	// T027's setup), each malformed PASSWD MUST yield `01 FF` + close.
	// SOCKS5 has no syntactic gate, so malformed candidates funnel
	// through hash+compare-fail (research.md §9). A buggy
	// implementation that special-cases wrong-length or non-hex input
	// with a distinct response (a framing reject, a diagnostic byte)
	// fails here.
	t.Run("MalformedPasswd_ReplyIsExact_01FF_ThenClose", func(t *testing.T) {
		requireAuth(t)
		h := dpharness.Start(t)
		resp := dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, wellFormedPasswd)})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("ReloadTokens(generation=1) status=%v, want "+
				"APPLY_STATUS_OK — precondition for the malformed-"+
				"PASSWD test failed; the DP did not accept the test's "+
				"token generation (without a populated generation the "+
				"malformed cases cannot be asserted against realistic "+
				"state)", resp.GetStatus())
		}

		for _, tc := range malformedPasswdCases {
			t.Run(tc.label, func(t *testing.T) {
				conn := dialProxy(t, h)
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

				doMethodNegotiation(t, conn)
				reply := doSubnegotiation(t, conn, "t028-malformed", tc.passwd)
				if want := []byte{0x01, 0xFF}; !bytes.Equal(reply, want) {
					t.Errorf("malformed-PASSWD (%s) sub-negotiation reply "+
						"= %x, want %x — contracts/socks5-auth.md §\"Auth "+
						"failure response\" + research.md §9: SOCKS5 has "+
						"no syntactic gate on PASSWD; a malformed "+
						"candidate MUST funnel through hash+compare-fail "+
						"to the same 0x01 0xFF as any other failure "+
						"(a distinct response here would be a "+
						"distinguishing substring across AUTH_REQUIRED "+
						"cases)", tc.label, reply, want)
				}
				expectEOF(t, conn, "after 01 FF reply (malformed-PASSWD "+tc.label+")")
			})
		}
	})

	// (c) NoDistinguishingSubstring_acrossAUTH_REQUIRED_Cases: capture
	// the FULL response (2-byte reply + every trailing byte through
	// EOF) for each AUTH_REQUIRED case — the empty-generation case
	// (captured BEFORE the generation is populated) and each malformed-
	// PASSWD variant (captured AFTER the generation is populated).
	// Assert every capture is byte-for-byte identical to the others
	// AND equal to [0x01, 0xFF] exactly.
	//
	// This is the cross-case invariant contracts/socks5-auth.md
	// §"Auth failure response" names ("no distinguishing substring
	// across missing/malformed/empty cases") and that no other test
	// asserts: T025 (a) gates the single-case shape (near-miss
	// password); T028 gates the cross-case identity. A buggy
	// implementation that emits a diagnostic byte on one path (e.g.
	// empty-gen) but not another (e.g. malformed) fails here even if
	// every individual case still leads with `01 FF`.
	t.Run("NoDistinguishingSubstring_acrossAUTH_REQUIRED_Cases", func(t *testing.T) {
		requireAuth(t)
		h := dpharness.Start(t)

		// Empty-generation capture FIRST: before any Reload, the
		// generation is empty and every offer fails. A well-formed
		// offer is the canonical AUTH_REQUIRED shape here.
		emptyCapture := captureAuthFailureReply(t, h, "t028-xcase-empty", wellFormedPasswd)

		// Populate the generation, then capture each malformed case.
		// The generation transitions empty → populated between
		// captures; each capture is an independent connection so the
		// transition is observable only as "the server's state when
		// this connection authed", which is exactly the dimension the
		// cross-case identity invariant forbids the response to leak.
		resp := dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, wellFormedPasswd)})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("ReloadTokens(generation=1) status=%v, want "+
				"APPLY_STATUS_OK — precondition for the cross-case "+
				"identity test failed; the malformed captures need a "+
				"populated generation", resp.GetStatus())
		}
		malformedCaptures := make([][]byte, len(malformedPasswdCases))
		for i, tc := range malformedPasswdCases {
			malformedCaptures[i] = captureAuthFailureReply(t, h, "t028-xcase-"+tc.label, tc.passwd)
		}

		// The contract's fixed point: every AUTH_REQUIRED capture is
		// exactly [0x01, 0xFF] — zero trailing bytes on every path.
		want := []byte{0x01, 0xFF}
		if !bytes.Equal(emptyCapture, want) {
			t.Errorf("empty-generation capture = %x, want exactly %x — "+
				"contracts/socks5-auth.md §\"Auth failure response\": "+
				"the 2-byte reply plus close is the ENTIRE failure "+
				"surface, no further bytes", emptyCapture, want)
		}
		for i, tc := range malformedPasswdCases {
			if !bytes.Equal(malformedCaptures[i], want) {
				t.Errorf("malformed-PASSWD (%s) capture = %x, want "+
					"exactly %x — the 2-byte reply plus close is the "+
					"ENTIRE failure surface, no further bytes",
					tc.label, malformedCaptures[i], want)
			}
		}

		// The cross-case identity invariant: every malformed capture
		// is byte-for-byte identical to the empty-generation capture
		// (and transitively to each other, since each equals `want`).
		// Asserted as an explicit pairwise comparison so a failure
		// names BOTH cases that diverged rather than only "did not
		// equal want". At the byte level this is equivalent to the
		// per-case check above given the fixed `want`, but it is the
		// load-bearing statement of the no-distinguishing-substring
		// property and stays meaningful if a future contract change
		// ever widened `want` (e.g. an allowed trailing close token).
		for i, tc := range malformedPasswdCases {
			if !bytes.Equal(emptyCapture, malformedCaptures[i]) {
				t.Errorf("AUTH_REQUIRED responses differ across cases — "+
					"empty-generation capture %x vs malformed-PASSWD "+
					"(%s) capture %x — contracts/socks5-auth.md "+
					"§\"Auth failure response\": no distinguishing "+
					"substring across missing/malformed/empty cases; "+
					"Principle III / FR-006 / FR-009",
					emptyCapture, tc.label, malformedCaptures[i])
			}
		}
	})
}

// captureAuthFailureReply dials the DP, performs SOCKS5 method
// negotiation, writes the RFC 1929 sub-negotiation with the given
// uname/passwd, reads the 2-byte reply, then drains every trailing
// byte through EOF into a single capture. Returns the full capture
// (reply + trailing) so callers can assert both the exact `0x01 0xFF`
// shape and the cross-case byte-identity invariant. The contract
// requires the capture to be exactly [0x01, 0xFF] — any trailing
// bytes are a breach of "the 2-byte reply plus close is the entire
// failure surface".
//
// The 2 s trailing-drain deadline is the close-check window: the
// contract requires the DP to close immediately after `0x01 0xFF`.
// io.ReadAll returns (trailing, err); a clean EOF yields the trailing
// bytes (expected zero). A timeout (no EOF) is itself a contract
// breach — the DP did not close — and is surfaced as a test failure
// here so sub-test (c) is self-sufficient for the no-close property
// (not reliant on (a)/(b)'s expectEOF defense-in-depth).
func captureAuthFailureReply(t *testing.T, h *dpharness.Harness, uname, passwd string) []byte {
	t.Helper()
	conn := dialProxy(t, h)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	doMethodNegotiation(t, conn)
	reply := doSubnegotiation(t, conn, uname, passwd)

	// Drain trailing bytes through EOF. A short read deadline is the
	// close-check window: the contract requires immediate close after
	// the 2-byte reply. A timeout (no EOF) means the DP held the conn
	// open — a contract breach surfaced here, not swallowed, so the
	// cross-case identity sub-test (c) falsifies the no-close
	// regression on its own.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	trailing, err := io.ReadAll(conn)
	if !errors.Is(err, io.EOF) {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Errorf("AUTH_REQUIRED path: DP did not close within 2 s of "+
				"the 0x01 0xFF reply (contract requires close) "+
				"[uname=%s] — contracts/socks5-auth.md §\"Auth failure "+
				"response\"", uname)
		}
		// Other non-EOF errors (reset, pipe) still imply the conn is
		// gone, which satisfies the "close" half of the contract; the
		// byte-identity checks below are the load-bearing assertions
		// in that case.
	}
	return append(append([]byte{}, reply...), trailing...)
}
