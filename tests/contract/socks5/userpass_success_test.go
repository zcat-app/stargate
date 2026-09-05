// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for RFC 1929 username/password sub-negotiation
// success and verbatim UNAME forwarding to the upstream SOCKS5 —
// specs/001-tor-route/contracts/socks5-auth.md §"Username/password
// sub-negotiation" and FR-007.
//
// Tests-first (Constitution Principle VII) for:
//   - T042 (listener RFC 1929 framing) — reads UNAME/PASSWD off the wire
//   - T044 (auth/token.go HMAC-SHA-256 verification) — validates PASSWD
//   - T047 (forward/tor.go) — passes UNAME verbatim to upstream SOCKS5
//
// The test self-skips until those + T045/T050 land; once present, a
// byte-shape or forwarding regression is FAIL, not SKIP.
package socks5

import (
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
	integration "github.com/zcat-app/stargate/tests/integration"
)

// knownPlaintext is the bearer-token plaintext the test mints into an
// HMAC verifier via dpharness.MintToken and pushes to the DP via
// ReloadTokens. Any 32-char hex string would do; this one is fixed so
// the test's intent is grep-friendly.
const knownPlaintext = "0123456789abcdef0123456789abcdef"

// TestUserpassSubnegotiationSuccess pins the byte-exact contract from
// contracts/socks5-auth.md §"Username/password sub-negotiation" plus
// the FR-007 verbatim-forwarding invariant.
func TestUserpassSubnegotiationSuccess(t *testing.T) {
	// Per-sub-test gates add to the boot-minimum gate inside
	// dpharness.Start. Auth-touching sub-tests require T044
	// (auth/token.go); the forwarding sub-test additionally requires
	// T047 (forward/tor.go) and T045 client.go (WatchEvents consumer —
	// advisory; admission is not CP-gated per T090/data-model.md §2).
	authGate := filepath.Join(dpharness.FindRepoRoot(t), "data-plane", "internal", "auth", "token.go")
	requireAuth := func(t *testing.T) {
		dpharness.RequireFile(t, authGate, "auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	}
	forwardGate := filepath.Join(dpharness.FindRepoRoot(t), "data-plane", "internal", "forward", "tor.go")
	clientGate := filepath.Join(dpharness.FindRepoRoot(t), "data-plane", "internal", "controlclient", "client.go")
	requireForward := func(t *testing.T) {
		dpharness.RequireFile(t, forwardGate, "forward/tor.go not implemented yet (T047); UNAME-forwarding sub-test self-lifts when T047 lands")
		dpharness.RequireFile(t, clientGate, "controlclient/client.go not implemented yet (T045 client side); needed to consume the WatchEvents stream (advisory; admission is not CP-gated per T090)")
	}

	// (a) AuthSuccess_ReplyIsExact_01_00: preload one valid token,
	// open SOCKS5, do method negotiation + RFC 1929 sub-negotiation
	// with the matching plaintext + a known UNAME, assert the reply
	// is byte-exactly 01 00. Then assert the conn is held open (the
	// DP proceeds to wait for the SOCKS5 request phase — no extra
	// bytes, no close).
	t.Run("AuthSuccess_ReplyIsExact_01_00", func(t *testing.T) {
		requireAuth(t)
		h := dpharness.Start(t)
		// Generation 1, one valid token. APPLY_STATUS_OK is the only
		// acceptable response — a stale-generation or invalid-hash
		// response would mean T044 / T046 (snapshot) is broken in a
		// way T020's contract test gates more precisely.
		resp := dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, knownPlaintext)})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("ReloadTokens returned %v, want APPLY_STATUS_OK — "+
				"precondition for the auth-success test failed; the DP "+
				"did not accept the test's token generation", resp.GetStatus())
		}

		conn := dialProxy(t, h)
		defer conn.Close()
		// 30 s covers HMAC auth (sub-ms nominal, more on loaded CI).
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		doMethodNegotiation(t, conn)
		reply := doSubnegotiation(t, conn, "t024-uname", knownPlaintext)
		want := []byte{0x01, 0x00}
		if !bytes.Equal(reply, want) {
			t.Fatalf("sub-negotiation reply = %x, want %x — "+
				"contracts/socks5-auth.md §\"Username/password sub-"+
				"negotiation\": on auth success the DP MUST reply 01 00 "+
				"then proceed to the SOCKS5 request phase", reply, want)
		}
		expectHeldOpen(t, conn, "after 01 00 sub-negotiation success reply")
	})

	// (b) UNAME_LengthBoundaries: same as (a) but UNAME is varied
	// across the RFC 1929 length range (1, 16, 255 bytes). Each MUST
	// yield 01 00 — pins the listener's ULEN parsing. If ULEN were
	// misparsed, PASSWD would land at the wrong offset and auth would
	// fail (01 FF) instead.
	t.Run("UNAME_LengthBoundaries", func(t *testing.T) {
		requireAuth(t)
		h := dpharness.Start(t)
		dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, knownPlaintext)})

		for _, tc := range []struct {
			name  string
			uname string
		}{
			{"OneByte", "a"},
			{"SixteenBytes", "0123456789abcdef"},
			{"Max255Bytes", strings.Repeat("u", 255)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				conn := dialProxy(t, h)
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				doMethodNegotiation(t, conn)
				reply := doSubnegotiation(t, conn, tc.uname, knownPlaintext)
				want := []byte{0x01, 0x00}
				if !bytes.Equal(reply, want) {
					t.Errorf("sub-negotiation reply for UNAME len=%d = %x, want %x — "+
						"ULEN misparsing would shift PASSWD to the wrong offset "+
						"and fail auth; this case pins RFC 1929 framing (len=%d)",
						len(tc.uname), reply, want, len(tc.uname))
				}
			})
		}
	})

	// (c) UNAME_ForwardedVerbatim: with a fake upstream pointed to
	// by STARGATE_TOR_SOCKS_ADDR, a fake control plane (advisory
	// WatchEvents stream; admission is not CP-gated per T090), and a
	// valid token preloaded: open SOCKS5, do method negotiation, send
	// RFC 1929 sub-negotiation with a distinctive UNAME, do SOCKS5
	// CONNECT to a target. Assert (1) sub-negotiation reply is 01 00;
	// (2) the fake upstream observed the EXACT UNAME bytes via its
	// CircuitIDs() snapshot — proving FR-007 verbatim forwarding.
	t.Run("UNAME_ForwardedVerbatim", func(t *testing.T) {
		requireAuth(t)
		requireForward(t)

		// Fake upstream: fake_socks5_tor in AcceptAndRelay mode. It
		// completes the SOCKS5 handshake, replies success, and records
		// observed UNAMEs via CircuitIDs() (T019a R4 — the fake mirrors
		// Tor's IsolateSOCKSAuth surface without validating creds).
		upstream := integration.NewServer(integration.AcceptAndRelay)
		upstreamAddr, err := upstream.Start()
		if err != nil {
			t.Fatalf("starting fake upstream: %v", err)
		}
		t.Cleanup(func() { _ = upstream.Close() })

		// Boot DP with: fake upstream override + the TLS fake CP hosted
		// on control.sock BEFORE the DP boots (so the first WatchEvents
		// dial lands against our programmable stream; the TLS transport
		// is the wire-auth §4 fixture lift, T050).
		h := dpharness.Start(t,
			dpharness.WithUpstream(upstreamAddr),
			dpharness.WithControlPlane(),
		)
		cp := h.CP

		// Push token. A HEALTHY event is pushed for advisory status
		// visibility, but admission is NOT gated on it (data-model.md
		// §2; Principle II; sol-review B3; remediated by T090) — the
		// forward path reaches the upstream regardless. The no-gating
		// regression for the SOCKS5 path is carried by T021's
		// AdmissionNotGatedBySidecarEvents; this test focuses on UNAME
		// verbatim forwarding.
		dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, knownPlaintext)})
		waitForWatchEventsDial(t, cp)
		if err := cp.Send(fakecp.Healthy("tor")); err != nil {
			t.Fatalf("pushing HEALTHY event: %v", err)
		}

		// Distinctive UNAME — long enough to be statistically
		// impossible to confuse with another stream's, short enough
		// to fit comfortably under RFC 1929's 255-byte ULEN.
		const wantUNAME = "t024-uname-marker-abc-def-1234567890"

		conn := dialProxy(t, h)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		doMethodNegotiation(t, conn)
		subReply := doSubnegotiation(t, conn, wantUNAME, knownPlaintext)
		if want := []byte{0x01, 0x00}; !bytes.Equal(subReply, want) {
			t.Fatalf("sub-negotiation reply = %x, want %x — forward-path "+
				"sub-test cannot proceed without auth success", subReply, want)
		}

		// SOCKS5 CONNECT to a target. The target is irrelevant — the
		// fake upstream short-circuits to an in-memory byte pipe; we
		// just need the forward path to dial it WITH the UNAME.
		writeConnectRequest(t, conn, "example.onion", 443)
		// The fake's success reply is 10 bytes (05 00 00 01 00*6) per
		// writeReply in fake_socks5_tor.go. We don't strictly need to
		// read it, but a stuck forward path would hang here; the
		// bounded read surfaces that as a test failure rather than a
		// timeout pile-up.
		rep := readN(t, conn, 10)
		if rep[0] != 0x05 || rep[1] != 0x00 {
			t.Fatalf("SOCKS5 CONNECT reply = %x, want 05 00... (success) — "+
				"the forward path did not reach the upstream successfully "+
				"(contracts/socks5-auth.md §\"SOCKS5 request-phase "+
				"failures\"; rep[1] mapping per data-model.md §2)", rep)
		}

		// The load-bearing assertion: the fake upstream observed the
		// exact UNAME the test sent into the inbound SOCKS5 path —
		// proving FR-007 verbatim forwarding end-to-end. A mutated,
		// truncated, or dropped UNAME would fail here.
		observed := upstream.CircuitIDs()
		if !containsExactly(observed, wantUNAME) {
			t.Errorf("UNAME not forwarded verbatim — upstream observed %v, "+
				"want [%q] exactly; FR-007 violation (contracts/socks5-"+
				"auth.md §\"Username/password sub-negotiation\" + spec.md "+
				"FR-007: UNAME is opaque to the auth layer and is passed "+
				"through verbatim to the upstream SOCKS5 connection)",
				observed, wantUNAME)
		}
	})
}

// doMethodNegotiation writes the SOCKS5 method greeting (single
// method: USERNAME/PASSWORD) and reads the method-selection reply.
// Fatal on any byte-shape mismatch — the contract for this layer is
// gated by T023, not this test.
func doMethodNegotiation(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	got := readN(t, conn, 2)
	want := []byte{0x05, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("method selection = %x, want %x — "+
			"T023 gates this layer; a failure here means the listener "+
			"regressed between T023 and T024", got, want)
	}
}

// doSubnegotiation writes the RFC 1929 username/password sub-
// negotiation message (VER ULEN UNAME PLEN PASSWD) and reads the
// 2-byte reply. Returns the reply bytes; the caller asserts the
// status byte (0x00 success / 0xFF failure) per their contract.
func doSubnegotiation(t *testing.T, conn net.Conn, uname, passwd string) []byte {
	t.Helper()
	user := []byte(uname)
	pass := []byte(passwd)
	if len(user) < 1 || len(user) > 255 {
		t.Fatalf("UNAME length %d out of RFC 1929 range [1,255]", len(user))
	}
	if len(pass) < 1 || len(pass) > 255 {
		t.Fatalf("PASSWD length %d out of RFC 1929 range [1,255]", len(pass))
	}
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write RFC 1929 sub-negotiation: %v", err)
	}
	return readN(t, conn, 2)
}

// writeConnectRequest sends a SOCKS5 CONNECT (RFC 1928 §4) to a
// hostname-mode target (ATYP=0x03, SOCKS5h — the data plane MUST NOT
// resolve the hostname locally per FR-007 / Principle III).
func writeConnectRequest(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	if len(host) > 255 {
		t.Fatalf("CONNECT target hostname %q exceeds RFC 1929 length", host)
	}
	req := []byte{
		0x05,            // VER
		0x01,            // CMD = CONNECT
		0x00,            // RSV
		0x03,            // ATYP = DOMAIN (SOCKS5h)
		byte(len(host)), // domain length
	}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 CONNECT request: %v", err)
	}
}

// waitForWatchEventsDial polls the fake CP's DialCount until the DP
// has dialled WatchEvents at least once. Without this wait, Send
// would race the dial and silently no-op (LatestStream returns nil).
// Bounded at 20 s to mirror dpharness.WaitFor's other boot polls.
func waitForWatchEventsDial(t *testing.T, cp *fakecp.Server) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cp.DialCount() > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("DP never dialled WatchEvents on control.sock within 20s — " +
		"T045 client.go is wired incorrectly or the DP failed to boot the " +
		"control-plane client")
}

// containsExactly reports whether want is the sole element of got.
// The fake upstream's CircuitIDs() returns the SET of observed UNAMEs
// (no duplicates even across re-uses of the same UNAME), so this is
// the right shape — a single-element set matching want exactly.
func containsExactly(got []string, want string) bool {
	if len(got) != 1 {
		return false
	}
	return got[0] == want
}

// The shared SOCKS5 client helpers (dialProxy, readN, expectHeldOpen,
// expectEOF, expectSilentClose) are authored in demux_test.go (T023)
// and reused here — both test files share package socks5.
